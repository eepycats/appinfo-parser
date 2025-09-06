# special thanks to ymgve and ben
from enum import IntEnum
from dataclasses import dataclass
from typing import Optional
import struct
import hashlib
import io

parsers = {}

def read_string(bs) -> bytes:
    res = b""
    while True:
        c = bs.read(1)
        if c == b"\x00":
            break
            
        res += c
        
    return res

def try_decode(data: bytes) -> str:
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        try:
            return data.decode('windows-1252', 'replace')
        except UnicodeDecodeError as e:
            print(f"failed to decode {e} {data}")

def read_key(bs, stringtable = None):
    if stringtable:
        idx, = struct.unpack("<I", bs.read(4))
        return try_decode(stringtable[idx])
    return try_decode(read_string(bs))

def parse_vdf(bs, stringtable = None) -> dict:
    res = {}
    while True:
        c = bs.read(1)
        if c == b"\x08":
            break
        k = read_key(bs, stringtable)
        if c == b"\x00":
            v = parse_vdf(bs, stringtable)
            res[k] = v
        elif c == b"\x01":
            v = try_decode(read_string(bs))
            res[k] = v
        elif c == b"\x02":
            v = int(struct.unpack("<I", bs.read(4))[0])
            res[k] = v
        elif c == b"\x03":
            v = float(struct.unpack("<f", bs.read(4))[0])
            res[k] = v
        elif c == b"\x07":
            v = int(struct.unpack("<Q", bs.read(8))[0])
            res[k] = v
        else:
            raise Exception("bad type", c, bs.tell(),bs.read(10), res)
        
    return res


def appinfo_parser(version):
    def decorator(func):
        parsers[version] = func
        return func
    return decorator

def stream_unpack(s, fmt) -> tuple:
    return struct.unpack(fmt, s.read(struct.calcsize(fmt)))

class AppInfoVersion(IntEnum):
    VDF2 = int.from_bytes(b"VDF\x02", 'big') # circa 2010, VDF header
    Version24 = 0x24445606 # circa 2011 - feb 2012?
    Version25 = 0x25445607 # circa feb 2012 - very late 2012 or very early 2013, same as 24?
    Version26 = 0x26445607 # circa jan 2013 or very late 2013, first known jan 2013 - ????, same as 27 w 0'd out sha and picstoken, but with section split appinfo instead? (since 2014 hash and picstoken are actually populated)
    Version27 = 0x27445607 # circa ???? (at least 2017) - 2020, same as above but not split?
    Version28 = 0x28445607 # december 2022 - june 2024, added binary vdf sha
    Version29 = 0x29445607
class AppInfoSection(IntEnum):
    Unknown = 0
    All = 1
    First = 2
    Common = 2
    Extended = 3
    Config = 4
    Stats = 5
    Install = 6
    Depots = 7
    UFS = 10
    OGG = 11
    Policies = 13
    SysReqs = 14
    Community = 15
    Store = 16
    Localization = 17
    Broadcastgamedata = 18
    Computed = 19
    Albummetadata = 20

@dataclass
class AppInfoMetadata:
    size: Optional[int]
    state: int
    timestamp: int
    token: Optional[int]
    sha: Optional[bytes]
    changeid: int
    
@appinfo_parser(AppInfoVersion.Version24)
@appinfo_parser(AppInfoVersion.Version25)
def parse_24(f) -> dict[tuple]:
    parsed_infos = {}
    # appid, size(?), state, timestamp, changeid (?),
    # 4+4+4+4+4
    universe, = stream_unpack(f, "<I")
    while buffer := f.read(20):
        if len(buffer) == 4 and buffer == b"\x00\x00\x00\x00":
            break
        appid,size,state,timestamp,changeid = struct.unpack("<IIIII", buffer)
        sections = {}
        section, = stream_unpack(f, "B")
        while section != 0:
            section = AppInfoSection(section)
            sections[section] = parse_vdf(f)
            section, = stream_unpack(f, "B")
        parsed_infos[appid] = (AppInfoMetadata(size,state,timestamp,None,None,changeid), sections)
    return parsed_infos

@appinfo_parser(AppInfoVersion.Version26)
def parse_26(f) -> dict[tuple]:
    parsed_infos = {}
    #magic, = stream_unpack(f, ">I")
    universe, = stream_unpack(f, "<I")
    while buffer := f.read(20+20+8  ):
        if len(buffer) == 4 and buffer == b"\x00\x00\x00\x00":
            break
        appid,size,state,timestamp,token_probably,sha,changeid = struct.unpack("<IIIIQ20sI", buffer)
        sections = {}
        section, = stream_unpack(f, "B")
        while section != 0:
            section = AppInfoSection(section)
            sections[section] = parse_vdf(f)
            section, = stream_unpack(f, "B")
        parsed_infos[appid] = (AppInfoMetadata(size,state,timestamp,token_probably,sha,changeid), sections)
    return parsed_infos

@appinfo_parser(AppInfoVersion.Version27)
def parse_27(f) -> dict[tuple]:
    parsed_infos = {}
    universe, = stream_unpack(f, "<I")
    #if not magic == AppInfoVersion.TYPE_STEAM3_27:
    #    raise Exception("bad magic")
    while buffer := f.read(20+20+8  ):
        if len(buffer) == 4 and buffer == b"\x00\x00\x00\x00":
            break
        appid,size,state,timestamp,token_probably,sha,changeid = struct.unpack("<IIIIQ20sI", (buffer))
        parsed_infos[appid] = (AppInfoMetadata(size,state,timestamp,token_probably,sha,changeid), parse_vdf(f))
    return parsed_infos

@appinfo_parser(AppInfoVersion.VDF2)
def parse_vdf2(f) -> dict[tuple]:
    parsed_infos = {}
    universe, = stream_unpack(f, "<I")
    #4+4+4+4 ?
    while buffer := f.read(16):
        if len(buffer) == 4 and buffer == b"\x00\x00\x00\x00":
            break
        appid,state,timestamp,changeid = struct.unpack("<IIII", buffer)
        sections = {}
        section, = stream_unpack(f, "B")
        while section != 0:
            section = AppInfoSection(section)
            sections[section] = parse_vdf(f)
            section, = stream_unpack(f, "B")
        parsed_infos[appid] = (AppInfoMetadata(None,state,timestamp,None,None,changeid), sections)
    return parsed_infos


def parse_appinfo(f):
    magic, = stream_unpack(f, ">I")
    if not magic in parsers:
        raise Exception("unsupported magic")
    return parsers[magic](f)

@appinfo_parser(AppInfoVersion.Version28)
def parse_28(f) -> dict[tuple]:
    parsed_infos = {}
    #magic, = stream_unpack(f, ">I")
    universe, = stream_unpack(f, "<I")
    #if not magic == AppInfoVersion.TYPE_STEAM3_27:
    #    raise Exception("bad magic")
    while buffer := f.read(20+20+8+20):
        if len(buffer) == 4 and buffer == b"\x00\x00\x00\x00":
            break
        appid,size,state,timestamp,token_probably,sha,changeid, shahash = struct.unpack("<IIIIQ20sI20s", (buffer))

        data = f.read(size-60)
        if hashlib.sha1(data).digest() != shahash:
            raise Exception("bad appinfo section hash")
        fvdf = io.BytesIO(data)
        parsed_infos[appid] = (AppInfoMetadata(size,state,timestamp,token_probably,sha,changeid), parse_vdf(fvdf))
    return parsed_infos

@appinfo_parser(AppInfoVersion.Version29)
def parse_29(f) -> dict[tuple]:
    parsed_infos = {}
    #magic, = stream_unpack(f, ">I")
    universe, stringtable = stream_unpack(f, "<IQ")
    ctell = f.tell()
    f.seek(stringtable)
    _strings = {}
    strc, = stream_unpack(f, "<I")
    for i in range(strc):
        s = read_string(f)
        _strings[i] = s
    f.seek(ctell)
    #if not magic == AppInfoVersion.TYPE_STEAM3_27:
    #    raise Exception("bad magic")
    while buffer := f.read(20+20+8+20):
        if buffer[:4] == b"\x00\x00\x00\x00":
            break
        appid,size,state,timestamp,token_probably,sha,changeid, shahash = struct.unpack("<IIIIQ20sI20s", buffer)
        data = f.read(size-60)
        if hashlib.sha1(data).digest() != shahash:
            raise Exception("bad appinfo section hash")
        fvdf = io.BytesIO(data)
        parsed_infos[appid] = (AppInfoMetadata(size,state,timestamp,token_probably,sha,changeid), parse_vdf(fvdf, _strings))
    return parsed_infos
