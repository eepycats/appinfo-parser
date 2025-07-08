from appinfo import parse_appinfo
parsed = parse_appinfo(open("appinfo.2010-06-05.vdf", "rb")) # from ymgve
import pprint
pprint.pprint(parsed)