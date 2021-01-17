import sys
import json
import datetime


def format_timestamp(ts):
    return (format_datetime(datetime.datetime.fromtimestamp(ts)))


def format_datetime(dt):
    return (dt.strftime("%Y-%m-%d %H:%M:%S.%f"))


def error (string):
    return("ERROR: %s" % (string))


def not_json_serializable(obj):
    try:
        return(obj.to_dictionary())
    except AttributeError:
        try:
            return("scapy:%s" % (obj.command()))
        except AttributeError:
            return(repr(obj))


def dump_json_readable(obj):
     return json.dumps(obj, indent = 4, separators=(',', ': '), sort_keys = False, default = not_json_serializable)


def dump_json_parsable(obj):
     return json.dumps(obj, separators=(',', ':'), default = not_json_serializable)


def commify(string):
     return str.format("{:,}", string)


def sec_to_usec(seconds):
    useconds = seconds * 1e6
    return(useconds)


def ip_to_int (ip):
    ip_fields = ip.split(".")
    if len(ip_fields) != 4:
         raise ValueError("IP addresses should be in the form of W.X.Y.Z")
    ip_int = 256**3 * int(ip_fields[0]) + 256**2 * int(ip_fields[1]) + 256**1 * int(ip_fields[2]) + int(ip_fields[3])
    return ip_int


def int_to_ip (_int):
    octet = int(_int / (256**3))
    _int = _int - (octet * 256**3)
    ip = str(octet)

    octet = int(_int / (256**2))
    _int = _int - (octet * 256**2)
    ip = ip + "." + str(octet)

    octet = int(_int / (256**1))
    _int = _int - (octet * 256**1)
    ip = ip + "." + str(octet)

    _int = _int - (octet * 256**1)
    ip = ip + "." + str(octet)
    return ip


def calculate_latency_pps (dividend, divisor, total_rate, protocols):
     return int((float(dividend) / float(divisor) * total_rate / protocols))


