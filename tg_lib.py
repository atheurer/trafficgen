from __future__ import print_function

import sys
import json
import datetime

def format_timestamp(ts):
    return (datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S.%f"))


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
     return json.dumps(obj, indent = 4, separators=(',', ': '), sort_keys = True, default = not_json_serializable)


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


def calculate_latency_pps (dividend, divisor, total_rate, protocols):
     return int((float(dividend) / float(divisor) * total_rate / protocols))


