from __future__ import print_function

import sys, getopt
sys.path.append('/opt/trex/current/automation/trex_control_plane/interactive')
import argparse
import json
import string
import datetime
import math
from decimal import *
from trex.stl.api import *
from trex_tg_lib import *

class t_global(object):
     args=None;

def myprint(*args, **kwargs):
     stderr_only = False
     if 'stderr_only' in kwargs:
          stderr_only = kwargs['stderr_only']
          del kwargs['stderr_only']
     if not stderr_only:
          print(*args, **kwargs)
     if stderr_only or t_global.args.mirrored_log:
          print(*args, file = sys.stderr, **kwargs)
     return

def process_options ():
    parser = argparse.ArgumentParser(usage=""" 
    query TRex for information about it's ports
    """);

    parser.add_argument('--trex-host',
                        dest='trex_host',
                        help='Hostname/IP address of the server where TRex is running',
                        default='localhost',
                        type = str
                        )
    parser.add_argument('--mirrored-log',
                        dest='mirrored_log',
                        help='Should the logging sent to STDOUT be mirrored on STDERR',
                        action = 'store_true',
                        )
    parser.add_argument('--device',
                        dest='device',
                        help='A device number/id to query.  Can be used multiple times.',
                        default = [],
                        action = 'append',
                        type = int
                        )
    t_global.args = parser.parse_args();
    myprint(t_global.args)

def main():
    process_options()

    try:
         if len(t_global.args.device) == 0:
              raise ValueError("You must provide at least one device to query")
    except ValueError as e:
         myprint(error("%s" % (e)))
         quit(1)

    c = STLClient(server = t_global.args.trex_host)
    passed = True

    stats = 0
    return_value = 1

    try:
        # turn this on for some information
        #c.set_verbose("debug")

        # connect to server
        myprint("Establishing connection to TRex server...")
        c.connect()
        myprint("Connection established")

        # prepare our ports
        c.acquire(ports = t_global.args.device, force=True)
        c.reset(ports = t_global.args.device)

        port_info = c.get_port_info(ports = t_global.args.device)
        myprint("READABLE PORT INFO:", stderr_only = True)
        myprint(dump_json_readable(port_info), stderr_only = True)
        myprint("PARSABLE PORT INFO: %s" % dump_json_parsable(port_info), stderr_only = True)

        return_value = 0

    except TRexError as e:
        myprint(e)

    finally:
        myprint("Disconnecting from TRex server...")
        c.disconnect()
        myprint("Connection severed")
        return return_value

if __name__ == "__main__":
    exit(main())
