#!/bin/python -u
from __future__ import print_function

import argparse
import sys
import time
from xenalib.XenaSocket import XenaSocket
from xenalib.XenaManager import XenaManager
# TODO: imports

# overview: xena-txrx is currently in development
# script interfaces between binary-search.py and XenaPythonLib

# argument parser
class t_global(object):
    args=None

def process_options():
    parser = argparse.ArgumentParser(usage=""" 
    generate network traffic and report packet loss
    """)

    parser.add_argument('--active-device-pairs',
                        dest='active_device_pairs',
                        help='List of active device pairs in the form A:B[,C:D][,E:F][,...]',
                        default='--',
                        )
    parser.add_argument('--device-pairs',
                        dest='device_pairs',
                        help='List of device pairs in the form A:B[,C:D][,E:F][,...]',
                        default="0:1",
                        )
    parser.add_argument('--rate', 
                        dest='rate',
                        help='rate per device',
                        default = 0.0,
                        type = float
                        )
    parser.add_argument('--runtime', 
                        dest='runtime',
                        help='trial period in seconds',
                        default=30,
                        type = int,
                        )
    parser.add_argument("--xena_chassis",
                        dest='xena_chassis',
                        help='Argument for use with Xena; specifies the IP address of the Xena chassis to connect to',
                        type=str
                        )
    parser.add_argument("--xena_pwd",
                        dest='xena_pwd',
                        help='Optional argument for Xena session; defaults to "xena"',
                        default='xena',
                        type=str
                        )
    parser.add_argument("--xena_user",
                        dest='xena_user',
                        help='The user for a Xena chassis session. String is limited to 8 characters',
                        type=str
                        )

    t_global.args = parser.parse_args()
    args_print(t_global.args)

def args_print(*args, **kwargs):
     stderr_only = False
     if 'stderr_only' in kwargs:
          stderr_only = kwargs['stderr_only']
          del kwargs['stderr_only']
     if not stderr_only:
          print(*args, **kwargs)
     if stderr_only:
          print(*args, file = sys.stderr, **kwargs)
     return

# TODO: expand XenaPythonLib functionality

def main():
    process_options()

    xenaUsr = t_global.args.xena_user
    xenaPwd = t_global.args.xena_pwd
    xenaChassis = t_global.args.xena_chassis
    # possible TODO: verify chassis ip input format?

    # create the communication socket
    xsocket = XenaSocket(xenaChassis)

    # connect to Xena chassis
    try:
        xsocket.connect()
        print('Xena chassis connection successful')
        
    except TypeError:
        # failure to connect returns object 'timeout', throws TypeError
        print('Error: connection to Xena chassis failed')

    else:
        time.sleep(5) # gives enough time to show up in ValkyrieManager
        print('Disconnecting from Xena chassis...')
        del xsocket
    
    sys.exit()

if __name__ == '__main__':
    main()

