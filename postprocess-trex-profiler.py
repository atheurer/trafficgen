#!/bin/python

from __future__ import print_function

import argparse
import os
import os.path
from trex_tg_lib import *

class t_global(object):
    args = None

def process_options ():
    parser = argparse.ArgumentParser(usage="postprocess a TRex profile")

    parser.add_argument('--input',
                        dest = 'input_file',
                        help = 'Data file to process',
                        default = '',
                        type = str
                    )

    t_global.args = parser.parse_args()

    if len(t_global.args.input_file) == 0:
        print(error("You must specify an input file"))
        return(1)
    elif not os.path.isfile(t_global.args.input_file):
        print(error("You must specify a valid input file (not %s)" % (t_global.args.input_file)))
        return(1)
    elif not os.access(t_global.args.input_file, os.R_OK):
        print(error("You must specify an input file that I have read access to"))
        return(1)

    return(0)

def main ():
    ret_val = process_options()
    if ret_val:
        return(ret_val)

    ret_val = trex_profiler_postprocess_file(t_global.args.input_file)
    if ret_val:
        print(dump_json_readable(ret_val))
    else:
        return(1)

    return(0)

if __name__ == "__main__":
    exit(main())
