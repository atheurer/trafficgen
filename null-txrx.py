from __future__ import print_function

import sys, getopt
import argparse
import subprocess
import re
import time
import json
import string
import select
import signal
import copy
import random

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

def dump_json_readable(obj):
     return json.dumps(obj, indent = 4, separators=(',', ': '), sort_keys = True)

def dump_json_parsable(obj):
     return json.dumps(obj, separators=(',', ':'))

def process_options ():
    parser = argparse.ArgumentParser(usage=""" 
    A null traffic generator for testing a binary search
    """);

    parser.add_argument('--mirrored-log',
                        dest='mirrored_log',
                        help='Should the logging sent to STDOUT be mirrored on STDERR',
                        action = 'store_true',
                        )
    parser.add_argument('--rate',
                        dest='rate',
                        help='Rate to test (in %%)',
                        default = 100.0,
                        type = float
                        )
    parser.add_argument('--random-seed',
                        dest='random_seed',
                        help='Specify a fixed random seed for repeatable results (defaults to not repeatable)',
                        default = None,
                        type = float
                        )
    t_global.args = parser.parse_args();
    myprint(t_global.args)

def define_rate_failure_obj(min_rate, max_rate, failure_odds):
    obj = dict()
    obj['min_rate'] = min_rate
    obj['max_rate'] = max_rate
    obj['failure_odds'] = failure_odds / 100.0
    return obj

def main():
    process_options()

    random.seed(t_global.args.random_seed)

    rate_failure_odds = []
    rate_failure_odds.append(define_rate_failure_obj(90, 100, 98))
    rate_failure_odds.append(define_rate_failure_obj(80,  90, 95))
    rate_failure_odds.append(define_rate_failure_obj(70,  80, 92))
    rate_failure_odds.append(define_rate_failure_obj(60,  70, 90))
    rate_failure_odds.append(define_rate_failure_obj(50,  60, 88))
    rate_failure_odds.append(define_rate_failure_obj(40,  50, 60))
    rate_failure_odds.append(define_rate_failure_obj(30,  40, 50))
    rate_failure_odds.append(define_rate_failure_obj(20,  30, 40))
    rate_failure_odds.append(define_rate_failure_obj(10,  20, 20))
    rate_failure_odds.append(define_rate_failure_obj( 5,  10, 10))
    rate_failure_odds.append(define_rate_failure_obj( 1,   5,  5))
    rate_failure_odds.append(define_rate_failure_obj( 0,   1,  0))

    result = 'fail'

    for failure_odds_index, failure_odds_obj in enumerate(rate_failure_odds):
        if t_global.args.rate > failure_odds_obj['min_rate'] and t_global.args.rate <= failure_odds_obj['max_rate']:
            value = random.random()
            myprint("value=%f" % value, stderr_only = True)
            myprint(dump_json_readable(failure_odds_obj), stderr_only = True)
            if value > failure_odds_obj['failure_odds']:
                result = 'pass'
            break

    myprint("result=%s" % (result))
    myprint("exiting")

    return 0

if __name__ == "__main__":
    exit(main())
