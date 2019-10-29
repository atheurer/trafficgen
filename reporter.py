#!/bin/python

from __future__ import print_function

import json
import argparse
import datetime
import re
from tg_lib import *


class t_global(object):
     args = None


def process_options():
    parser = argparse.ArgumentParser(description = 'Load a binary-search.py JSON output file and provide reports from it')

    parser.add_argument('--input',
                        dest = 'input',
                        help = 'JSON file to use as input',
                        default = ""
                        )

    parser.add_argument('--type',
                        dest = 'report_type',
                        help = 'Type of report to generate',
                        default = "log",
                        choices = [ "log", "trial-list", "dump-trial", "search-summary", "result" ]
                        )

    parser.add_argument('--trial',
                        dest = 'trial',
                        help = 'Trial to operate on',
                        default = 0,
                        type = int
                        )

    t_global.args = parser.parse_args();

    return()


def generate_report(input_json):
    if t_global.args.report_type == 'log':
        for entry in input_json['log']:
            prefix = ""
            if 'bso' in entry and entry['bso']:
                 prefix = "[BSO]"
            if 'prefix' in entry and len(entry['prefix']):
                 prefix = "[%s]" % (entry['prefix'])
            for line in entry['message'].split('\n'):
                print("[%s]%s %s" % (format_timestamp(entry['timestamp']/1000), prefix, line))
    elif t_global.args.report_type == "trial-list":
        print("Available Trials:")
        for trial in input_json['trials']:
            print("%d" % (trial['trial']))
    elif t_global.args.report_type == "search-summary":
        print("%3s | %26s   %26s | %15s | %11s | %10s | %s" % ("#",
                                                               "Start Time",
                                                               "Stop Time",
                                                               "Duration",
                                                               "Rate",
                                                               "Type",
                                                               "Result"))
        for trial in input_json['trials']:
            start_time = datetime.datetime.fromtimestamp(trial['stats']['trial_start']/1000)
            stop_time = datetime.datetime.fromtimestamp(trial['stats']['trial_stop']/1000)
            run_time = stop_time - start_time
            print("%3d | %26s - %26s | %7.2f seconds | %10.6f%s | %10s | %s" % (trial['trial'],
                                                                            format_datetime(start_time),
                                                                            format_datetime(stop_time),
                                                                            run_time.total_seconds(),
                                                                            trial['rate'],
                                                                            trial['rate_unit'],
                                                                            trial['trial_params']['trial_mode'],
                                                                            trial['result']) )
    elif t_global.args.report_type == "dump-trial":
        for trial in input_json['trials']:
            if trial['trial'] == t_global.args.trial:
                print(dump_json_readable(trial))
                return(0)
        print(error("Invalid trial requested"))
        return(1)
    elif t_global.args.report_type == "result":
        for trial in reversed(input_json['trials']):
            if trial['trial_params']['trial_mode'] == "validation" and trial['result'] == "pass":
                print("Found result in trial %d:" % (trial['trial']))
                result = []
                # filter for only device stats
                for entry in trial['stats']:
                     m = re.search(r"^[0-9]+$", entry)
                     if m:
                         result.append(trial['stats'][entry])
                print(dump_json_readable(result))
                return(0)
        print(error("Could not find a final validation that passed"))
        return(1)

    return(0)


def main():
    process_options()

    try:
        input_fp = open(t_global.args.input, 'r')
        input_json = json.load(input_fp)
        input_fp.close()

    except:
        print(error("Couldn't load input file %s" % (t_global.args.input)))
        return(1)

    generate_report(input_json)

    return(0)


if __name__ == "__main__":
    exit(main())
