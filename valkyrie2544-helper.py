# Copyright 2016-2017 Red Hat Inc & Xena Networks.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import json
import locale
import logging
import os
import subprocess
import sys
from time import sleep
import xml.etree.ElementTree as ET
import base64

import pprint

pp = pprint.PrettyPrinter(indent=4)

_LOGGER = logging.getLogger(__name__)
_DEBUG = False

def main(args):
    cmd = 'python -u XenaVerify.py'
    cmd = cmd + ' --config_file ' + args.traffic_profile # --config_file
    if _DEBUG: # --debug
        cmd = cmd + ' --debug'
    if args.xena_module:
        cmd = cmd + ' --module ' + str(args.xena_module)
    if args.valkyrie2544_windows_mode: # --windows_mode
        cmd = cmd + ' --windows_mode'
    if args.validation_runtime: # --verify_duration
        cmd = cmd + ' --verify_duration ' + str(args.validation_runtime)
    if args.max_retries: # --retry_attempts
        cmd = cmd + ' --retry_attempts ' + str(int(args.max_retries))
    if args.smart_search: # --smart_search
        cmd = cmd + ' --smart_search'
    if args.pdf: # --pdf_output
        cmd = cmd + ' --pdf_output'
    if args.search_runtime: # --search_trial_duration
        cmd = cmd + ' --search_trial_duration ' + str(args.search_runtime) 
    if args.measure_latency == 0: # --collect_latency
        cmd = cmd + ' --collect_latency'
    if args.valkyrie2544_packet_sizes: # --packet_sizes
        cmd = cmd + ' --packet_sizes ' + str(args.valkyrie2544_packet_sizes)
    if args.max_loss_pct: # --acceptable_loss
        cmd = cmd + ' --acceptable_loss ' + str(args.max_loss_pct)
    if args.valkyrie2544_save_file_name: # --save_file_name
        cmd = cmd + ' --save_file_name ' + args.valkyrie2544_save_file_name
    if args.valkyrie2544_initial_tput: # --initial_tput
        cmd = cmd + ' --initial_tput ' + str(args.valkyrie2544_initial_tput)
    if args.rate: # --max_tput
        cmd = cmd + ' --max_tput ' + str(args.rate)
    if args.min_rate: # --min_tput
        cmd = cmd + ' --min_tput ' + str(args.min_rate)
    if args.dst_macs and args.src_macs: # --mac_address
        cmd = cmd + ' --mac_address ' + str(args.dst_macs) + ' ' + str(args.src_macs)
    if args.src_ips and args.dst_ips: # --connection_ips
        cmd = cmd + ' ' + str(args.src_ips) + ' ' + str(args.dst_ips)
    if args.valkyrie2544_resolution_tput: # --resolution_tput
        cmd = cmd + ' --resolution_tput ' + str(args.valkyrie2544_resolution_tput)
    if args.num_flows: # --flow_count
        # round num_flows to nearest compatible option
        # binary-search checks that flows are within range 1-1M
        if round(args.num_flows, -6): # checks if rounds to 1,000,000
            flow_count = '1M'
        elif round(args.num_flows, -5): # catches values rounding to 100,000
            flow_count = '100k'
        elif round(args.num_flows, -4): # catches values rounding to 10,000
            flow_count = '10k'
        elif round(args.num_flows, -3): # catches values rounding to 1,000
            flow_count = '1k'
        else: # anything else is rounded down to 1
            flow_count = '1'
        cmd = cmd + ' --flow_count ' + flow_count

    if args.use_src_ip_flows or args.use_dst_ip_flows: # use ip flows, test addition
        ip_flows = True
        
    if (args.use_src_mac_flows != 1) or (args.use_dst_mac_flows != 1): # --use_mac_flows
        cmd = cmd + ' --use_mac_flows'
        mac_flows = True
    else:
        mac_flows = False

    if ip_flows and mac_flows: # --use_both_flows
        cmd = cmd + ' --use_both_flows'
    
    XenaVerify_pipe = subprocess.Popen(cmd, shell=True, stdout=sys.stdout)
    print('VALKYRIE2544HELPER cmd: ', cmd)
    
    data = ''
    
    while True:
        try:
            XenaVerify_pipe.wait(60)
            # log_handle.close()
            break
        except subprocess.TimeoutExpired:
            # check the log to see if Valkrie2544 has completed and mono is
            # deadlocked.
            # data += log_handle.read()
            if 'TestCompletedSuccessfully' in data:
                # log_handle.close()
                XenaVerify_pipe.terminate()
                break

    return

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--traffic-profile',
                        dest='traffic_profile',
                        help='Xena/Valkyrie 2544 json config file name',
                        default = '',
                        type = str
                        )
    parser.add_argument('--valkyrie2544-windows_mode', required=False,
                        action='store_true', help='Use windows mode, no mono')
    parser.add_argument('--validation-runtime', 
                        dest='validation_runtime',
                        help='trial period in seconds during final validation',
                        default=30,
                        type = int,
                        )
    parser.add_argument('-l', '--verify_duration', required=False,
                        type=int, default=7200,
                        help='Verification duration in seconds')
    parser.add_argument('--max-retries',
                        dest='max_retries',
                        help='Maximum number of trial retries before aborting',
                        default = 1,
                        type = int
                        )
    parser.add_argument('--valkyrie2544-smart_search', action='store_true',
                        required=False, help='Enable smart search',
                        dest='smart_search', default=False)
    parser.add_argument('--valkyrie2544-pdf_output', action='store_true',
                        dest='pdf', required=False,
                        help='Generate PDF report, do not use on Linux!',
                        default=False)
    parser.add_argument('--search-runtime', 
                        dest='search_runtime',
                        help='trial period in seconds during binary search',
                        default=30,
                        type = int,
                        )
    parser.add_argument('--measure-latency',
                        dest='measure_latency',
                        help='Collect latency statistics or not',
                        default = 1,
                        type = int
                        )
    parser.add_argument('--valkyrie2544-packet_sizes', required=False, nargs='+',
                        type=int, default=False,
                        help='Specify custom packet sizes for test')
    parser.add_argument('--max-loss-pct', 
                        dest='max_loss_pct',
                        help='maximum percentage of packet loss',
                        type = float
                        )
    parser.add_argument('--valkyrie2544-save_file_name', required=False, type=str,
                        default='./2bUsed.x2544', 
                        help='File name to save new config file as')
    parser.add_argument('--valkyrie2544-initial_tput', required=False, type=float,
                        help='Specify initial throughput for test')
    parser.add_argument('--rate', required=False, type=float, dest='rate',
                        help='Specify maximum throughput for test')
    parser.add_argument('--min-rate',
                        dest='min_rate',
                        help='minimum rate per device',
                        type = float
                        )
    parser.add_argument('--src-macs', 
                        dest='src_macs',
                        help='comma separated list of src MACs, 1 per device',
                        default=""
                        )
    parser.add_argument('--dst-macs', 
                        dest='dst_macs',
                        help='comma separated list of destination MACs, 1 per device',
                        default=""
                        )
    parser.add_argument('--src-ips', 
                        dest='src_ips',
                        help='comma separated list of src IPs, 1 per device',
                        default=""
                        )
    parser.add_argument('--dst-ips', 
                        dest='dst_ips',
                        help='comma separated list of destination IPs 1 per device',
                        default=""
                        )
    parser.add_argument('--valkyrie2544-resolution_tput', required=False, type=float,
                        help='Specify resolution rate for throughput test')
    parser.add_argument('--num-flows', 
                        dest='num_flows',
                        help='Choose number of flows to run',
                        default=1024,
                        type = int,
                        )
    parser.add_argument('--use-src-ip-flows', 
                        dest='use_src_ip_flows',
                        help='implement flows by source IP',
                        default=1,
                        type = int,
                        )
    parser.add_argument('--use-dst-ip-flows', 
                        dest='use_dst_ip_flows',
                        help='implement flows by destination IP',
                        default=1,
                        type = int,
                        )
    parser.add_argument('--use-src-mac-flows', 
                        dest='use_src_mac_flows',
                        help='implement flows by source MAC',
                        default=1,
                        type = int,
                        )
    parser.add_argument('--use-dst-mac-flows', 
                        dest='use_dst_mac_flows',
                        help='implement flows by destination MAC',
                        default=1,
                        type = int,
                        )
    parser.add_argument('--xena_module',
                        dest='xena_module',
                        help='Argument for use with Xena; specify module number of a Xena chassis'
                        )

    args = parser.parse_args()
    if args.debug:
        print("HELPER DEBUG ENABLED!!!")
    main(args)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
