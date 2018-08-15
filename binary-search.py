#!/bin/python -u

from __future__ import print_function

from trex_tg_lib import *
import sys, getopt
import argparse
import subprocess
import re
# import stl_path
import time
import json
import string
import threading
import thread
import select
import signal
import copy
import random
import os
import os.path
# from decimal import *
# from trex_stl_lib.api import *

class t_global(object):
     args=None;

def sigint_handler(signal, frame):
     print('binary-search.py: CTRL+C detected and ignored')

def process_options ():
    parser = argparse.ArgumentParser(usage=""" 
    Conduct a binary search to find the maximum packet rate within acceptable loss percent
    """);

    parser.add_argument('--output-dir',
                        dest='output_dir',
                        help='Directory where the output should be stored',
                        default="./"
                        )
    parser.add_argument('--frame-size', 
                        dest='frame_size',
                        help='L2 frame size in bytes or IMIX',
                        default="64"
                        )
    parser.add_argument('--num-flows', 
                        dest='num_flows',
                        help='number of unique network flows',
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
    parser.add_argument('--use-src-port-flows',
                        dest='use_src_port_flows',
                        help='implement flows by source port',
                        default=0,
                        type = int,
                        )
    parser.add_argument('--use-dst-port-flows',
                        dest='use_dst_port_flows',
                        help='implement flows by destination port',
                        default=0,
                        type = int,
                        )
    parser.add_argument('--use-protocol-flows',
                        dest='use_protocol_flows',
                        help='implement flows by IP protocol',
                        default=0,
                        type = int,
                        )
    parser.add_argument('--use-encap-src-ip-flows', 
                        dest='use_encap_src_ip_flows',
                        help='implement flows by source IP in the encapsulated packet',
                        default=0,
                        type = int,
                        )
    parser.add_argument('--use-encap-dst-ip-flows', 
                        dest='use_encap_dst_ip_flows',
                        help='implement flows by destination IP in the encapsulated packet',
                        default=0,
                        type = int,
                        )
    parser.add_argument('--use-encap-src-mac-flows', 
                        dest="use_encap_src_mac_flows",
                        help='implement flows by source MAC in the encapsulated packet',
                        default=0,
                        type = int,
                        )
    parser.add_argument('--use-encap-dst-mac-flows', 
                        dest="use_encap_dst_mac_flows",
                        help='implement flows by destination MAC in the encapsulated packet',
                        default=0,
                        type = int,
                        )
    parser.add_argument('--one-shot', 
                        dest='one_shot',
                        help='0 = run regular binary seach, 1 = run single trial',
                        default=0,
                        type = int,
                        )
    parser.add_argument('--traffic-direction',
                        dest='traffic_direction',
                        help='What direction is the traffic flow?',
                        default = 'bidirectional',
                        choices = ['bidirectional', 'unidirectional', 'revunidirectional']
                        )
    parser.add_argument('--validation-runtime', 
                        dest='validation_runtime',
                        help='tiral period in seconds during final validation',
                        default=30,
                        type = int,
                        )
    parser.add_argument('--search-runtime', 
                        dest='search_runtime',
                        help='tiral period in seconds during binary search',
                        default=30,
                        type = int,
                        )
    parser.add_argument('--sniff-runtime',
                        dest='sniff_runtime',
                        help='trial period in seconds during sniff search',
                        default = 0,
                        type = int,
                        )
    parser.add_argument('--rate', 
                        dest='rate',
                        help='rate per device',
                        default = 0.0,
                        type = float
                        )
    parser.add_argument('--min-rate',
                        dest='min_rate',
                        help='minimum rate per device',
                        default = 0.0,
                        type = float
                        )
    parser.add_argument('--rate-unit',
                        dest='rate_unit',
                        help='rate unit per device',
                        default = "mpps",
                        choices = [ '%', 'mpps' ]
                        )
    parser.add_argument('--packet-protocol',
                        dest='packet_protocol',
                        help='IP protocol to use when constructing packets',
                        default = "UDP",
                        choices = [ 'UDP', 'TCP' ]
                        )
    parser.add_argument('--rate-tolerance',
                        dest='rate_tolerance',
                        help='percentage that TX rate is allowed to vary from requested rate and still be considered valid',
                        default = 5,
                        type = float
                        )
    parser.add_argument('--rate-tolerance-failure',
                        dest='rate_tolerance_failure',
                        help='What to do when a rate tolerance failure is encountered',
                        default = 'quit',
                        choices = [ 'fail', 'quit' ]
                        )
    parser.add_argument('--runtime-tolerance',
                        dest='runtime_tolerance',
                        help='percentage that runtime is allowed to vary from requested runtime and still be considered valid',
                        default = 5,
                        type = float
                        )
    parser.add_argument('--search-granularity',
                        dest='search_granularity',
                        help='the binary search will stop once the percent throughput difference between the most recent passing and failing trial is lower than this',
                        default = 0.1,
                        type = float
                        )
    parser.add_argument('--max-loss-pct', 
                        dest='max_loss_pct',
                        help='maximum percentage of packet loss',
                        default=0.002,
			type = float
                        )
    parser.add_argument('--src-ports',
                        dest='src_ports',
                        help='comma separated list of source ports, 1 per device',
                        default=""
                        )
    parser.add_argument('--dst-ports',
                        dest='dst_ports',
                        help='comma separated list of destination ports, 1 per device',
                        default=""
                        )
    parser.add_argument('--dst-macs', 
                        dest='dst_macs',
                        help='comma separated list of destination MACs, 1 per device',
                        default=""
                        )
    parser.add_argument('--src-macs', 
                        dest='src_macs',
                        help='comma separated list of src MACs, 1 per device',
                        default=""
                        )
    parser.add_argument('--encap-dst-macs', 
                        dest='encap_dst_macs',
                        help='comma separated list of destination MACs for encapulsated network, 1 per device',
                        default=""
                        )
    parser.add_argument('--encap-src-macs', 
                        dest='encap_src_macs',
                        help='comma separated list of src MACs for encapulsated network, 1 per device',
                        default=""
                        )
    parser.add_argument('--dst-ips', 
                        dest='dst_ips',
                        help='comma separated list of destination IPs 1 per device',
                        default=""
                        )
    parser.add_argument('--src-ips', 
                        dest='src_ips',
                        help='comma separated list of src IPs, 1 per device',
                        default=""
                        )
    parser.add_argument('--vxlan-ids', 
                        dest='vxlan_ids',
                        help='comma separated list of VxLAN IDs, 1 per device',
                        default=""
                        )
    parser.add_argument('--vlan-ids', 
                        dest='vlan_ids',
                        help='comma separated list of VLAN IDs, 1 per device',
                        default=""
                        )
    parser.add_argument('--encap-dst-ips', 
                        dest='encap_dst_ips',
                        help='comma separated list of destination IPs for excapsulated network, 1 per device',
                        default=""
                        )
    parser.add_argument('--encap-src-ips', 
                        dest='encap_src_ips',
                        help='comma separated list of src IPs for excapsulated network,, 1 per device',
                        default=""
                        )
    parser.add_argument('--traffic-generator', 
                        dest='traffic_generator',
                        help='name of traffic generator: trex-txrx or trex-txrx-profile or moongen-txrx of null-txrx',
                        default="trex-txrx"
                        )
    parser.add_argument('--measure-latency',
                        dest='measure_latency',
                        help='Collect latency statistics or not',
                        default = 1,
                        type = int
                        )
    parser.add_argument('--latency-rate',
                        dest='latency_rate',
                        help='Rate to send latency packets per second',
                        default = 1000,
                        type = int
                   )
    parser.add_argument('--trial-gap',
                        dest='trial_gap',
                        help='Time to sleep between trial attempts',
                        default = 0,
                        type = int
                        )
    parser.add_argument('--max-retries',
                        dest='max_retries',
                        help='Maximum number of trial retries before aborting',
                        default = 3,
                        type = int
                        )
    parser.add_argument('--loss-granularity',
                        dest='loss_granularity',
                        help='Test for packet loss at a granularity of direction, device, or segment',
                        default = "direction",
                        choices = [ 'direction', 'device', 'segment' ]
                        )
    parser.add_argument('--stream-mode',
                        dest='stream_mode',
                        help='How the packet streams are constructed',
                        default = "continuous",
                        choices = [ 'continuous', 'segmented' ]
                        )
    parser.add_argument('--use-device-stats',
                        dest='use_device_stats',
                        help='Should device stats be used instead of stream stats',
                        action = 'store_true',
                        )
    parser.add_argument('--enable-segment-monitor',
                        dest='enable_segment_monitor',
                        help='Should individual segments be monitored for pass/fail status relative to --max-loss-pct in order to short circuit trials',
                        action = 'store_true',
                        )
    parser.add_argument('--device-pairs',
                        dest='device_pairs',
                        help='List of device pairs in the form A:B[,C:D][,E:F][,...]',
                        default="0:1",
                        )
    parser.add_argument('--active-device-pairs',
                        dest='active_device_pairs',
                        help='List of active device pairs in the form A:B[,C:D][,E:F][,...]',
                        default='--',
                        )
    parser.add_argument('--disable-flow-cache',
                        dest='enable_flow_cache',
                        help='Force disablement of the TRex flow cache',
                        action = 'store_false',
                        )
    parser.add_argument('--send-teaching-warmup',
                        dest='send_teaching_warmup',
                        help='Send teaching packets from the receiving port during a warmup phase',
                        action = 'store_true',
                        )
    parser.add_argument('--send-teaching-measurement',
                        dest='send_teaching_measurement',
                        help='Send teaching packets from the receiving port during the measurement phase',
                        action = 'store_true',
                        )
    parser.add_argument('--teaching-measurement-interval',
                        dest='teaching_measurement_interval',
                        help='Interval to send teaching packets on from the receiving port during the measurement phase in seconds',
                        default = 10.0,
                        type = float
                        )
    parser.add_argument('--teaching-warmup-packet-rate',
                        dest='teaching_warmup_packet_rate',
                        help='Rate to send teaching packets at from the receiving port in packets per second (pps) during the warmup',
                        default = 1000,
                        type = int
                        )
    parser.add_argument('--teaching-measurement-packet-rate',
                        dest='teaching_measurement_packet_rate',
                        help='Rate to send teaching packets at from the receiving port in packets per second (pps) during the measurement phase',
                        default = 1000,
                        type = int
                        )
    parser.add_argument('--teaching-warmup-packet-type',
                        dest='teaching_warmup_packet_type',
                        help='Type of packet to send for the teaching warmup from the receiving port',
                        default = '',
                        choices = ['garp', 'icmp', 'generic']
                        )
    parser.add_argument('--teaching-measurement-packet-type',
                        dest='teaching_measurement_packet_type',
                        help='Type of packet to send for the teaching measurement from the receiving port',
                        default = '',
                        choices = ['garp', 'icmp', 'generic']
                        )
    parser.add_argument('--traffic-profile',
                        dest='traffic_profile',
                        help='Name of the file containing traffic profiles to load',
                        default = '',
                        type = str
                        )
    parser.add_argument('--random-seed',
                        dest='random_seed',
                        help='Specify a fixed random seed for repeatable results (defaults to not repeatable)',
                        default = random.random(),
                        type = float
                        )
    parser.add_argument('--pre-trial-cmd',
                        dest='pre_trial_cmd',
                        help='Specify a script/binary to execute prior to each trial',
                        default = '',
                        type = str
                        )
    parser.add_argument('--disable-trex-profiler',
                        dest='enable_trex_profiler',
                        help='Force disablement of the TRex profiler',
                        action = 'store_false'
                        )
    parser.add_argument('--trex-profiler-interval',
                        dest='trex_profiler_interval',
                        help='Interval to collect samples on when using the TRex profiler',
                        default = 3.0,
                        type = float
                        )

    t_global.args = parser.parse_args();
    if t_global.args.frame_size == "IMIX":
         t_global.args.frame_size = "imix"
    if t_global.args.active_device_pairs == '--':
         t_global.args.active_device_pairs = t_global.args.device_pairs
    print(t_global.args)

def execute_pre_trial_cmd(trial_params):
     cmd = trial_params['pre_trial_cmd']

     previous_sig_handler = signal.signal(signal.SIGINT, sigint_handler)

     print("Executing pre-trial-cmd [%s]" % (cmd))

     the_process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
     exit_event = threading.Event()

     io_thread = threading.Thread(target = handle_pre_trial_cmd_io, args = (the_process, exit_event))

     io_thread.start()

     exit_event.wait()

     retval = the_process.wait()

     io_thread.join()

     signal.signal(signal.SIGINT, previous_sig_handler)

     print('return code', retval)

def handle_pre_trial_cmd_io(process, exit_event):
     capture_output = True
     do_loop = True
     while do_loop:
          lines = handle_process_output(process, process.stdout, capture_output)

          for line in lines:
               if line == "--END--":
                    exit_event.set()
                    do_loop = False
                    continue
               else:
                    print('Pre Trial CMD: %s' % (line.rstrip('\n')))

def get_trex_port_info(trial_params, dev_pairs):
     devices = dict()
     device_string = ""

     trial_params['max_port'] = 0

     for dev_pair in dev_pairs:
          for direction in [ 'tx', 'rx' ]:
               if not dev_pair[direction] in devices:
                    devices[dev_pair[direction]] = 1
                    device_string = device_string + ' --device ' + str(dev_pair[direction])
                    if dev_pair[direction] > trial_params['max_port']:
                         trial_params['max_port'] = dev_pair[direction]
               else:
                    devices[dev_pair[direction]] += 1

     cmd = 'python trex-query.py'
     cmd = cmd + ' --mirrored-log'
     cmd = cmd + device_string

     previous_sig_handler = signal.signal(signal.SIGINT, sigint_handler)

     port_info = { 'json': None }

     print('querying TRex...')
     print('cmd:', cmd)
     query_process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
     stdout_exit_event = threading.Event()
     stderr_exit_event = threading.Event()

     stdout_thread = threading.Thread(target = handle_query_process_stdout, args = (query_process, stdout_exit_event))
     stderr_thread = threading.Thread(target = handle_query_process_stderr, args = (query_process, trial_params, port_info, stderr_exit_event))

     stdout_thread.start()
     stderr_thread.start()

     stdout_exit_event.wait()
     stderr_exit_event.wait()
     retval = query_process.wait()

     stdout_thread.join()
     stderr_thread.join()

     signal.signal(signal.SIGINT, previous_sig_handler)

     print('return code', retval)
     return port_info['json']

def handle_query_process_stdout(process, exit_event):
     capture_output = True
     do_loop = True
     while do_loop:
          stdout_lines = handle_process_output(process, process.stdout, capture_output)

          for line in stdout_lines:
               if line == "--END--":
                    exit_event.set()
                    do_loop = False
                    continue

def handle_query_process_stderr(process, trial_params, port_info, exit_event):
     primary_output_file = None
     primary_close_file = False
     trial_params['port_primary_info_file'] = "binary-search.port-info.txt"
     filename = "%s/%s" % (trial_params['output_dir'], trial_params['port_primary_info_file'])
     try:
          primary_output_file = open(filename, 'w')
          primary_close_file = True
     except IOError:
          print(error("Could not open %s for writing" % (filename)))
          primary_output_file = sys.stdout

     secondary_output_file = None
     secondary_close_file = False
     trial_params['port_secondary_info_file'] = "binary-search.port-info.extra.txt"
     filename = "%s/%s" % (trial_params['output_dir'], trial_params['port_secondary_info_file'])
     try:
          secondary_output_file = open(filename, 'w')
          secondary_close_file = True
     except IOError:
          print(error("Could not open %s for writing" % (filename)))
          secondary_output_file = sys.stdout

     capture_output = True
     do_loop = True
     while do_loop:
          stderr_lines = handle_process_output(process, process.stderr, capture_output)

          for line in stderr_lines:
               if line == "--END--":
                    exit_event.set()
                    do_loop = False
                    continue

               m = re.search(r"PARSABLE PORT INFO:\s+(.*)$", line)
               if m:
                    print(line, file=secondary_output_file)

                    port_info['json'] = json.loads(m.group(1))

                    continue

               if primary_close_file:
                    print(line.rstrip('\n'))
               print(line.rstrip('\n'), file=primary_output_file)

               if line.rstrip('\n') == "Connection severed":
                    capture_output = False
                    exit_event.set()

     if primary_close_file:
          primary_output_file.close()

     if secondary_close_file:
          secondary_output_file.close()

def calculate_tx_pps_target(trial_params, streams, tmp_stats):
     stream_types = [ 'default', 'latency' ]

     rate_target = 0.0

     # packet overhead is (7 byte preamable + 1 byte SFD -- Start of Frame Delimiter -- + 12 byte IFG -- Inter Frame Gap)
     packet_overhead_bytes = 20
     bits_per_byte = 8
     crc_bytes = 4

     default_packet_avg_bytes = 0.0
     latency_packet_avg_bytes = 0.0

     target_latency_bytes = 0.0
     target_default_bytes = 0.0
     target_default_rate = 0.0
     if trial_params['rate_unit'] == "%":
          if trial_params['traffic_generator'] == 'trex-txrx':
               total_target_bytes = (tmp_stats['tx_available_bandwidth'] / bits_per_byte) * (trial_params['rate'] / 100)
          elif trial_params['traffic_generator'] == 'trex-txrx-profile':
               total_target_bytes = 0

               for stream_type in stream_types:
                    for stream_frame_size, stream_pps in zip(streams[stream_type]['frame_sizes'], streams[stream_type]['pps']):
                         total_target_bytes += (stream_frame_size + packet_overhead_bytes) * stream_pps
     else:
          if trial_params['frame_size'] < 64:
               frame_size = 64
          else:
               frame_size = trial_params['frame_size']
          total_target_bytes = (frame_size + packet_overhead_bytes) * trial_params['rate'] * 1000000

     if trial_params['traffic_generator'] == 'trex-txrx-profile':
          for stream_type in stream_types:
               for stream_pps in streams[stream_type]['pps']:
                    rate_target += stream_pps
     else:
          for frame_size, traffic_shares in zip(streams['default']['frame_sizes'], streams['default']['traffic_shares']):
               default_packet_avg_bytes += (frame_size * traffic_shares)

          if trial_params['measure_latency']:
               for frame_size, traffic_shares in zip(streams['latency']['frame_sizes'], streams['latency']['traffic_shares']):
                    latency_packet_avg_bytes += (frame_size * traffic_shares)

               target_latency_bytes = (latency_packet_avg_bytes + packet_overhead_bytes) * trial_params['latency_rate']

          target_default_bytes = total_target_bytes - target_latency_bytes

          target_default_rate = target_default_bytes / (default_packet_avg_bytes + packet_overhead_bytes)

          rate_target = target_default_rate
          if trial_params['measure_latency']:
               rate_target += trial_params['latency_rate']

     tmp_stats['packet_overhead_bytes'] = packet_overhead_bytes
     tmp_stats['bits_per_byte'] = bits_per_byte
     tmp_stats['crc_bytes'] = crc_bytes

     return rate_target

def stats_error_append_pg_id(stats, action, pg_id):
     action += "_error"
     if action in stats:
          stats[action] += "," + str(pg_id)
     else:
          stats[action] = str(pg_id)
     return

def run_trial (trial_params, port_info, stream_info, detailed_stats):
    stats = dict()
    tmp_stats = dict()
    streams = dict()

    if trial_params['traffic_generator'] == 'moongen-txrx' or trial_params['traffic_generator'] == 'null-txrx':
         stats[0] = dict()
         stats[0]['tx_packets'] = 0
         stats[0]['rx_packets'] = 0
         stats[1] = dict()
         stats[1]['tx_packets'] = 0
         stats[1]['rx_packets'] = 0
    elif trial_params['traffic_generator'] == 'trex-txrx' or trial_params['traffic_generator'] == 'trex-txrx-profile':
         for dev_pair in trial_params['test_dev_pairs']:
              for port in [ 'tx', 'rx' ]:
                   if not dev_pair[port] in stats:
                        stats[dev_pair[port]] = copy.deepcopy(trial_params['null_stats'])
                        tmp_stats[dev_pair[port]]= { 'tx_available_bandwidth': 0.0 }
                        streams[dev_pair[port]] = {}

    cmd = ""

    trial_params['trial_profiler_file'] = "N/A"

    if trial_params['traffic_generator'] == 'moongen-txrx':
        cmd = './MoonGen/build/MoonGen txrx.lua'
        cmd = cmd + ' --devices=0,1' # fix to allow different devices
        cmd = cmd + ' --measureLatency=0' # fix to allow latency measurment (whern txrx supports)
        cmd = cmd + ' --rate=' + str(trial_params['rate'])
	cmd = cmd + ' --size=' + str(trial_params['frame_size'])
	cmd = cmd + ' --runTime=' + str(trial_params['runtime'])

	traffic_direction=0
	if trial_params['traffic_direction'] == 'bidirectional':
            traffic_direction=1
	cmd = cmd + ' --bidirectional=' + str(traffic_direction)

        if trial_params['vlan_ids'] != '':
            cmd = cmd + ' --vlanIds=' + str(trial_params['vlan_ids'])
        if trial_params['vxlan_ids'] != '':
            cmd = cmd + ' --vxlanIds=' + str(trial_params['vxlan_ids'])
        if trial_params['src_ips'] != '':
            cmd = cmd + ' --srcIps=' + str(trial_params['src_ips'])
        if trial_params['dst_ips'] != '':
            cmd = cmd + ' --dstIps=' + str(trial_params['dst_ips'])
        if trial_params['src_macs'] != '':
            cmd = cmd + ' --srcMacs=' + str(trial_params['src_macs'])
        if trial_params['dst_macs'] != '':
            cmd = cmd + ' --dstMacs=' + str(trial_params['dst_macs'])
        if trial_params['encap_src_ips'] != '':
            cmd = cmd + ' --encapSrcIps=' + str(trial_params['encap_src_ips'])
        if trial_params['encap_dst_ips'] != '':
            cmd = cmd + ' --encapDstIps=' + str(trial_params['encap_dst_ips'])
        if trial_params['encap_src_macs'] != '':
            cmd = cmd + ' --encapSrcMacs=' + str(trial_params['encap_src_macs'])
        if trial_params['encap_dst_macs'] != '':
            cmd = cmd + ' --encapDstMacs=' + str(trial_params['encap_dst_macs'])
        flow_mods_opt = ''
        if trial_params['use_src_ip_flows'] == 1:
	    flow_mods_opt = flow_mods_opt + ',srcIp'
        if trial_params['use_dst_ip_flows'] == 1:
	    flow_mods_opt = flow_mods_opt + ',dstIp'
        if trial_params['use_encap_src_ip_flows'] == 1:
	    flow_mods_opt = flow_mods_opt + ',encapSrcIp'
        if trial_params['use_encap_dst_ip_flows'] == 1:
	    flow_mods_opt = flow_mods_opt + ',encapDstIp'
        if trial_params['use_src_mac_flows'] == 1:
	    flow_mods_opt = flow_mods_opt + ',srcMac'
        if trial_params['use_dst_mac_flows'] == 1:
	    flow_mods_opt = flow_mods_opt + ',dstMac'
        if trial_params['use_encap_src_mac_flows'] == 1:
	    flow_mods_opt = flow_mods_opt + ',encapSrcMac'
        if trial_params['use_encap_dst_mac_flows'] == 1:
	    flow_mods_opt = flow_mods_opt + ',encapDstMac'
        flow_mods_opt = ' --flowMods="' + re.sub('^,', '', flow_mods_opt) + '"'
        cmd = cmd + flow_mods_opt
    elif trial_params['traffic_generator'] == 'null-txrx':
         cmd = 'python null-txrx.py'
         cmd = cmd + ' --mirrored-log'
         cmd = cmd + ' --rate=' + str(trial_params['rate'])
    elif trial_params['traffic_generator'] == 'trex-txrx-profile':
        for tmp_stats_index, tmp_stats_id in enumerate(tmp_stats):
             tmp_stats[tmp_stats_id]['tx_available_bandwidth'] = port_info[tmp_stats_id]['speed'] * 1000 * 1000 * 1000

        cmd = 'python trex-txrx-profile.py'
        cmd = cmd + ' --mirrored-log'
        cmd = cmd + ' --random-seed=' + str(trial_params['random_seed'])
        cmd = cmd + ' --device-pairs=' + str(trial_params['device_pairs'])
        cmd = cmd + ' --active-device-pairs=' + str(trial_params['active_device_pairs'])
        cmd = cmd + ' --runtime=' + str(trial_params['runtime'])
        cmd = cmd + ' --runtime-tolerance=' + str(trial_params['runtime_tolerance'])
        cmd = cmd + ' --rate-modifier=' + str(trial_params['rate'])
        if trial_params['measure_latency']:
             cmd = cmd + ' --measure-latency'
        cmd = cmd + ' --latency-rate=' + str(trial_params['latency_rate'])
        cmd = cmd + ' --max-loss-pct=' + str(trial_params['max_loss_pct'])
        if trial_params['enable_trex_profiler']:
             cmd = cmd + ' --enable-profiler'
             cmd = cmd + ' --profiler-interval=' + str(trial_params['trex_profiler_interval'])
             trial_params['trial_profiler_file'] = "binary-search.trial-%03d.profiler.txt" % (trial_params['trial'])
             cmd = cmd + ' --profiler-logfile=' + trial_params['output_dir'] + '/' + trial_params['trial_profiler_file']
        if not trial_params['enable_flow_cache']:
             cmd = cmd + ' --disable-flow-cache'
        if trial_params['send_teaching_warmup']:
             cmd = cmd + ' --send-teaching-warmup'
        if trial_params['send_teaching_measurement']:
             cmd = cmd + ' --send-teaching-measurement'
        if trial_params['teaching_measurement_interval']:
             cmd = cmd + ' --teaching-measurement-interval=' + str(trial_params['teaching_measurement_interval'])
        if trial_params['teaching_warmup_packet_rate']:
             cmd = cmd + ' --teaching-warmup-packet-rate=' + str(trial_params['teaching_warmup_packet_rate'])
        if trial_params['teaching_measurement_packet_rate']:
             cmd = cmd + ' --teaching-measurement-packet-rate=' + str(trial_params['teaching_measurement_packet_rate'])
        cmd = cmd + ' --traffic-profile=' + trial_params['traffic_profile']

    elif trial_params['traffic_generator'] == 'trex-txrx':
        for tmp_stats_index, tmp_stats_id in enumerate(tmp_stats):
             tmp_stats[tmp_stats_id]['tx_available_bandwidth'] = port_info[tmp_stats_id]['speed'] * 1000 * 1000 * 1000

        cmd = 'python trex-txrx.py'
        cmd = cmd + ' --device-pairs=' + str(trial_params['device_pairs'])
        cmd = cmd + ' --active-device-pairs=' + str(trial_params['active_device_pairs'])
        cmd = cmd + ' --mirrored-log'
        cmd = cmd + ' --measure-latency=' + str(trial_params['measure_latency'])
        cmd = cmd + ' --latency-rate=' + str(trial_params['latency_rate'])
        cmd = cmd + ' --rate=' + str(trial_params['rate'])
        cmd = cmd + ' --rate-unit=' + str(trial_params['rate_unit'])
        cmd = cmd + ' --size=' + str(trial_params['frame_size'])
        cmd = cmd + ' --runtime=' + str(trial_params['runtime'])
        cmd = cmd + ' --runtime-tolerance=' + str(trial_params['runtime_tolerance'])

        if trial_params['traffic_direction'] == 'bidirectional':
             cmd = cmd + ' --run-bidirec=1'
             cmd = cmd + ' --run-revunidirec=0'
        elif trial_params['traffic_direction'] == 'unidirectional':
             cmd = cmd + ' --run-bidirec=0'
             cmd = cmd + ' --run-revunidirec=0'
        elif trial_params['traffic_direction'] == 'revunidirectional':
             cmd = cmd + ' --run-bidirec=0'
             cmd = cmd + ' --run-revunidirec=1'

        cmd = cmd + ' --num-flows=' + str(trial_params['num_flows'])
        if trial_params['src_ports'] != '':
             cmd = cmd + ' --src-ports=' + str(trial_params['src_ports'])
        if trial_params['dst_ports'] != '':
             cmd = cmd + ' --dst-ports=' + str(trial_params['dst_ports'])
        if trial_params['src_ips'] != '':
             cmd = cmd + ' --src-ips=' + str(trial_params['src_ips'])
        if trial_params['dst_ips'] != '':
             cmd = cmd + ' --dst-ips=' + str(trial_params['dst_ips'])
        if trial_params['src_macs'] != '':
             cmd = cmd + ' --src-macs=' + str(trial_params['src_macs'])
        if trial_params['dst_macs'] != '':
             cmd = cmd + ' --dst-macs=' + str(trial_params['dst_macs'])
        if trial_params['vlan_ids'] != '':
             cmd = cmd + ' --vlan-ids=' + str(trial_params['vlan_ids'])
        cmd = cmd + ' --use-src-ip-flows=' + str(trial_params['use_src_ip_flows'])
        cmd = cmd + ' --use-dst-ip-flows=' + str(trial_params['use_dst_ip_flows'])
        cmd = cmd + ' --use-src-mac-flows=' + str(trial_params['use_src_mac_flows'])
        cmd = cmd + ' --use-dst-mac-flows=' + str(trial_params['use_dst_mac_flows'])
        cmd = cmd + ' --use-src-port-flows=' + str(trial_params['use_src_port_flows'])
        cmd = cmd + ' --use-dst-port-flows=' + str(trial_params['use_dst_port_flows'])
        cmd = cmd + ' --use-protocol-flows=' + str(trial_params['use_protocol_flows'])
        cmd = cmd + ' --packet-protocol=' + str(trial_params['packet_protocol'])
        cmd = cmd + ' --stream-mode=' + trial_params['stream_mode']
        cmd = cmd + ' --max-loss-pct=' + str(trial_params['max_loss_pct'])
        if trial_params['stream_mode'] == "segmented" and trial_params['enable_segment_monitor']:
             cmd = cmd + ' --enable-segment-monitor'
        if trial_params['use_device_stats']:
             cmd = cmd + ' --skip-hw-flow-stats'
        if not trial_params['enable_flow_cache']:
             cmd = cmd + ' --disable-flow-cache'
        if trial_params['send_teaching_warmup']:
             cmd = cmd + ' --send-teaching-warmup'
        if trial_params['send_teaching_measurement']:
             cmd = cmd + ' --send-teaching-measurement'
        if trial_params['teaching_measurement_interval']:
             cmd = cmd + ' --teaching-measurement-interval=' + str(trial_params['teaching_measurement_interval'])
        if trial_params['teaching_warmup_packet_rate']:
             cmd = cmd + ' --teaching-warmup-packet-rate=' + str(trial_params['teaching_warmup_packet_rate'])
        if trial_params['teaching_measurement_packet_rate']:
             cmd = cmd + ' --teaching-measurement-packet-rate=' + str(trial_params['teaching_measurement_packet_rate'])
        if trial_params['teaching_warmup_packet_type']:
             cmd = cmd + ' --teaching-warmup-packet-type=' + str(trial_params['teaching_warmup_packet_type'])
        if trial_params['teaching_measurement_packet_type']:
             cmd = cmd + ' --teaching-measurement-packet-type=' + str(trial_params['teaching_measurement_packet_type'])

    previous_sig_handler = signal.signal(signal.SIGINT, sigint_handler)

    print('cmd:', cmd)
    tg_process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout_exit_event = threading.Event()
    stderr_exit_event = threading.Event()

    stdout_thread = threading.Thread(target = handle_trial_process_stdout, args = (tg_process, trial_params, stats, stdout_exit_event))
    stderr_thread = threading.Thread(target = handle_trial_process_stderr, args = (tg_process, trial_params, stats, tmp_stats, streams, detailed_stats, stderr_exit_event))

    stdout_thread.start()
    stderr_thread.start()

    stdout_exit_event.wait()
    stderr_exit_event.wait()
    retval = tg_process.wait()

    stdout_thread.join()
    stderr_thread.join()

    signal.signal(signal.SIGINT, previous_sig_handler)

    print('return code', retval)
    stream_info['streams'] = streams
    return stats

def handle_process_output(process, process_stream, capture):
     lines = []
     if process.poll() is None:
          process_stream.flush()
          ready_streams = select.select([process_stream], [], [], 1)
          if process_stream in ready_streams[0]:
               line = process_stream.readline()
               if capture:
                    lines.append(line)
     if process.poll() is not None:
          for line in process_stream:
               if capture:
                    lines.append(line)
          lines.append("--END--")
     return lines

def handle_trial_process_stdout(process, trial_params, stats, exit_event):
    prefix = "%03d" % trial_params['trial']

    capture_output = True
    do_loop = True
    while do_loop:
        stdout_lines = handle_process_output(process, process.stdout, capture_output)

        for line in stdout_lines:
             if line == "--END--":
                  exit_event.set()
                  do_loop = False
                  continue

             print("%s:%s" % (prefix, line.rstrip('\n')))

             if trial_params['traffic_generator'] == 'moongen-txrx':
                  #[INFO]  [0]->[1] txPackets: 10128951 rxPackets: 10128951 packetLoss: 0 txRate: 2.026199 rxRate: 2.026199 packetLossPct: 0.000000
                  #[INFO]  [0]->[1] txPackets: 10130148 rxPackets: 10130148 packetLoss: 0 txRate: 2.026430 rxRate: 2.026430 packetLossPct: 0.000000
                  m = re.search(r"\[INFO\]\s+\[(\d+)\]\-\>\[(\d+)\]\s+txPackets:\s+(\d+)\s+rxPackets:\s+(\d+)\s+packetLoss:\s+(\-*\d+)\s+txRate:\s+(\d+\.\d+)\s+rxRate:\s+(\d+\.\d+)\s+packetLossPct:\s+(\-*\d+\.\d+)", line)
                  if m:
                       print('tx_packets, tx_rate, device', m.group(3), m.group(6), int(m.group(1)))
                       print('rx_packets, rx_rate, device', m.group(4), m.group(7), int(m.group(2)))
                       #stats[0] = {'rx_packets':int(m.group(4)), 'tx_packets':int(m.group(3)), 'tx_rate':float(m.group(6)), 'rx_rate':float(m.group(7))}
                       #stats[1] = {'rx_packets':0, 'tx_packets':0, 'tx_rate':0, 'rx_rate':0}
                       stats[int(m.group(1))]['tx_packets'] = int(m.group(3))
                       stats[int(m.group(1))]['tx_pps'] = float(m.group(3)) / float(trial_params['runtime'])
                       stats[int(m.group(2))]['rx_packets'] = int(m.group(4))
                       stats[int(m.group(2))]['rx_pps'] = float(m.group(4)) / float(trial_params['runtime'])
             elif trial_params['traffic_generator'] == 'null-txrx':
                  if line.rstrip('\n') == "exiting":
                       capture_output = False
                       exit_event.set()
                  m = re.search(r"result=(.*)$", line)
                  if m:
                       print("trial result: %s" % m.group(1))

                       total_packets = 1000000
                       max_lost_packets = total_packets * (trial_params['max_loss_pct'] / 100)
                       pass_packets = total_packets - random.randint(0, max_lost_packets - 1)
                       fail_packets = total_packets - random.randint(max_lost_packets + 1, total_packets)

                       if m.group(1) == "pass":
                            if trial_params['traffic_direction'] != 'revunidirectional':
                                 stats[0]['tx_packets'] = total_packets
                                 stats[0]['tx_pps'] = float(total_packets) / float(trial_params['runtime'])
                                 stats[1]['rx_packets'] = pass_packets
                                 stats[1]['rx_pps'] = float(pass_packets) / float(trial_params['runtime'])
                                 stats[1]['rx_lost_packets'] = total_packets - pass_packets
                                 stats[1]['rx_lost_packets_pct'] = float(stats[1]['rx_lost_packets']) / float(total_packets)
                            if trial_params['traffic_direction'] == 'bidirectional' or trial_params['traffic_direction'] == 'revunidirectional':
                                 stats[1]['tx_packets'] = total_packets
                                 stats[1]['tx_pps'] = float(total_packets) / float(trial_params['runtime'])
                                 stats[0]['rx_packets'] = pass_packets
                                 stats[0]['rx_pps'] = float(pass_packets) / float(trial_params['runtime'])
                                 stats[0]['rx_lost_packets'] = total_packets - pass_packets
                                 stats[0]['rx_lost_packets_pct'] = float(stats[0]['rx_lost_packets']) / float(total_packets)
                       elif m.group(1) == "fail":
                            if trial_params['traffic_direction'] != 'revunidirectional':
                                 stats[0]['tx_packets'] = total_packets
                                 stats[0]['tx_pps'] = float(total_packets) / float(trial_params['runtime'])
                                 stats[1]['rx_packets'] = fail_packets
                                 stats[1]['rx_pps'] = float(fail_packets) / float(trial_params['runtime'])
                                 stats[1]['rx_lost_packets'] = total_packets - fail_packets
                                 stats[1]['rx_lost_packets_pct'] = float(stats[1]['rx_lost_packets']) / float(total_packets)
                            if trial_params['traffic_direction'] == 'bidirectional' or trial_params['traffic_direction'] == 'revunidirectional':
                                 stats[1]['tx_packets'] = total_packets
                                 stats[1]['tx_pps'] = float(total_packets) / float(trial_params['runtime'])
                                 stats[0]['rx_packets'] = fail_packets
                                 stats[0]['rx_pps'] = float(fail_packets) / float(trial_params['runtime'])
                                 stats[0]['rx_lost_packets'] = total_packets - fail_packets
                                 stats[0]['rx_lost_packets_pct'] = float(stats[0]['rx_lost_packets']) / float(total_packets)
             elif trial_params['traffic_generator'] == 'trex-txrx' or trial_params['traffic_generator'] == 'trex-txrx-profile':
                  if line.rstrip('\n') == "Connection severed":
                       capture_output = False
                       exit_event.set()

def handle_trial_process_stderr(process, trial_params, stats, tmp_stats, streams, detailed_stats, exit_event):
    primary_output_file = None
    primary_close_file = False
    trial_params['trial_primary_output_file'] = "binary-search.trial-%03d.txt" % (trial_params['trial'])
    filename = "%s/%s" % (trial_params['output_dir'], trial_params['trial_primary_output_file'])
    try:
         primary_output_file = open(filename, 'w')
         primary_close_file = True
    except IOError:
         print(error("Could not open %s for writing" % (filename)))
         primary_output_file = sys.stdout

    secondary_output_file = None
    secondary_close_file = False
    trial_params['trial_secondary_output_file'] = "binary-search.trial-%03d.extra.txt" % (trial_params['trial'])
    filename = "%s/%s" % (trial_params['output_dir'], trial_params['trial_secondary_output_file'])
    try:
         secondary_output_file = open(filename, 'w')
         secondary_close_file = True
    except IOError:
         print(error("Could not open %s for writing" % (filename)))
         secondary_output_file = sys.stdout

    capture_output = True
    do_loop = True
    while do_loop:
        stderr_lines = handle_process_output(process, process.stderr, capture_output)

        for line in stderr_lines:
             if line == "--END--":
                  exit_event.set()
                  do_loop = False
                  continue

             if trial_params['traffic_generator'] == 'moongen-txrx':
                  print(line.rstrip('\n'))
             if trial_params['traffic_generator'] == 'trex-txrx' or trial_params['traffic_generator'] == 'trex-txrx-profile':
                  m = re.search(r"DEVICE PAIR ([0-9]+:[0-9]+) \| PARSABLE STREAMS FOR DIRECTION '([0-9]+[-><]{2}[0-9]+)':\s+(.*)$", line)
                  if m:
                       print(line, file=secondary_output_file)

                       dev_pair = m.group(1)
                       path = m.group(2)
                       json_data = m.group(3)
                       for device_pair in trial_params['test_dev_pairs']:
                            if dev_pair == device_pair['dev_pair']:
                                 if path == device_pair['path']:
                                      streams[device_pair['tx']] = json.loads(json_data)
                                      stats[device_pair['tx']]['tx_pps_target'] = calculate_tx_pps_target(trial_params, streams[device_pair['tx']], tmp_stats[device_pair['tx']])
                       continue

                  m = re.search(r"PARSABLE RESULT:\s+(.*)$", line)
                  if m:
                       print(line, file=secondary_output_file)

                       results = json.loads(m.group(1))
                       detailed_stats['stats'] = copy.deepcopy(results)

                       stats['global'] = dict()

                       stats['global']['runtime'] = results['global']['runtime']
                       stats['global']['timeout'] = results['global']['timeout']
                       stats['global']['early_exit'] = results['global']['early_exit']
                       stats['global']['force_quit'] = results['global']['force_quit']

                       stats['directional'] = dict()
                       stats['directional']['->'] = dict()
                       stats['directional']['->']['active'] = False
                       stats['directional']['->']['tx_packets'] = 0
                       stats['directional']['->']['rx_packets'] = 0
                       stats['directional']['->']['rx_lost_packets'] = 0
                       stats['directional']['->']['rx_lost_packets_pct'] = 0
                       stats['directional']['<-'] = dict()
                       stats['directional']['<-']['active'] = False
                       stats['directional']['<-']['tx_packets'] = 0
                       stats['directional']['<-']['rx_packets'] = 0
                       stats['directional']['<-']['rx_lost_packets'] = 0
                       stats['directional']['<-']['rx_lost_packets_pct'] = 0

                       for device_pair in trial_params['test_dev_pairs']:
                            stream_types = []

                            if trial_params['use_device_stats']:
                                 stats[device_pair['tx']]['tx_active'] = True
                                 stats[device_pair['rx']]['rx_active'] = True

                                 stats[device_pair['tx']]['tx_packets'] += int(results[str(device_pair['tx'])]['opackets'])
                                 stats[device_pair['rx']]['rx_packets'] += int(results[str(device_pair['rx'])]['ipackets'])

                                 stats[device_pair['rx']]['rx_lost_packets'] = stats[device_pair['tx']]['tx_packets'] - stats[device_pair['rx']]['rx_packets']
                                 stats[device_pair['rx']]['rx_lost_packets_pct'] = 100.0 * stats[device_pair['rx']]['rx_lost_packets'] / stats[device_pair['tx']]['tx_packets']

                                 stats[device_pair['tx']]['tx_pps'] = float(stats[device_pair['tx']]['tx_packets']) / float(results['global']['runtime'])
                                 stats[device_pair['rx']]['rx_pps'] = float(stats[device_pair['rx']]['rx_packets']) / float(results['global']['runtime'])

                                 stats[device_pair['rx']]['rx_lost_pps'] = float(stats[device_pair['rx']]['rx_lost_packets']) / float(results['global']['runtime'])

                                 stats[device_pair['tx']]['tx_l1_bps'] += (int(results[str(device_pair['tx'])]['opackets']) * tmp_stats[device_pair['tx']]['packet_overhead_bytes']) + int(results[str(device_pair['tx'])]['obytes'])
                                 stats[device_pair['rx']]['rx_l1_bps'] += (int(results[str(device_pair['rx'])]['ipackets']) * tmp_stats[device_pair['tx']]['packet_overhead_bytes']) + int(results[str(device_pair['rx'])]['ibytes'])

                                 stats[device_pair['tx']]['tx_l2_bps'] += int(results[str(device_pair['tx'])]['obytes']) - (int(results[str(device_pair['tx'])]['opackets']) * tmp_stats[device_pair['tx']]['crc_bytes'])
                                 stats[device_pair['rx']]['rx_l2_bps'] += int(results[str(device_pair['rx'])]['ibytes']) - (int(results[str(device_pair['rx'])]['ipackets']) * tmp_stats[device_pair['tx']]['crc_bytes'])

                                 stats[device_pair['tx']]['tx_l1_bps'] = float(stats[device_pair['tx']]['tx_l1_bps']) / float(results['global']['runtime']) * tmp_stats[device_pair['tx']]['bits_per_byte']
                                 stats[device_pair['rx']]['rx_l1_bps'] = float(stats[device_pair['rx']]['rx_l1_bps']) / float(results['global']['runtime']) * tmp_stats[device_pair['tx']]['bits_per_byte']

                                 stats[device_pair['tx']]['tx_l2_bps'] = float(stats[device_pair['tx']]['tx_l2_bps']) / float(results['global']['runtime']) * tmp_stats[device_pair['tx']]['bits_per_byte']
                                 stats[device_pair['rx']]['rx_l2_bps'] = float(stats[device_pair['rx']]['rx_l2_bps']) / float(results['global']['runtime']) * tmp_stats[device_pair['tx']]['bits_per_byte']

                                 print("Device Pair: %s |   All TX   | packets=%s rate=%s l1_bps=%s l2_bps=%s" % (device_pair['path'], commify(stats[device_pair['tx']]['tx_packets']), commify(stats[device_pair['tx']]['tx_pps']), commify(stats[device_pair['tx']]['tx_l1_bps'], stats[device_pair['tx']]['tx_l2_bps'])))
                                 print("Device Pair: %s |   All RX   | packets=%s rate=%s l1_bps=%s l2_bps=%s" % (device_pair['path'], commify(stats[device_pair['rx']]['rx_packets']), commify(stats[device_pair['rx']]['rx_pps']), commify(stats[device_pair['rx']]['rx_l1_bps'], stats[device_pair['rx']]['rx_l2_bps'])))

                                 if trial_params['measure_latency']:
                                      stream_types.append('latency')
                            else:
                                 stream_types.append('default')
                                 if trial_params['measure_latency']:
                                      stream_types.append('latency')

                            for stream_type in stream_types:
                                 if device_pair['tx'] in streams and stream_type in streams[device_pair['tx']]:
                                      for pg_id, frame_size in zip(streams[device_pair['tx']][stream_type]['pg_ids'], streams[device_pair['tx']][stream_type]['frame_sizes']):
                                           if str(device_pair['tx']) in results['flow_stats'][str(pg_id)]['rx_pkts'] and int(results['flow_stats'][str(pg_id)]['rx_pkts'][str(device_pair['tx'])]):
                                                stats_error_append_pg_id(stats[device_pair['tx']], 'rx_invalid', pg_id)

                                           if str(device_pair['rx']) in results['flow_stats'][str(pg_id)]['tx_pkts'] and int(results['flow_stats'][str(pg_id)]['tx_pkts'][str(device_pair['rx'])]):
                                                stats_error_append_pg_id(stats[device_pair['rx']], 'tx_invalid', pg_id)

                                           if str(device_pair['tx']) in results['flow_stats'][str(pg_id)]['tx_pkts']:
                                                if not trial_params['use_device_stats']:
                                                     stats[device_pair['tx']]['tx_packets'] += int(results["flow_stats"][str(pg_id)]["tx_pkts"][str(device_pair['tx'])])
                                                     stats['directional'][device_pair['direction']]['tx_packets'] += stats[device_pair['tx']]['tx_packets']
                                                     stats['directional'][device_pair['direction']]['active'] = True

                                                if stream_type == "latency":
                                                     stats[device_pair['tx']]['tx_latency_packets'] += int(results["flow_stats"][str(pg_id)]["tx_pkts"][str(device_pair['tx'])])
                                                     stats['directional'][device_pair['direction']]['tx_packets'] += stats[device_pair['tx']]['tx_latency_packets']
                                                     stats['directional'][device_pair['direction']]['active'] = True
                                           else:
                                                stats_error_append_pg_id(stats[device_pair['tx']], 'tx_missing', pg_id)

                                           if str(device_pair['rx']) in results["flow_stats"][str(pg_id)]["rx_pkts"]:
                                                if not trial_params['use_device_stats']:
                                                     stats[device_pair['rx']]['rx_packets'] += int(results["flow_stats"][str(pg_id)]["rx_pkts"][str(device_pair['rx'])])
                                                     stats['directional'][device_pair['direction']]['rx_packets'] += stats[device_pair['rx']]['rx_packets']
                                                     stats['directional'][device_pair['direction']]['active'] = True

                                                if stream_type == "latency":
                                                     stats[device_pair['rx']]['rx_latency_packets'] += int(results["flow_stats"][str(pg_id)]["rx_pkts"][str(device_pair['rx'])])
                                                     stats['directional'][device_pair['direction']]['rx_packets'] += stats[device_pair['rx']]['rx_latency_packets']
                                                     stats['directional'][device_pair['direction']]['active'] = True

                                                     stats[device_pair['rx']]['rx_latency_average'] += int(results["flow_stats"][str(pg_id)]["rx_pkts"][str(device_pair['rx'])]) * float(results["latency"][str(pg_id)]["latency"]["average"])

                                                     if int(results["latency"][str(pg_id)]["err_cntrs"]["dup"]):
                                                          stats_error_append_pg_id(stats[device_pair['rx']], "latency_duplicate", pg_id)

                                                     if float(results["latency"][str(pg_id)]["latency"]["total_max"]) > stats[device_pair['rx']]['rx_latency_maximum']:
                                                          stats[device_pair['rx']]['rx_latency_maximum'] = float(results["latency"][str(pg_id)]["latency"]["total_max"])
                                           else:
                                                stats_error_append_pg_id(stats[device_pair['rx']], 'rx_missing', pg_id)

                                           if str(device_pair['tx']) in results["flow_stats"][str(pg_id)]["tx_pkts"] and str(device_pair['rx']) in results["flow_stats"][str(pg_id)]["rx_pkts"]:
                                                if not trial_params['use_device_stats']:
                                                     stats[device_pair['tx']]['tx_l1_bps'] += int(results["flow_stats"][str(pg_id)]["tx_pkts"][str(device_pair['tx'])]) * (frame_size + tmp_stats[device_pair['tx']]['packet_overhead_bytes'])
                                                     stats[device_pair['rx']]['rx_l1_bps'] += int(results["flow_stats"][str(pg_id)]["rx_pkts"][str(device_pair['rx'])]) * (frame_size + tmp_stats[device_pair['tx']]['packet_overhead_bytes'])

                                                     stats[device_pair['tx']]['tx_l2_bps'] += int(results["flow_stats"][str(pg_id)]["tx_pkts"][str(device_pair['tx'])]) * (frame_size - tmp_stats[device_pair['tx']]['crc_bytes'])
                                                     stats[device_pair['rx']]['rx_l2_bps'] += int(results["flow_stats"][str(pg_id)]["rx_pkts"][str(device_pair['rx'])]) * (frame_size - tmp_stats[device_pair['tx']]['crc_bytes'])

                                                if stream_type == "latency":
                                                     stats[device_pair['tx']]['tx_latency_l1_bps'] += int(results["flow_stats"][str(pg_id)]["tx_pkts"][str(device_pair['tx'])]) * (frame_size + tmp_stats[device_pair['tx']]['packet_overhead_bytes'])
                                                     stats[device_pair['rx']]['rx_latency_l1_bps'] += int(results["flow_stats"][str(pg_id)]["rx_pkts"][str(device_pair['rx'])]) * (frame_size + tmp_stats[device_pair['tx']]['packet_overhead_bytes'])

                                                     stats[device_pair['tx']]['tx_latency_l2_bps'] += int(results["flow_stats"][str(pg_id)]["tx_pkts"][str(device_pair['tx'])]) * (frame_size - tmp_stats[device_pair['tx']]['crc_bytes'])
                                                     stats[device_pair['rx']]['rx_latency_l2_bps'] += int(results["flow_stats"][str(pg_id)]["rx_pkts"][str(device_pair['rx'])]) * (frame_size - tmp_stats[device_pair['tx']]['crc_bytes'])

                                           if results["flow_stats"][str(pg_id)]["loss"]["pct"][device_pair['path']] != "N/A":
                                                if float(results["flow_stats"][str(pg_id)]["loss"]["pct"][device_pair['path']]) < 0:
                                                     stats_error_append_pg_id(stats[device_pair['rx']], 'rx_negative_loss', pg_id)
                                                elif float(results["flow_stats"][str(pg_id)]["loss"]["pct"][device_pair['path']]) > trial_params["max_loss_pct"]:
                                                     stats_error_append_pg_id(stats[device_pair['rx']], 'rx_loss', pg_id)

                            if not trial_params['use_device_stats'] and 'bits_per_byte' in tmp_stats[device_pair['tx']]:
                                 stats[device_pair['tx']]['tx_active'] = True
                                 stats[device_pair['rx']]['rx_active'] = True

                                 stats[device_pair['rx']]['rx_lost_packets'] = stats[device_pair['tx']]['tx_packets'] - stats[device_pair['rx']]['rx_packets']
                                 if stats[device_pair['tx']]['tx_packets']:
                                      stats[device_pair['rx']]['rx_lost_packets_pct'] = 100.0 * stats[device_pair['rx']]['rx_lost_packets'] / stats[device_pair['tx']]['tx_packets']

                                 stats[device_pair['tx']]['tx_pps'] = float(stats[device_pair['tx']]['tx_packets']) / float(results['global']['runtime'])
                                 stats[device_pair['rx']]['rx_pps'] = float(stats[device_pair['rx']]['rx_packets']) / float(results['global']['runtime'])

                                 stats[device_pair['rx']]['rx_lost_pps'] = float(stats[device_pair['rx']]['rx_lost_packets']) / float(results['global']['runtime'])

                                 stats[device_pair['tx']]['tx_l1_bps'] = float(stats[device_pair['tx']]['tx_l1_bps']) / float(results['global']['runtime']) * tmp_stats[device_pair['tx']]['bits_per_byte']
                                 stats[device_pair['rx']]['rx_l1_bps'] = float(stats[device_pair['rx']]['rx_l1_bps']) / float(results['global']['runtime']) * tmp_stats[device_pair['tx']]['bits_per_byte']

                                 stats[device_pair['tx']]['tx_l2_bps'] = float(stats[device_pair['tx']]['tx_l2_bps']) / float(results['global']['runtime']) * tmp_stats[device_pair['tx']]['bits_per_byte']
                                 stats[device_pair['rx']]['rx_l2_bps'] = float(stats[device_pair['rx']]['rx_l2_bps']) / float(results['global']['runtime']) * tmp_stats[device_pair['tx']]['bits_per_byte']

                                 print("Device Pair: %s |   All TX   | packets=%s rate=%s l1_bps=%s l2_bps=%s" % (device_pair['path'], commify(stats[device_pair['tx']]['tx_packets']), commify(stats[device_pair['tx']]['tx_pps']), commify(stats[device_pair['tx']]['tx_l1_bps']), commify(stats[device_pair['tx']]['tx_l2_bps'])))
                                 print("Device Pair: %s |   All RX   | packets=%s rate=%s l1_bps=%s l2_bps=%s" % (device_pair['path'], commify(stats[device_pair['rx']]['rx_packets']), commify(stats[device_pair['rx']]['rx_pps']), commify(stats[device_pair['rx']]['rx_l1_bps']), commify(stats[device_pair['rx']]['rx_l2_bps'])))

                            if trial_params['measure_latency'] and 'bits_per_byte' in tmp_stats[device_pair['tx']]:
                                 stats[device_pair['tx']]['tx_active'] = True
                                 stats[device_pair['rx']]['rx_active'] = True

                                 stats[device_pair['rx']]['rx_latency_lost_packets'] = stats[device_pair['tx']]['tx_latency_packets'] - stats[device_pair['rx']]['rx_latency_packets']
                                 stats[device_pair['rx']]['rx_latency_lost_packets_pct'] = 100.0 * stats[device_pair['rx']]['rx_latency_lost_packets'] / stats[device_pair['tx']]['tx_latency_packets']

                                 stats[device_pair['tx']]['tx_latency_pps'] = float(stats[device_pair['tx']]['tx_latency_packets']) / float(results['global']['runtime'])
                                 stats[device_pair['rx']]['rx_latency_pps'] = float(stats[device_pair['rx']]['rx_latency_packets']) / float(results['global']['runtime'])

                                 stats[device_pair['rx']]['rx_latency_lost_pps'] = float(stats[device_pair['rx']]['rx_latency_lost_packets']) / float(results['global']['runtime'])

                                 stats[device_pair['tx']]['tx_latency_l1_bps'] = float(stats[device_pair['tx']]['tx_latency_l1_bps']) / float(results['global']['runtime']) * tmp_stats[device_pair['tx']]['bits_per_byte']
                                 stats[device_pair['rx']]['rx_latency_l1_bps'] = float(stats[device_pair['rx']]['rx_latency_l1_bps']) / float(results['global']['runtime']) * tmp_stats[device_pair['tx']]['bits_per_byte']

                                 stats[device_pair['tx']]['tx_latency_l2_bps'] = float(stats[device_pair['tx']]['tx_latency_l2_bps']) / float(results['global']['runtime']) * tmp_stats[device_pair['tx']]['bits_per_byte']
                                 stats[device_pair['rx']]['rx_latency_l2_bps'] = float(stats[device_pair['rx']]['rx_latency_l2_bps']) / float(results['global']['runtime']) * tmp_stats[device_pair['tx']]['bits_per_byte']

                                 if float(stats[device_pair['rx']]['rx_latency_packets']):
                                      stats[device_pair['rx']]['rx_latency_average'] = stats[device_pair['rx']]['rx_latency_average'] / float(stats[device_pair['rx']]['rx_latency_packets'])
                                 else:
                                      # ERROR?
                                      stats[device_pair['rx']]['rx_latency_average'] = -1.0

                                 print("Device Pair: %s | Latency TX | packets=%s rate=%s l1_bps=%s l2_bps=%s" % (device_pair['path'], commify(stats[device_pair['tx']]['tx_latency_packets']), commify(stats[device_pair['tx']]['tx_latency_pps']), commify(stats[device_pair['tx']]['tx_latency_l1_bps']), commify(stats[device_pair['tx']]['tx_latency_l2_bps'])))
                                 print("Device Pair: %s | Latency RX | packets=%s rate=%s l1_bps=%s l2_bps=%s average=%s maximum=%s" % (device_pair['path'], commify(stats[device_pair['rx']]['rx_latency_packets']), commify(stats[device_pair['rx']]['rx_latency_pps']), commify(stats[device_pair['rx']]['rx_latency_l1_bps']), commify(stats[device_pair['rx']]['rx_latency_l2_bps']), commify(stats[device_pair['rx']]['rx_latency_average']), commify(stats[device_pair['rx']]['rx_latency_maximum'])))

                       for direction in stats['directional']:
                            if stats['directional'][direction]['active']:
                                 stats['directional'][direction]['rx_lost_packets'] = stats['directional'][direction]['tx_packets'] - stats['directional'][direction]['rx_packets']
                                 if stats['directional'][direction]['tx_packets']:
                                      stats['directional'][direction]['rx_lost_packets_pct'] = 100.0 * stats['directional'][direction]['rx_lost_packets'] / stats['directional'][direction]['tx_packets']

                       continue

             print(line.rstrip('\n'), file=primary_output_file)

    if primary_close_file:
         primary_output_file.close()

    if secondary_close_file:
         secondary_output_file.close()

def print_stats(trial_params, stats):
     if t_global.args.traffic_generator == 'moongen-txrx' or t_global.args.traffic_generator == 'null-txrx':
          print('[')
          print(json.dumps(stats[0], indent = 4, separators=(',', ': '), sort_keys = True))
          print(',')
          print(json.dumps(stats[1], indent = 4, separators=(',', ': '), sort_keys = True))
          print(']')
     elif t_global.args.traffic_generator == 'trex-txrx' or t_global.args.traffic_generator == 'trex-txrx-profile':
          print('[')
          port = 0
          while port <= trial_params['max_port']:
               if port in stats:
                    print(json.dumps(stats[port], indent = 4, separators=(',', ': '), sort_keys = True))
               else:
                    print(json.dumps(trial_params['null_stats'], indent = 4, separators=(',', ': '), sort_keys = True))
               if port < trial_params['max_port']:
                    print(',')
               port += 1
          print(']')

def setup_config_var(variable, value, trial_params, config_tag = True, silent = False):
     trial_params[variable] = value

     if config_tag:
          print("CONFIG | %s=%s" % (variable, value))
     else:
          if not silent:
               print("%s=%s" % (variable, value))

def main():
    process_options()
    final_validation = t_global.args.one_shot == 1
    rate = t_global.args.rate

    trial_results = { 'trials': [] }

    if t_global.args.traffic_generator == 'null-txrx':
         random.seed()

    if t_global.args.traffic_generator == 'moongen-txrx' and t_global.args.rate_unit == "%":
         print("The moongen-txrx traffic generator does not support --rate-unit=%")
         quit(1)

    if t_global.args.traffic_generator == 'null-txrx' and t_global.args.rate_unit == "mpps":
         print("The null-txrx traffic generator does not support --rate-unit=mpps")
         quit(1)

    if t_global.args.traffic_generator == 'trex-txrx-profile' and t_global.args.rate_unit == "mpps":
         print("The trex-txrx-profile traffic generator does not support --rate-unit=mpps")
         quit(1)

    if t_global.args.traffic_generator == 'null-txrx' and t_global.args.measure_latency:
         print("The null-txrx traffic generator does not support latency measurements")
         quit(1)

    if t_global.args.frame_size == "imix":
         if t_global.args.traffic_generator == 'moongen-txrx':
              print("The moongen-txrx traffic generator does not support --frame-size=imix")
              quit(1)
         if t_global.args.rate_unit == "mpps":
              print("When --frame-size=imix then --rate-unit must be set to %")
              quit(1)
    else:
         t_global.args.frame_size = int(t_global.args.frame_size)

    # the packet rate in millions/sec is based on 10Gbps, update for other Ethernet speeds
    if rate == 0:
        if t_global.args.traffic_generator == "null-txrx" or t_global.args.traffic_generator == "trex-txrx-profile" or (t_global.args.traffic_generator == "trex-txrx" and t_global.args.rate_unit == "%"):
             rate = 100.0
        else:
             rate = 9999 / ((t_global.args.frame_size) * 8 + 64 + 96.0)
    initial_rate = rate
    prev_rate = 0
    prev_pass_rate = [0]
    prev_fail_rate = rate

    trial_params = {} 

    # option handling
    setup_config_var("output_dir", t_global.args.output_dir, trial_params, config_tag = False)
    setup_config_var("traffic_generator", t_global.args.traffic_generator, trial_params)
    setup_config_var("rate", rate, trial_params)
    setup_config_var("runtime_tolerance", t_global.args.runtime_tolerance, trial_params)
    setup_config_var("rate_tolerance_failure", t_global.args.rate_tolerance_failure, trial_params)
    setup_config_var("rate_tolerance", t_global.args.rate_tolerance, trial_params)
    setup_config_var("one_shot", t_global.args.one_shot, trial_params)
    setup_config_var("min_rate", t_global.args.min_rate, trial_params)
    setup_config_var("max_loss_pct", t_global.args.max_loss_pct, trial_params)
    setup_config_var("trial_gap", t_global.args.trial_gap, trial_params)
    setup_config_var("search_runtime", t_global.args.search_runtime, trial_params)
    setup_config_var("validation_runtime", t_global.args.validation_runtime, trial_params)
    setup_config_var("sniff_runtime", t_global.args.sniff_runtime, trial_params)
    setup_config_var("search_granularity", t_global.args.search_granularity, trial_params)
    setup_config_var("max_retries", t_global.args.max_retries, trial_params)
    setup_config_var("loss_granularity", t_global.args.loss_granularity, trial_params)
    setup_config_var("pre_trial_cmd", t_global.args.pre_trial_cmd, trial_params)

    if t_global.args.traffic_generator == "moongen-txrx" or t_global.args.traffic_generator == "trex-txrx" or t_global.args.traffic_generator == "trex-txrx-profile":
         # empty for now
         foo = None

    if t_global.args.traffic_generator == "trex-txrx" or t_global.args.traffic_generator == "moongen-txrx":
         setup_config_var("traffic_direction", t_global.args.traffic_direction, trial_params)
         setup_config_var("num_flows", t_global.args.num_flows, trial_params)
         setup_config_var("frame_size", t_global.args.frame_size, trial_params)
         setup_config_var("use_src_mac_flows", t_global.args.use_src_mac_flows, trial_params)
         setup_config_var("use_dst_mac_flows", t_global.args.use_dst_mac_flows, trial_params)
         setup_config_var("use_src_ip_flows", t_global.args.use_src_ip_flows, trial_params)
         setup_config_var("use_dst_ip_flows", t_global.args.use_dst_ip_flows, trial_params)
         setup_config_var("src_macs", t_global.args.src_macs, trial_params)
         setup_config_var("dst_macs", t_global.args.dst_macs, trial_params)
         setup_config_var("src_ips", t_global.args.src_ips, trial_params)
         setup_config_var("dst_ips", t_global.args.dst_ips, trial_params)
         setup_config_var("vlan_ids", t_global.args.vlan_ids, trial_params)

    if t_global.args.traffic_generator == "trex-txrx" or t_global.args.traffic_generator == "trex-txrx-profile":
         setup_config_var("device_pairs", t_global.args.device_pairs, trial_params)
         setup_config_var('active_device_pairs', t_global.args.active_device_pairs, trial_params)
         setup_config_var("rate_unit", t_global.args.rate_unit, trial_params)
         setup_config_var("measure_latency", t_global.args.measure_latency, trial_params)
         setup_config_var("latency_rate", t_global.args.latency_rate, trial_params)
         setup_config_var('enable_flow_cache', t_global.args.enable_flow_cache, trial_params)
         setup_config_var('send_teaching_warmup', t_global.args.send_teaching_warmup, trial_params)
         setup_config_var('send_teaching_measurement', t_global.args.send_teaching_measurement, trial_params)
         setup_config_var('teaching_measurement_interval', t_global.args.teaching_measurement_interval, trial_params)
         setup_config_var('teaching_warmup_packet_rate', t_global.args.teaching_warmup_packet_rate, trial_params)
         setup_config_var('teaching_measurement_packet_rate', t_global.args.teaching_measurement_packet_rate, trial_params)
         setup_config_var("use_device_stats", t_global.args.use_device_stats, trial_params)

    if t_global.args.traffic_generator == "moongen-txrx":
         setup_config_var("encap_src_macs", t_global.args.encap_src_macs, trial_params)
         setup_config_var("encap_dest_macs", t_global.args.encap_dst_macs, trial_params)
         setup_config_var("encap_src_ips", t_global.args.encap_src_ips, trial_params)
         setup_config_var("encap_dest_ips", t_global.args.encap_dst_ips, trial_params)
         setup_config_var("vxlan_ids", t_global.args.vxlan_ids, trial_params)
         setup_config_var("use_encap_src_mac_flows", t_global.args.use_encap_src_mac_flows)
         setup_config_var("use_encap_dst_mac_flows", t_global.args.use_encap_dst_mac_flows)
         setup_config_var("use_encap_src_ip_flows", t_global.args.use_encap_src_ip_flows)
         setup_config_var("use_encap_dst_ip_flows", t_global.args.use_encap_dst_ip_flows)

    if t_global.args.traffic_generator == "null-txrx":
         # empty for now
         foo = None

    if t_global.args.traffic_generator == "trex-txrx":
         setup_config_var("use_src_port_flows", t_global.args.use_src_port_flows, trial_params)
         setup_config_var("use_dst_port_flows", t_global.args.use_dst_port_flows, trial_params)
         setup_config_var("src_ports", t_global.args.src_ports, trial_params)
         setup_config_var("dst_ports", t_global.args.dst_ports, trial_params)
         setup_config_var("use_protocol_flows", t_global.args.use_protocol_flows, trial_params)
         setup_config_var("packet_protocol", t_global.args.packet_protocol, trial_params)
         setup_config_var("stream_mode", t_global.args.stream_mode, trial_params)
         setup_config_var("enable_segment_monitor", t_global.args.enable_segment_monitor, trial_params)
         setup_config_var('teaching_warmup_packet_type', t_global.args.teaching_warmup_packet_type, trial_params)
         setup_config_var('teaching_measurement_packet_type', t_global.args.teaching_measurement_packet_type, trial_params)

    if t_global.args.traffic_generator == "trex-txrx-profile":
         setup_config_var('random_seed', t_global.args.random_seed, trial_params)
         setup_config_var('traffic_profile', t_global.args.traffic_profile, trial_params)
         setup_config_var("enable_trex_profiler", t_global.args.enable_trex_profiler, trial_params)
         setup_config_var("trex_profiler_interval", t_global.args.trex_profiler_interval, trial_params)

         setup_config_var('traffic_direction', 'bidirectional', trial_params, config_tag = False, silent = True)

    if t_global.args.traffic_generator == 'trex-txrx-profile':
         trial_params['traffic_profile'] = t_global.args.traffic_profile
         trial_params['loaded_traffic_profile'] = load_traffic_profile(traffic_profile = trial_params['traffic_profile'],
                                                                       rate_modifier = 100.0)
         if trial_params['loaded_traffic_profile'] == 1:
              quit(1)

         print("Loaded traffic profile from %s:" % (trial_params['traffic_profile']))
         print(dump_json_readable(trial_params['loaded_traffic_profile']))

    if t_global.args.traffic_generator == "trex-txrx" or t_global.args.traffic_generator == 'trex-txrx-profile':
         trial_params['null_stats'] = { 'rx_l1_bps':                   0.0,
                                        'rx_l2_bps':                   0.0,
                                        'rx_packets':                  0,
                                        'rx_lost_packets':             0,
                                        'rx_lost_packets_pct':         0.0,
                                        'rx_pps':                      0.0,
                                        'rx_lost_pps':                 0.0,
                                        'rx_latency_average':          0.0,
                                        'rx_latency_packets':          0,
                                        'rx_latency_lost_packets':     0,
                                        'rx_latency_lost_packets_pct': 0.0,
                                        'rx_latency_maximum':          0.0,
                                        'rx_latency_l1_bps':           0.0,
                                        'rx_latency_l2_bps':           0.0,
                                        'rx_latency_pps':              0.0,
                                        'rx_latency_lost_pps':         0.0,
                                        'rx_active':                   False,
                                        'tx_l1_bps':                   0.0,
                                        'tx_l2_bps':                   0.0,
                                        'tx_packets':                  0,
                                        'tx_pps':                      0.0,
                                        'tx_pps_target':               0.0,
                                        'tx_latency_packets':          0,
                                        'tx_latency_l1_bps':           0.0,
                                        'tx_latency_l2_bps':           0.0,
                                        'tx_latency_pps':              0.0,
                                        'tx_active':                   False }

    trial_params['claimed_dev_pairs'] = []
    for device_pair in trial_params['device_pairs'].split(','):
         ports = device_pair.split(':')
         claimed_dev_pair_obj = { 'tx': None,
                                  'rx': None,
                                  'dev_pair': device_pair }
         if trial_params['traffic_direction'] == 'revunidirectional':
              claimed_dev_pair_obj['tx'] = int(ports[1])
              claimed_dev_pair_obj['rx'] = int(ports[0])
              trial_params['claimed_dev_pairs'].append(claimed_dev_pair_obj)
         else:
              claimed_dev_pair_obj['tx'] = int(ports[0])
              claimed_dev_pair_obj['rx'] = int(ports[1])
              trial_params['claimed_dev_pairs'].append(claimed_dev_pair_obj)

              if trial_params['traffic_direction'] == 'bidirectional':
                   claimed_dev_pair_obj = copy.deepcopy(claimed_dev_pair_obj)
                   claimed_dev_pair_obj['tx'] = int(ports[1])
                   claimed_dev_pair_obj['rx'] = int(ports[0])
                   trial_params['claimed_dev_pairs'].append(claimed_dev_pair_obj)

          

    trial_params['test_dev_pairs'] = []
    for device_pair in trial_params['active_device_pairs'].split(','):
         ports = device_pair.split(':')
         test_dev_pair_obj = { 'tx': None,
                               'rx': None,
                               'path': None,
                               'direction': None,
                               'dev_pair': device_pair }
         if trial_params['traffic_direction'] == 'revunidirectional':
              test_dev_pair_obj['tx'] = int(ports[1])
              test_dev_pair_obj['rx'] = int(ports[0])
              test_dev_pair_obj['direction'] = "<-"

              if t_global.args.traffic_generator == 'trex-txrx-profile':
                   test_dev_pair_obj['path'] = "%d<-%d" % (test_dev_pair_obj['rx'], test_dev_pair_obj['tx'])
              else:
                   test_dev_pair_obj['path'] = "%d->%d" % (test_dev_pair_obj['tx'], test_dev_pair_obj['rx'])

              trial_params['test_dev_pairs'].append(test_dev_pair_obj)
         else:
              test_dev_pair_obj['tx'] = int(ports[0])
              test_dev_pair_obj['rx'] = int(ports[1])
              test_dev_pair_obj['path'] = "%d->%d" % (test_dev_pair_obj['tx'], test_dev_pair_obj['rx'])
              test_dev_pair_obj['direction'] = "->"
              trial_params['test_dev_pairs'].append(test_dev_pair_obj)

              if trial_params['traffic_direction'] == 'bidirectional':
                   test_dev_pair_obj = copy.deepcopy(test_dev_pair_obj)
                   test_dev_pair_obj['tx'] = int(ports[1])
                   test_dev_pair_obj['rx'] = int(ports[0])
                   test_dev_pair_obj['direction'] = "<-"

                   if t_global.args.traffic_generator == 'trex-txrx-profile':
                        test_dev_pair_obj['path'] = "%d<-%d" % (test_dev_pair_obj['rx'], test_dev_pair_obj['tx'])
                   else:
                        test_dev_pair_obj['path'] = "%d->%d" % (test_dev_pair_obj['tx'], test_dev_pair_obj['rx'])

                   trial_params['test_dev_pairs'].append(test_dev_pair_obj)

    port_speed_verification_fail = False

    port_info = None
    if t_global.args.traffic_generator == "trex-txrx" or t_global.args.traffic_generator == 'trex-txrx-profile':
         port_info = get_trex_port_info(trial_params, trial_params['claimed_dev_pairs'])
         trial_results['port_info'] = port_info

         for port in port_info:
              if port['speed'] == 0:
                   port_speed_verification_fail = True
                   print(error("Port with HW MAC %s failed speed verification test" % (port['hw_mac'])))
              else:
                   if port['driver'] == "net_ixgbe" and not trial_params['use_device_stats']:
                        print("WARNING: Forcing use of device stats instead of stream stats due to issue with Intel 82599/Niantic flow programming")
                        trial_params['use_device_stats'] = True

    if port_speed_verification_fail:
         quit(1)

    if len(trial_params['pre_trial_cmd']):
         if not os.path.isfile(trial_params['pre_trial_cmd']):
              print(error("The pre-trial-cmd file does not exist [%s]" % (trial_params['pre_trial_cmd'])))
              quit(1)

         if not os.access(trial_params['pre_trial_cmd'], os.X_OK):
              print(error("The pre-trial-cmd file is not executable [%s]" % (trial_params['pre_trial_cmd'])))
              quit(1)

    perform_sniffs = False
    do_sniff = False
    do_search = True
    if t_global.args.sniff_runtime:
         perform_sniffs = True
         do_sniff = True
         do_search = False

    trial_params['trial'] = 0

    minimum_rate = initial_rate * trial_params['search_granularity'] / 100
    if trial_params['min_rate'] != 0:
         minimum_rate = trial_params['min_rate']

    try:
         retries = 0
         # the actual binary search to find the maximum packet rate
         while final_validation or do_sniff or do_search:
              # support a longer measurement for the last trial, AKA "final validation"
              if final_validation:
                   trial_params['runtime'] = t_global.args.validation_runtime
                   trial_params['trial_mode'] = 'validation'
                   print('\nTrial Mode: Final Validation')
              elif do_search:
                   trial_params['runtime'] = t_global.args.search_runtime
                   trial_params['trial_mode'] = 'search'
                   print('\nTrial Mode: Search')
              else:
                   trial_params['runtime'] = t_global.args.sniff_runtime
                   trial_params['trial_mode'] = 'sniff'
                   print('\nTrial Mode: Sniff')

              trial_params['rate'] = rate
              # run the actual trial
              trial_params['trial'] += 1
              stream_info = { 'streams': None }
              detailed_stats = { 'stats': None }

              print('running trial %03d, rate %s%s' % (trial_params['trial'], commify(trial_params['rate']), trial_params['rate_unit']))

              if len(trial_params['pre_trial_cmd']):
                   execute_pre_trial_cmd(trial_params)

              trial_stats = run_trial(trial_params, port_info, stream_info, detailed_stats)

              trial_result = 'pass'
              test_abort = False
              total_tx_packets = 0
              total_rx_packets = 0
              for dev_pair in trial_params['test_dev_pairs']:
                   pair_abort = False
                   if trial_stats[dev_pair['tx']]['tx_active'] and trial_stats[dev_pair['tx']]['tx_packets'] == 0:
                        pair_abort = True
                        print("binary search failed because no packets were transmitted between device pair: %d -> %d" % (dev_pair['tx'], dev_pair['rx']))

                   if trial_stats[dev_pair['rx']]['rx_active'] and trial_stats[dev_pair['rx']]['rx_packets'] == 0:
                        pair_abort = True
                        print("binary search failed because no packets were received between device pair: %d -> %d" % (dev_pair['tx'], dev_pair['rx']))

                   if 'rx_invalid_error' in trial_stats[dev_pair['tx']]:
                        pair_abort = True
                        print("binary search failed because packets were received on an incorrect port between device pair: %d -> %d (pg_ids: %s)" % (dev_pair['tx'], dev_pair['rx'], trial_stats[dev_pair['tx']]['rx_invalid_error']))

                   if 'tx_invalid_error' in trial_stats[dev_pair['rx']]:
                        pair_abort = True
                        print("binary search failed because packets were transmitted on an incorrect port between device pair: %d -> %d (pg_ids: %s)" % (dev_pair['tx'], dev_pair['rx'], trial_stats[dev_pair['rx']]['tx_invalid_error']))

                   if pair_abort:
                        test_abort = True
                        continue

                   if 'latency_duplicate_error' in trial_stats[dev_pair['rx']]:
                        test_abort = True
                        print("(trial failed requirement, duplicate latency packets detected, device pair: %d -> %d, pg_ids: %s)" % (dev_pair['tx'], dev_pair['rx'], trial_stats[dev_pair['tx']]['latency_duplicate_error']) )

                   if 'tx_missing_error' in trial_stats[dev_pair['tx']]:
                        trial_result = 'fail'
                        print("(trial failed requirement, missing TX results, device pair: %d -> %d, pg_ids: %s)" % (dev_pair['tx'], dev_pair['rx'], trial_stats[dev_pair['tx']]['tx_missing_error']))

                   if 'rx_missing_error' in trial_stats[dev_pair['rx']]:
                        trial_result = 'fail'
                        print("(trial failed requirement, missing RX results, device pair: %d -> %d, pg_ids: %s)" % (dev_pair['tx'], dev_pair['rx'], trial_stats[dev_pair['rx']]['rx_missing_error']))

                   if trial_params['loss_granularity'] == 'segment' and 'rx_loss_error' in trial_stats[dev_pair['rx']]:
                        trial_result = 'fail'
                        print("(trial failed requirement, individual stream RX packet loss, device pair: %d -> %d, pg_ids: %s)" % (dev_pair['tx'], dev_pair['rx'], trial_stats[dev_pair['rx']]['rx_loss_error']))

                   if 'rx_negative_loss_error' in trial_stats[dev_pair['rx']]:
                        trial_result = 'fail'
                        print("(trial failed requirement, negative individual stream RX packet loss, device pair: %d -> %d, pg_ids: %s)" % (dev_pair['tx'], dev_pair['rx'], trial_stats[dev_pair['rx']]['rx_negative_loss_error']))

                   if trial_params['loss_granularity'] == 'device' and trial_stats[dev_pair['rx']]['rx_active']:
                        requirement_msg = "passed"
                        if trial_stats[dev_pair['rx']]['rx_lost_packets_pct'] > t_global.args.max_loss_pct:
                             requirement_msg = "failed"
                             trial_result = 'fail'
                        print("(trial %s requirement, percent loss, device pair: %d -> %d, requested: %s%%, achieved: %s%%, lost packets: %s)" % (requirement_msg, dev_pair['tx'], dev_pair['rx'], commify(t_global.args.max_loss_pct), commify(trial_stats[dev_pair['rx']]['rx_lost_packets_pct']), commify(trial_stats[dev_pair['rx']]['rx_lost_packets'])))
     
                        if t_global.args.measure_latency:
                             requirement_msg = "passed"
                             if trial_stats[dev_pair['rx']]['rx_latency_lost_packets_pct'] > t_global.args.max_loss_pct:
                                  requirement_msg = "failed"
                                  trial_result = 'fail'
                             print("(trial %s requirement, latency percent loss, device pair: %d -> %d, requested: %s%%, achieved: %s%%, lost packets: %s)" % (requirement_msg, dev_pair['tx'], dev_pair['rx'], commify(t_global.args.max_loss_pct), commify(trial_stats[dev_pair['rx']]['rx_latency_lost_packets_pct']), commify(trial_stats[dev_pair['rx']]['rx_latency_lost_packets'])))


                   if t_global.args.traffic_generator != 'null-txrx' and trial_stats[dev_pair['tx']]['tx_active']:
                        requirement_msg = "passed"
                        tx_rate = trial_stats[dev_pair['tx']]['tx_pps'] / 1000000.0
                        tolerance_min = 0.0
                        tolerance_max = 0.0
                        if t_global.args.traffic_generator == 'trex-txrx' or t_global.args.traffic_generator == 'trex-txrx-profile':
                             tolerance_min = (trial_stats[dev_pair['tx']]['tx_pps_target'] / 1000000) * ((100.0 - trial_params['rate_tolerance']) / 100)
                             tolerance_max = (trial_stats[dev_pair['tx']]['tx_pps_target'] / 1000000) * ((100.0 + trial_params['rate_tolerance']) / 100)
                             if tx_rate > tolerance_max or tx_rate < tolerance_min:
                                  requirement_msg = "retry"
                                  if trial_result == "pass":
                                       trial_result = "retry-to-%s" % trial_params['rate_tolerance_failure']
                             tolerance_min *= 1000000
                             tolerance_max *= 1000000
                        elif t_global.args.traffic_generator == 'moongen-txrx':
                             tolerance_min = trial_params['rate'] * (100 - trial_params['rate_tolerance']) / 100
                             tolerance_max = trial_params['rate'] * (100 + trial_params['rate_tolerance']) / 100
                             if tx_rate > tolerance_max or tx_rate < tolerance_min:
                                  requirement_msg = "retry"
                                  if trial_result == "pass":
                                       trial_result = "retry-to-%s" % trial_params['rate_tolerance_failure']
                        trial_stats[dev_pair['tx']]['tx_tolerance_min'] = tolerance_min
                        trial_stats[dev_pair['tx']]['tx_tolerance_max'] = tolerance_max
                        print("(trial %s requirement, TX rate tolerance, device pair: %d -> %d, unit: mpps, tolerance: %s - %s, achieved: %s)" % (requirement_msg, dev_pair['tx'], dev_pair['rx'], commify(tolerance_min/1000000), commify(tolerance_max/1000000), commify(tx_rate)))

              if test_abort:
                   print(error('Binary search aborting due to critical error'))
                   quit(1)

              if trial_params['loss_granularity'] == 'direction':
                   for direction in trial_stats['directional']:
                        if trial_stats['directional'][direction]['active']:
                             requirement_msg = "passed"
                             if trial_stats['directional'][direction]['rx_lost_packets_pct'] > t_global.args.max_loss_pct:
                                  requirement_msg = "failed"
                                  trial_result = 'fail'
                             print("(trial %s requirement, percent loss, direction: %s, requested: %s%%, achieved: %s%%, lost packets: %s)" % (requirement_msg, direction, commify(t_global.args.max_loss_pct), commify(trial_stats['directional'][direction]['rx_lost_packets_pct']), commify(trial_stats['directional'][direction]['rx_lost_packets'])))
                        

              if 'global' in trial_stats:
                   tolerance_min = float(trial_params['runtime']) * (1 - (float(trial_params['runtime_tolerance']) / 100))
                   tolerance_max = float(trial_params['runtime']) * (1 + (float(trial_params['runtime_tolerance']) / 100))
                   trial_stats['global']['runtime_tolerance_min'] = tolerance_min
                   trial_stats['global']['runtime_tolerance_max'] = tolerance_max

                   if trial_stats['global']['timeout']:
                        print("(trial timeout, forcing a retry, timeouts can cause inconclusive trial results)")
                        trial_result = "retry-to-fail"
                   else:
                        if trial_stats['global']['runtime'] < tolerance_min or trial_stats['global']['runtime'] > tolerance_max:
                             print("(trial failed requirement, runtime tolerance test, forcing retry, tolerance: %s - %s, achieved: %s)" % (commify(tolerance_min), commify(tolerance_max), commify(trial_stats['global']['runtime'])))
                             if trial_result == "pass":
                                  trial_result = "retry-to-fail"

                   if trial_stats['global']['early_exit']:
                        print("(trial failed due to early exit)")
                        trial_result = 'fail'

                   if trial_stats['global']['force_quit']:
                        print("Received Force Quit")
                        return(1)

              profiler_data = None
              if trial_params['traffic_generator'] == 'trex-txrx-profile' and trial_params['enable_trex_profiler']:
                   profiler_data = trex_profiler_postprocess_file("%s/%s" % (trial_params['output_dir'], trial_params['trial_profiler_file']))

              trial_results['trials'].append({ 'trial': trial_params['trial'],
                                               'rate': trial_params['rate'],
                                               'rate_unit': trial_params['rate_unit'],
                                               'result': trial_result,
                                               'logfile': trial_params['trial_primary_output_file'],
                                               'extra-logfile': trial_params['trial_secondary_output_file'],
                                               'profiler-logfile': trial_params['trial_profiler_file'],
                                               'profiler-data': profiler_data,
                                               'stats': trial_stats,
                                               'trial_params': copy.deepcopy(trial_params),
                                               'stream_info': copy.deepcopy(stream_info['streams']),
                                               'detailed_stats': copy.deepcopy(detailed_stats['stats']) })

              if trial_result == "pass":
                   print('(trial passed all requirements)')
              elif trial_result == "retry-to-fail" or trial_result == "retry-to-quit":
                   print('(trial must be repeated because one or more requirements did not pass, but allow a retry)')

                   if retries >= trial_params['max_retries']:
                        if trial_result == "retry-to-quit":
                             print('---> The retry limit for a trial has been reached.  This is probably due to a rate tolerance failure.  <---')
                             print('---> You must adjust the --rate-tolerance to a higher value, or use --rate to start with a lower rate. <---')
                             quit(1)
                        elif trial_result == "retry-to-fail":
                             print('---> The retry limit has been reached.  Failing and continuing. <---')
                             retries = 0
                             trial_result = "fail"
                   else:
                        # if trial_result is retry, then don't adjust anything and repeat
                        retries = retries + 1
              else:
                   print('(trial failed one or more requirements)')

              if t_global.args.one_shot == 1:
                   break
              if trial_result == "fail":
                   if final_validation:
                        final_validation = False
                        next_rate = rate - (trial_params['search_granularity'] * rate / 100) # subtracting by at least search_granularity percent avoids very small reductions in rate
                   else:
                        if len(prev_pass_rate) > 1 and rate < prev_pass_rate[len(prev_pass_rate)-1]:
                             # if the attempted rate drops below the most recent passing rate then that
                             # passing rate is considered a false positive and should be removed; ensure
                             # that at least the original passing rate (which is a special rate of 0) is never
                             # removed from the stack
                             print("Removing false positive passing result: %s" % (commify(prev_pass_rate.pop())))
                        next_rate = (prev_pass_rate[len(prev_pass_rate)-1] + rate) / 2 # use the most recently added passing rate present in stack to calculate the next rate
                        if abs(rate - next_rate) < (trial_params['search_granularity'] * rate / 100):
                             next_rate = rate - (trial_params['search_granularity'] * rate / 100) # subtracting by at least search_granularity percent avoids very small reductions in rate
                   if perform_sniffs:
                        do_sniff = True
                        do_search = False
                   else:
                        do_search = True
                        do_sniff = False
                   prev_fail_rate = rate
                   prev_rate = rate
                   rate = next_rate
                   retries = 0
              elif trial_result == "pass":
                   passed_stats = trial_stats
                   if final_validation: # no longer necessary to continue searching
                        if initial_rate == rate:
                             print("Detected requested rate is too low, doubling rate and restarting search")

                             final_validation = False

                             if perform_sniffs:
                                  do_sniff = True
                                  do_search = False
                             else:
                                  do_sniff = False
                                  do_search = True

                             rate = 2 * initial_rate
                             initial_rate = rate
                             prev_rate = 0
                             prev_pass_rate = [0]
                             prev_fail_rate = rate
                             retries = 0
                        else:
                             break
                   else:
                        if do_sniff:
                             do_sniff = False
                             do_search = True
                             next_rate = rate # since this was only the sniff test, keep the current rate
                        else:
                             prev_pass_rate.append(rate) # add the newly passed rate to the stack of passed rates; this will become the new reference for passed rates
                             next_rate = (prev_fail_rate + rate) / 2
                             if abs(rate - next_rate)/rate * 100 < trial_params['search_granularity']: # trigger final validation
                                  final_validation = True
                                  do_search = False
                             else:
                                  if perform_sniffs:
                                       do_sniff = True
                                       do_search = False
                        prev_rate = rate
                        rate = next_rate
                        retries = 0

              if rate < minimum_rate and prev_rate > minimum_rate:
                   print("Setting the rate to the minimum allowed by the search granularity as a last attempt at passing.")
                   prev_rate = rate
                   rate = minimum_rate
              elif (rate == minimum_rate or prev_rate <= minimum_rate) and trial_result == 'fail':
                   print("Binary search ended up at rate which is below minimum allowed")
                   print("There is no trial which passed")
                   failed_stats = []

                   if t_global.args.traffic_generator == 'moongen-txrx' or t_global.args.traffic_generator == 'null-txrx':
                        failed_stats.append(copy.deepcopy(trial_params['null_stats']))
                        failed_stats.append(copy.deepcopy(trial_params['null_stats']))
                   elif t_global.args.traffic_generator == 'trex-txrx' or t_global.args.traffic_generator == 'trex-txrx-profile':
                        port = 0
                        while port <= trial_params['max_port']:
                             failed_stats.append(copy.deepcopy(trial_params['null_stats']))
                             port += 1

                   print("RESULT:")
                   print_stats(trial_params, failed_stats)
                   return(0)

              if t_global.args.trial_gap:
                   print("Sleeping for %s seconds between trial attempts" % (commify(t_global.args.trial_gap)))
                   time.sleep(t_global.args.trial_gap)

         print("RESULT:")
         if prev_pass_rate[len(prev_pass_rate)-1] != 0: # show the stats for the most recent passing trial
              print_stats(trial_params, passed_stats)
         else:
              if t_global.args.one_shot == 1:
                   print_stats(trial_params, trial_stats)
              else:
                   print("There is no trial which passed")

    finally:
         # prune the profiler data from all trials except the last one
         # in an effort to save space.  if this data is required it
         # can be recreated from log files
         for x in range(0, len(trial_results['trials']) - 1):
              if trial_results['trials'][x]['profiler-data']:
                   trial_results['trials'][x]['profiler-data'] = None

         trial_json_filename = "%s/binary-search.json" % (trial_params['output_dir'])
         try:
              trial_json_file = open(trial_json_filename, 'w')
              print(json.dumps(trial_results, indent = 4, separators=(',', ': '), sort_keys = True), file=trial_json_file)
              trial_json_file.close()
         except IOError:
              print(error("Could not open %s for writing" % (trial_json_filename)))
              print("TRIALS:")
              print(json.dumps(trial_results, indent = 4, separators=(',', ': '), sort_keys = True))

if __name__ == "__main__":
    exit(main())

