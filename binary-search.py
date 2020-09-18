#!/bin/python -u

from __future__ import print_function

from trex_tg_lib import *
from tg_lib import *
import sys, getopt
import argparse
import subprocess
import re
import time
import json
import string
import threading
import select
import signal
import copy
import random
import os
import os.path
# from decimal import *

class t_global(object):
     args=None;
     bs_logger_queue = deque()
     trafficgen_dir = os.path.dirname(__file__)

def bs_logger_cleanup(notifier, thread):
     notifier.set()
     thread.join()
     return(0)

def bs_logger(msg, bso = True, prefix = ""):
     t_global.bs_logger_queue.append({ 'timestamp': time.time(),
                                       'message':   str(msg),
                                       'bso':       bso,
                                       'prefix':    prefix })
     return(0)

def bs_logger_worker(log, thread_exit):
     while not thread_exit.is_set() or len(t_global.bs_logger_queue):
          try:
               bs_log_entry = t_global.bs_logger_queue.popleft()

               bs_log_entry_time = format_timestamp(bs_log_entry['timestamp'])
               bs_log_entry_prefix = ""
               if bs_log_entry['bso']:
                    bs_log_entry_prefix = "[BSO]"
               if len(bs_log_entry['prefix']):
                    bs_log_entry_prefix = "[%s]" % (bs_log_entry['prefix'])
               for bs_log_entry_line in bs_log_entry['message'].split('\n'):
                    print("[%s]%s %s" % (bs_log_entry_time, bs_log_entry_prefix, bs_log_entry_line))

               bs_log_entry['timestamp'] = bs_log_entry['timestamp'] * 1000
               log.append(bs_log_entry)
          except IndexError:
               if not thread_exit.is_set():
                    time.sleep(1)

     return(0)

def sigint_handler(signal, frame):
     bs_logger('binary-search.py: CTRL+C detected and ignored')

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
                        help='trial period in seconds during final validation',
                        default=30,
                        type = int,
                        )
    parser.add_argument('--search-runtime', 
                        dest='search_runtime',
                        help='trial period in seconds during binary search',
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
    parser.add_argument('--duplicate-packet-failure',
                        dest='duplicate_packet_failure_mode',
                        help='What to do when a duplicate packet failure is encountered',
                        default = 'quit',
                        choices = [ 'fail', 'quit', 'retry-to-fail', 'retry-to-quit' ]
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
    parser.add_argument('--negative-packet-loss',
                        dest='negative_packet_loss_mode',
                        help='What to do when negative packet loss is encountered',
                        default = 'quit',
                        choices = [ 'fail', 'quit', 'retry-to-fail', 'retry-to-quit' ]
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
                        help='name of traffic generator: trex-txrx or trex-txrx-profile or Valkyrie2544 or null-txrx',
                        default = "trex-txrx",
                        choices = [ 'trex-txrx', 'trex-txrx-profile', 'valkyrie2544', 'null-txrx' ]
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
                        default = 1,
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
    parser.add_argument('--latency-device-pair',
                        dest='latency_device_pair',
                        help='Latency device pair in the form A:B',
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
    parser.add_argument('--process-all-profiler-data',
                        dest = 'process_all_profiler_data',
                        help = 'Force processing of profiler data for all trials instead of just the last one',
                        action = 'store_true',
                        )
    parser.add_argument('--repeat-final-validation',
                        dest = 'repeat_final_validation',
                        help = 'Repeat the final validation trial (if passed) to allow more invasive performance tools to be used',
                        action = 'store_true',
                        )
    parser.add_argument('--warmup-trial',
                        dest = 'warmup_trial',
                        help = 'Perform a warmup trial prior to performing the binary search.  The warmup trial results are ignored.',
                        action = 'store_true',
                        )
    parser.add_argument('--warmup-trial-runtime',
                        dest='warmup_trial_runtime',
                        help='trial period in seconds during warmup',
                        default=30,
                        type = int,
                        )
    parser.add_argument('--warmup-traffic-profile',
                        dest='warmup_traffic_profile',
                        help='Name of the file containing traffic profiles to load for the warmup trial',
                        default = '',
                        type = str
                        )
    parser.add_argument('--disable-upward-search',
                        dest = 'disable_upward_search',
                        help = 'Do not allow binary search to increase beyond the initial rate if it passes final validation',
                        action = 'store_true',
                        )
    parser.add_argument('--trex-host',
                        dest = 'trex_host',
                        help = 'Hostname/IP address of the server where TRex is running',
                        default = 'localhost',
                        type = str
                        )
    parser.add_argument('--no-promisc',
                        dest='no_promisc',
                        help='Do not use promiscuous mode for interfaces (usually needed for virtual functions)',
                        action = 'store_true',
                        )

    t_global.args = parser.parse_args();
    if t_global.args.frame_size == "IMIX":
         t_global.args.frame_size = "imix"
    if t_global.args.active_device_pairs == '--':
         t_global.args.active_device_pairs = t_global.args.device_pairs

def execute_pre_trial_cmd(trial_params):
     cmd = trial_params['pre_trial_cmd']

     previous_sig_handler = signal.signal(signal.SIGINT, sigint_handler)

     bs_logger("Executing pre-trial-cmd [%s]" % (cmd))

     the_process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
     exit_event = threading.Event()

     io_thread = threading.Thread(target = handle_pre_trial_cmd_io, args = (the_process, trial_params, exit_event))

     io_thread.start()

     exit_event.wait()

     retval = the_process.wait()

     io_thread.join()

     signal.signal(signal.SIGINT, previous_sig_handler)

     bs_logger('return code: %d' % (retval))
     return(retval)

def handle_pre_trial_cmd_io(process, trial_params, exit_event):
     output_file = None
     close_file = False
     trial_params['pre_trial_cmd_output_file'] = "binary-search.trial-%03d.pre-trial-cmd.txt" % (trial_params['trial'])
     filename = "%s/%s" % (trial_params['output_dir'], trial_params['pre_trial_cmd_output_file'])
     try:
          output_file = open(filename, 'w')
          close_file = True
     except IOError:
          bs_logger("Could not open %s for writing" % (filename))
          output_file = sys.stdout

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
                    if close_file:
                         print(line.rstrip('\n'), file=output_file)
                    else:
                         bs_logger('Pre Trial CMD: %s' % (line.rstrip('\n')))

     if close_file:
          output_file.close()

     return(0)

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

     cmd = 'python -u ' + t_global.trafficgen_dir + '/trex-query.py'
     cmd = cmd + ' --trex-host=' + str(trial_params['trex_host'])
     cmd = cmd + ' --mirrored-log'
     cmd = cmd + device_string

     previous_sig_handler = signal.signal(signal.SIGINT, sigint_handler)

     port_info = { 'json': None }

     bs_logger('querying TRex...')
     bs_logger('cmd: %s' % (cmd))
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

     bs_logger('return code: %d' % (retval))
     if retval:
          return { 'retval': retval }
     else:
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
          bs_logger(error("Could not open %s for writing" % (filename)))
          primary_output_file = sys.stdout

     secondary_output_file = None
     secondary_close_file = False
     trial_params['port_secondary_info_file'] = "binary-search.port-info.extra.txt"
     filename = "%s/%s" % (trial_params['output_dir'], trial_params['port_secondary_info_file'])
     try:
          secondary_output_file = open(filename, 'w')
          secondary_close_file = True
     except IOError:
          bs_logger(error("Could not open %s for writing" % (filename)))
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
                    bs_logger(line.rstrip('\n'), bso = False, prefix = "PQO")
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
               for stream_pps, stream_runtime in zip(streams[stream_type]['pps'], streams[stream_type]['runtime']):
                    rate_target += (stream_pps * stream_runtime)

          rate_target = rate_target / trial_params['runtime']
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

    stats['latency'] = dict()

    if trial_params['traffic_generator'] == 'null-txrx':
         stats[0] = dict()
         stats[0]['tx_packets'] = 0
         stats[0]['rx_packets'] = 0
         stats[1] = dict()
         stats[1]['tx_packets'] = 0
         stats[1]['rx_packets'] = 0
    elif trial_params['traffic_generator'] == 'trex-txrx' or trial_params['traffic_generator'] == 'trex-txrx-profile':
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

         for dev_pair in trial_params['test_dev_pairs']:
              for port in [ 'tx', 'rx' ]:
                   if not dev_pair[port] in stats:
                        stats[dev_pair[port]] = copy.deepcopy(trial_params['null_stats'])
                        tmp_stats[dev_pair[port]]= { 'tx_available_bandwidth': 0.0 }
                        streams[dev_pair[port]] = {}

    cmd = ""
    latency_cmd = ""

    trial_params['trial_profiler_file'] = "N/A"
    trial_params['trial_fwd_latency_histogram_file'] = "N/A"
    trial_params['trial_rev_latency_histogram_file'] = "N/A"
    trial_params['trial_latency_output_file'] = "N/A"
    trial_params['trial_latency_debug_file'] = "N/A"

    if 'latency_device_pair' in trial_params and trial_params['latency_device_pair'] != '--':
         latency_device_pair = trial_params['latency_device_pair'].split(':')

         trial_params['trial_fwd_latency_histogram_file'] = "binary-search.trial-%03d.latency.histogram.fwd.csv" % (trial_params['trial'])
         trial_params['trial_rev_latency_histogram_file'] = "binary-search.trial-%03d.latency.histogram.rev.csv" % (trial_params['trial'])

         latency_cmd = t_global.trafficgen_dir + '/MoonGen/build/MoonGen'
         latency_cmd = latency_cmd + ' ' + t_global.trafficgen_dir + '/moongen-latency.lua'
         latency_cmd = latency_cmd + ' --binarysearch 1'
         latency_cmd = latency_cmd + ' --time ' + str(trial_params['runtime'])
         latency_cmd = latency_cmd + ' --output ' + trial_params['output_dir']
         latency_cmd = latency_cmd + ' --fwdfile ' + trial_params['trial_fwd_latency_histogram_file']
         latency_cmd = latency_cmd + ' --revfile ' + trial_params['trial_rev_latency_histogram_file']
         latency_cmd = latency_cmd + ' --fwddev ' + latency_device_pair[0]
         latency_cmd = latency_cmd + ' --revdev ' + latency_device_pair[1]

         if trial_params['latency_traffic_direction'] == 'bidirectional':
              latency_cmd = latency_cmd + ' --traffic-direction bi'
         elif trial_params['latency_traffic_direction'] == 'unidirectional':
              latency_cmd = latency_cmd + ' --traffic-direction uni'
         elif trial_params['latency_traffic_direction'] == 'revunidirectional':
              latency_cmd = latency_cmd + ' --traffic-direction revuni'

    if trial_params['traffic_generator'] == 'null-txrx':
         cmd = 'python -u ' + t_global.trafficgen_dir + '/null-txrx.py'
         cmd = cmd + ' --mirrored-log'
         cmd = cmd + ' --rate=' + str(trial_params['rate'])
    elif trial_params['traffic_generator'] == 'trex-txrx-profile':
        for tmp_stats_index, tmp_stats_id in enumerate(tmp_stats):
             tmp_stats[tmp_stats_id]['tx_available_bandwidth'] = port_info[tmp_stats_id]['speed'] * 1000 * 1000 * 1000

        cmd = 'python -u ' + t_global.trafficgen_dir + '/trex-txrx-profile.py'
        if 'latency_device_pair' in trial_params and trial_params['latency_device_pair'] != '--':
             cmd = cmd + ' --binary-search-synchronize'
        cmd = cmd + ' --trex-host=' + str(trial_params['trex_host'])
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
        if trial_params['teaching_measurement_interval']:
             cmd = cmd + ' --teaching-measurement-interval=' + str(trial_params['teaching_measurement_interval'])
        if trial_params['teaching_warmup_packet_rate']:
             cmd = cmd + ' --teaching-warmup-packet-rate=' + str(trial_params['teaching_warmup_packet_rate'])
        if trial_params['teaching_measurement_packet_rate']:
             cmd = cmd + ' --teaching-measurement-packet-rate=' + str(trial_params['teaching_measurement_packet_rate'])
        if trial_params['trial_mode'] == 'warmup' and len(trial_params['warmup_traffic_profile']):
             cmd = cmd + ' --traffic-profile=' + trial_params['warmup_traffic_profile']
        else:
             cmd = cmd + ' --traffic-profile=' + trial_params['traffic_profile']
        if trial_params['no_promisc']:
             cmd = cmd + ' --no-promisc'

    elif trial_params['traffic_generator'] == 'trex-txrx':
        for tmp_stats_index, tmp_stats_id in enumerate(tmp_stats):
             tmp_stats[tmp_stats_id]['tx_available_bandwidth'] = port_info[tmp_stats_id]['speed'] * 1000 * 1000 * 1000

        cmd = 'python -u ' + t_global.trafficgen_dir + '/trex-txrx.py'
        if 'latency_device_pair' in trial_params and trial_params['latency_device_pair'] != '--':
             cmd = cmd + ' --binary-search-synchronize'
        cmd = cmd + ' --trex-host=' + str(trial_params['trex_host'])
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
        if trial_params['no_promisc']:
             cmd = cmd + ' --no-promisc'

    previous_sig_handler = signal.signal(signal.SIGINT, sigint_handler)

    bs_logger('cmd: %s' % (cmd))
    tg_process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    child_launch_sem = None
    child_go_sem = None

    if latency_cmd != '':
         bs_logger('latency cmd: %s' % (latency_cmd))
         latency_process = subprocess.Popen(latency_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

         child_launch_sem = posix_ipc.Semaphore("trafficgen_child_launch", flags = posix_ipc.O_CREX, initial_value = 0)
         child_go_sem = posix_ipc.Semaphore("trafficgen_child_go", flags = posix_ipc.O_CREX, initial_value = 0)

    tg_stdout_exit_event = threading.Event()
    tg_stderr_exit_event = threading.Event()

    if latency_cmd != '':
         latency_stdout_exit_event = threading.Event()
         latency_stderr_exit_event = threading.Event()

    tg_stdout_thread = threading.Thread(target = handle_trial_process_stdout, args = (tg_process, trial_params, stats, tg_stdout_exit_event))
    tg_stderr_thread = threading.Thread(target = handle_trial_process_stderr, args = (tg_process, trial_params, stats, tmp_stats, streams, detailed_stats, tg_stderr_exit_event))

    if latency_cmd != '':
         latency_stdout_thread = threading.Thread(target = handle_trial_process_latency_stdout, args = (latency_process, trial_params, stats, latency_stdout_exit_event))
         latency_stderr_thread = threading.Thread(target = handle_trial_process_latency_stderr, args = (latency_process, trial_params, stats, latency_stderr_exit_event))

    stats['trial_start'] = time.time() * 1000

    tg_stdout_thread.start()
    tg_stderr_thread.start()

    if latency_cmd != '':
         latency_stdout_thread.start()
         latency_stderr_thread.start()

    if latency_cmd != '':
         # sychronization stuff happens here
         bs_logger("Waiting for children to launch")
         child_launch_sem.acquire()
         child_launch_sem.acquire()
         bs_logger("Children have launched")

         bs_logger("Telling children to go")
         child_go_sem.release()
         child_go_sem.release()

         bs_logger("Synchronization services complete")

    tg_stdout_exit_event.wait()
    tg_stderr_exit_event.wait()

    if latency_cmd != '':
         latency_stdout_exit_event.wait()
         latency_stderr_exit_event.wait()

    tg_retval = tg_process.wait()
    if latency_cmd != '':
         latency_retval = latency_process.wait()

    tg_stdout_thread.join()
    tg_stderr_thread.join()

    if latency_cmd != '':
         latency_stdout_thread.join()
         latency_stderr_thread.join()

    stats['trial_stop'] = time.time() * 1000

    signal.signal(signal.SIGINT, previous_sig_handler)

    bs_logger('tg return code: %s' % (tg_retval))
    if latency_cmd != '':
         bs_logger('latency return code: %s' % (latency_retval))
         stats['retval'] = tg_retval + latency_retval

         child_launch_sem.unlink()
         child_go_sem.unlink()

         child_launch_sem.close()
         child_go_sem.close()
    else:
         stats['retval'] = tg_retval

    if latency_cmd != '':
         # fixup the directional stats to include the latency stats since they come from different places

         if trial_params['latency_traffic_direction'] == 'bidirectional' or trial_params['latency_traffic_direction'] == 'unidirectional':
              stats['directional']['->']['active'] = True
              stats['directional']['->']['tx_packets'] += stats['latency']['Forward']['TX Samples']
              stats['directional']['->']['rx_packets'] += stats['latency']['Forward']['RX Samples']
              stats['directional']['->']['rx_lost_packets'] += (stats['latency']['Forward']['TX Samples'] - stats['latency']['Forward']['RX Samples'])
              stats['directional']['->']['rx_lost_packets_pct'] = 100.0 * stats['directional']['->']['rx_lost_packets'] / stats['directional']['->']['tx_packets']

         if trial_params['latency_traffic_direction'] == 'bidirectional' or trial_params['latency_traffic_direction'] == 'revunidirectional':
              stats['directional']['<-']['active'] = True
              stats['directional']['<-']['tx_packets'] += stats['latency']['Reverse']['TX Samples']
              stats['directional']['<-']['rx_packets'] += stats['latency']['Reverse']['RX Samples']
              stats['directional']['<-']['rx_lost_packets'] += (stats['latency']['Reverse']['TX Samples'] - stats['latency']['Reverse']['RX Samples'])
              stats['directional']['<-']['rx_lost_packets_pct'] = 100.0 * stats['directional']['<-']['rx_lost_packets'] / stats['directional']['<-']['tx_packets']

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
                    lines.append(line.decode())
     if process.poll() is not None:
          for line in process_stream:
               if capture:
                    lines.append(line.decode())
          lines.append("--END--")
     return lines

def handle_trial_process_latency_stdout(process, trial_params, stats, exit_event):
    latency_output_file = None
    latency_close_file = False
    trial_params['trial_latency_output_file'] = "binary-search.trial-%03d.latency.output.txt" % (trial_params['trial'])
    filename = "%s/%s" % (trial_params['output_dir'], trial_params['trial_latency_output_file'])
    try:
         latency_output_file = open(filename, 'w')
         latency_close_file = True
    except IOError:
         bs_logger(error("Could not open %s for writing" % (filename)))
         latency_output_file = sys.stdout

    capture_output = True
    do_loop = True
    while do_loop:
         stdout_lines = handle_process_output(process, process.stdout, capture_output)

         for line in stdout_lines:
              if line == "--END--":
                   exit_event.set()
                   do_loop = False
                   continue

              print(line.rstrip('\n'), file = latency_output_file)

    if latency_close_file:
         latency_output_file.close()

    return(0)

def handle_trial_process_latency_stderr(process, trial_params, stats, exit_event):
    prefix = "LAT"

    latency_debug_file = None
    latency_close_file = False
    trial_params['trial_latency_debug_file'] = "binary-search.trial-%03d.latency.debug.txt" % (trial_params['trial'])
    filename = "%s/%s" % (trial_params['output_dir'], trial_params['trial_latency_debug_file'])
    try:
         latency_debug_file = open(filename, 'w')
         latency_close_file = True
    except IOError:
         bs_logger(error("Could not open %s for writing" % (filename)))
         latency_debug_file = sys.stdout

    capture_output = True
    do_loop = True
    while do_loop:
         stdout_lines = handle_process_output(process, process.stderr, capture_output)

         for line in stdout_lines:
              if line == "--END--":
                   exit_event.set()
                   do_loop = False
                   continue

              if latency_close_file:
                   print(line.rstrip('\n'), file = latency_debug_file)

              m = re.search(r"^\[BS\]\s(.*)$", line)
              if m:
                   bs_logger(m.group(1), bso = False, prefix = prefix)

                   r = re.search(r"\[([a-zA-Z]+) Latency: ([0-9]+)->([0-9]+)\]\s+(.*):\s+(.*)", m.group(1))
                   if r:
                        if not r.group(1) in stats['latency']:
                             stats['latency'][r.group(1)] = dict()
                             stats['latency'][r.group(1)]['tx_device'] = int(r.group(2))
                             stats['latency'][r.group(1)]['rx_device'] = int(r.group(3))
                             stats['latency'][r.group(1)]['percentiles'] = dict()

                        f = re.search(r"(.*)th Percentile", r.group(4))
                        if f:
                             stats['latency'][r.group(1)]['percentiles'][f.group(1)] = float(r.group(5))
                        else:
                             stats['latency'][r.group(1)][r.group(4)] = float(r.group(5))
              elif not latency_close_file:
                   bs_logger(line.rstrip('\n'), bso = False, prefix = prefix + 'DBG')

    if latency_close_file:
         latency_debug_file.close()

    return(0)

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

             bs_logger(line.rstrip('\n'), bso = False, prefix = prefix)

             if trial_params['traffic_generator'] == 'null-txrx':
                  if line.rstrip('\n') == "exiting":
                       capture_output = False
                       exit_event.set()
                  m = re.search(r"result=(.*)$", line)
                  if m:
                       bs_logger("trial result: %s" % m.group(1))

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
         bs_logger(error("Could not open %s for writing" % (filename)))
         primary_output_file = sys.stdout

    secondary_output_file = None
    secondary_close_file = False
    trial_params['trial_secondary_output_file'] = "binary-search.trial-%03d.extra.txt" % (trial_params['trial'])
    filename = "%s/%s" % (trial_params['output_dir'], trial_params['trial_secondary_output_file'])
    try:
         secondary_output_file = open(filename, 'w')
         secondary_close_file = True
    except IOError:
         bs_logger(error("Could not open %s for writing" % (filename)))
         secondary_output_file = sys.stdout

    tertiary_output_file = None
    tertiary_close_file = False
    filename = "%s/binary-search.trial-%03d.json-port-profiles.txt" % (trial_params['output_dir'], trial_params['trial'])
    try:
         tertiary_output_file = open(filename, 'w')
         tertiary_close_file = True
    except IOError:
         bs_logger(error("Could not open %s for writing" % (filename)))
         tertiary_output_file = sys.stdout

    capture_output = True
    do_loop = True
    while do_loop:
        stderr_lines = handle_process_output(process, process.stderr, capture_output)

        for line in stderr_lines:
             if line == "--END--":
                  exit_event.set()
                  do_loop = False
                  continue

             if trial_params['traffic_generator'] == 'trex-txrx' or trial_params['traffic_generator'] == 'trex-txrx-profile':
                  m = re.search(r"DEVICE PAIR ([0-9]+:[0-9]+) \| PARSABLE JSON STREAM PROFILE FOR DIRECTION '([0-9]+[-><]{2}[0-9]+)':\s+(.*)$", line)
                  if m:
                       dev_pair = m.group(1)
                       path = m.group(2)
                       json_data = json.loads(m.group(3))
                       print("Device Pair %s | Direction '%s':" % (dev_pair, path), file=tertiary_output_file)
                       print("%s\n" % (dump_json_readable(json_data)), file=tertiary_output_file)
                       continue

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

             if trial_params['traffic_generator'] == 'trex-txrx':
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

                       for device_pair in trial_params['test_dev_pairs']:
                            stream_types = []

                            if trial_params['use_device_stats']:
                                 stats[device_pair['tx']]['tx_active'] = True
                                 stats[device_pair['rx']]['rx_active'] = True
                                 stats['directional'][device_pair['direction']]['active'] = True

                                 stats[device_pair['tx']]['tx_packets'] += int(results[str(device_pair['tx'])]['opackets'])
                                 stats['directional'][device_pair['direction']]['tx_packets'] += int(results[str(device_pair['tx'])]['opackets'])

                                 stats[device_pair['rx']]['rx_packets'] += int(results[str(device_pair['rx'])]['ipackets'])
                                 stats['directional'][device_pair['direction']]['rx_packets'] += int(results[str(device_pair['rx'])]['ipackets'])

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

                                 bs_logger("Device Pair: %s |   All TX   | packets=%s rate=%s l1_bps=%s l2_bps=%s" % (device_pair['path'], commify(stats[device_pair['tx']]['tx_packets']), commify(stats[device_pair['tx']]['tx_pps']), commify(stats[device_pair['tx']]['tx_l1_bps']), commify(stats[device_pair['tx']]['tx_l2_bps'])))
                                 bs_logger("Device Pair: %s |   All RX   | packets=%s rate=%s l1_bps=%s l2_bps=%s" % (device_pair['path'], commify(stats[device_pair['rx']]['rx_packets']), commify(stats[device_pair['rx']]['rx_pps']), commify(stats[device_pair['rx']]['rx_l1_bps']), commify(stats[device_pair['rx']]['rx_l2_bps'])))

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
                                                     stats['directional'][device_pair['direction']]['tx_packets'] += int(results["flow_stats"][str(pg_id)]["tx_pkts"][str(device_pair['tx'])])
                                                     stats['directional'][device_pair['direction']]['active'] = True

                                                if stream_type == "latency":
                                                     stats[device_pair['tx']]['tx_latency_packets'] += int(results["flow_stats"][str(pg_id)]["tx_pkts"][str(device_pair['tx'])])
                                                     if not trial_params['use_device_stats']:
                                                          stats['directional'][device_pair['direction']]['tx_packets'] += int(results["flow_stats"][str(pg_id)]["tx_pkts"][str(device_pair['tx'])])
                                                          stats['directional'][device_pair['direction']]['active'] = True
                                           else:
                                                stats_error_append_pg_id(stats[device_pair['tx']], 'tx_missing', pg_id)

                                           if str(device_pair['rx']) in results["flow_stats"][str(pg_id)]["rx_pkts"]:
                                                if not trial_params['use_device_stats']:
                                                     stats[device_pair['rx']]['rx_packets'] += int(results["flow_stats"][str(pg_id)]["rx_pkts"][str(device_pair['rx'])])
                                                     stats['directional'][device_pair['direction']]['rx_packets'] += int(results["flow_stats"][str(pg_id)]["rx_pkts"][str(device_pair['rx'])])
                                                     stats['directional'][device_pair['direction']]['active'] = True

                                                if stream_type == "latency":
                                                     stats[device_pair['rx']]['rx_latency_packets'] += int(results["flow_stats"][str(pg_id)]["rx_pkts"][str(device_pair['rx'])])
                                                     if not trial_params['use_device_stats']:
                                                          stats['directional'][device_pair['direction']]['rx_packets'] += int(results["flow_stats"][str(pg_id)]["rx_pkts"][str(device_pair['rx'])])
                                                          stats['directional'][device_pair['direction']]['active'] = True

                                                     stats[device_pair['rx']]['rx_latency_average'] += int(results["flow_stats"][str(pg_id)]["rx_pkts"][str(device_pair['rx'])]) * float(results["latency"][str(pg_id)]["latency"]["average"])

                                                     if int(results["latency"][str(pg_id)]["err_cntrs"]["dup"]):
                                                          stats_error_append_pg_id(stats[device_pair['rx']], "latency_duplicate", pg_id)

                                                     if float(results["latency"][str(pg_id)]["latency"]["total_max"]) > stats[device_pair['rx']]['rx_latency_maximum']:
                                                          stats[device_pair['rx']]['rx_latency_maximum'] = float(results["latency"][str(pg_id)]["latency"]["total_max"])

                                                     if results["latency"][str(pg_id)]["latency"]["total_min"] != "N/A":
                                                          if stats[device_pair['rx']]['rx_latency_minimum'] == 0.0 or float(results["latency"][str(pg_id)]["latency"]["total_min"]) < stats[device_pair['rx']]['rx_latency_minimum']:
                                                               stats[device_pair['rx']]['rx_latency_minimum'] = float(results["latency"][str(pg_id)]["latency"]["total_min"])
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
                                                elif float(results["flow_stats"][str(pg_id)]["loss"]["pct"][device_pair['path']]) == 100.0:
                                                     stats_error_append_pg_id(stats[device_pair['rx']], 'rx_total_loss', pg_id)
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

                                 bs_logger("Device Pair: %s |   All TX   | packets=%s rate=%s l1_bps=%s l2_bps=%s" % (device_pair['path'], commify(stats[device_pair['tx']]['tx_packets']), commify(stats[device_pair['tx']]['tx_pps']), commify(stats[device_pair['tx']]['tx_l1_bps']), commify(stats[device_pair['tx']]['tx_l2_bps'])))
                                 bs_logger("Device Pair: %s |   All RX   | packets=%s rate=%s l1_bps=%s l2_bps=%s" % (device_pair['path'], commify(stats[device_pair['rx']]['rx_packets']), commify(stats[device_pair['rx']]['rx_pps']), commify(stats[device_pair['rx']]['rx_l1_bps']), commify(stats[device_pair['rx']]['rx_l2_bps'])))

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

                                 bs_logger("Device Pair: %s | Latency TX | packets=%s rate=%s l1_bps=%s l2_bps=%s" % (device_pair['path'], commify(stats[device_pair['tx']]['tx_latency_packets']), commify(stats[device_pair['tx']]['tx_latency_pps']), commify(stats[device_pair['tx']]['tx_latency_l1_bps']), commify(stats[device_pair['tx']]['tx_latency_l2_bps'])))
                                 bs_logger("Device Pair: %s | Latency RX | packets=%s rate=%s l1_bps=%s l2_bps=%s average=%s minimum=%s maximum=%s" % (device_pair['path'], commify(stats[device_pair['rx']]['rx_latency_packets']), commify(stats[device_pair['rx']]['rx_latency_pps']), commify(stats[device_pair['rx']]['rx_latency_l1_bps']), commify(stats[device_pair['rx']]['rx_latency_l2_bps']), commify(stats[device_pair['rx']]['rx_latency_average']), commify(stats[device_pair['rx']]['rx_latency_minimum']), commify(stats[device_pair['rx']]['rx_latency_maximum'])))

                       for direction in stats['directional']:
                            if stats['directional'][direction]['active']:
                                 stats['directional'][direction]['rx_lost_packets'] = stats['directional'][direction]['tx_packets'] - stats['directional'][direction]['rx_packets']
                                 if stats['directional'][direction]['tx_packets']:
                                      stats['directional'][direction]['rx_lost_packets_pct'] = 100.0 * stats['directional'][direction]['rx_lost_packets'] / stats['directional'][direction]['tx_packets']

                       continue

             elif trial_params['traffic_generator'] == 'trex-txrx-profile':
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

                       stream_types = []
                       stream_types.append('default')
                       if trial_params['measure_latency']:
                            stream_types.append('latency')

                       for device_pair in trial_params['test_dev_pairs']:
                            examined_pg_ids = []

                            for stream_type in stream_types:
                                 if device_pair['tx'] in streams and stream_type in streams[device_pair['tx']]:
                                      for pg_id, frame_size, traffic_type in zip(streams[device_pair['tx']][stream_type]['pg_ids'], streams[device_pair['tx']][stream_type]['frame_sizes'], streams[device_pair['tx']][stream_type]['traffic_type']):
                                           if pg_id in examined_pg_ids:
                                                continue
                                           else:
                                                examined_pg_ids.append(pg_id)

                                           if str(device_pair['tx']) in results['flow_stats'][str(pg_id)]['rx_pkts'] and int(results['flow_stats'][str(pg_id)]['rx_pkts'][str(device_pair['tx'])]):
                                                stats_error_append_pg_id(stats[device_pair['tx']], 'rx_invalid', pg_id)

                                           if str(device_pair['rx']) in results['flow_stats'][str(pg_id)]['tx_pkts'] and int(results['flow_stats'][str(pg_id)]['tx_pkts'][str(device_pair['rx'])]):
                                                stats_error_append_pg_id(stats[device_pair['rx']], 'tx_invalid', pg_id)

                                           if str(device_pair['tx']) in results['flow_stats'][str(pg_id)]['tx_pkts']:
                                                stats[device_pair['tx']]['tx_packets'] += int(results["flow_stats"][str(pg_id)]["tx_pkts"][str(device_pair['tx'])])
                                                if traffic_type == 'measurement':
                                                     stats['directional'][device_pair['direction']]['tx_packets'] += int(results["flow_stats"][str(pg_id)]["tx_pkts"][str(device_pair['tx'])])
                                                     stats['directional'][device_pair['direction']]['active'] = True

                                                if stream_type == "latency":
                                                     stats[device_pair['tx']]['tx_latency_packets'] += int(results["flow_stats"][str(pg_id)]["tx_pkts"][str(device_pair['tx'])])
                                                     if traffic_type == 'measurement':
                                                          stats['directional'][device_pair['direction']]['tx_packets'] += int(results["flow_stats"][str(pg_id)]["tx_pkts"][str(device_pair['tx'])])
                                                          stats['directional'][device_pair['direction']]['active'] = True
                                           else:
                                                stats_error_append_pg_id(stats[device_pair['tx']], 'tx_missing', pg_id)

                                           if str(device_pair['rx']) in results["flow_stats"][str(pg_id)]["rx_pkts"]:
                                                stats[device_pair['rx']]['rx_packets'] += int(results["flow_stats"][str(pg_id)]["rx_pkts"][str(device_pair['rx'])])
                                                if traffic_type == 'measurement':
                                                     stats['directional'][device_pair['direction']]['rx_packets'] += int(results["flow_stats"][str(pg_id)]["rx_pkts"][str(device_pair['rx'])])
                                                     stats['directional'][device_pair['direction']]['active'] = True

                                                if stream_type == "latency":
                                                     stats[device_pair['rx']]['rx_latency_packets'] += int(results["flow_stats"][str(pg_id)]["rx_pkts"][str(device_pair['rx'])])
                                                     if traffic_type == 'measurement':
                                                          stats['directional'][device_pair['direction']]['rx_packets'] += int(results["flow_stats"][str(pg_id)]["rx_pkts"][str(device_pair['rx'])])
                                                          stats['directional'][device_pair['direction']]['active'] = True

                                                     stats[device_pair['rx']]['rx_latency_average'] += int(results["flow_stats"][str(pg_id)]["rx_pkts"][str(device_pair['rx'])]) * float(results["latency"][str(pg_id)]["latency"]["average"])

                                                     if int(results["latency"][str(pg_id)]["err_cntrs"]["dup"]):
                                                          stats_error_append_pg_id(stats[device_pair['rx']], "latency_duplicate", pg_id)

                                                     if float(results["latency"][str(pg_id)]["latency"]["total_max"]) > stats[device_pair['rx']]['rx_latency_maximum']:
                                                          stats[device_pair['rx']]['rx_latency_maximum'] = float(results["latency"][str(pg_id)]["latency"]["total_max"])

                                                     if results["latency"][str(pg_id)]["latency"]["total_min"] != "N/A":
                                                          if stats[device_pair['rx']]['rx_latency_minimum'] == 0.0 or float(results["latency"][str(pg_id)]["latency"]["total_min"]) < stats[device_pair['rx']]['rx_latency_minimum']:
                                                               stats[device_pair['rx']]['rx_latency_minimum'] = float(results["latency"][str(pg_id)]["latency"]["total_min"])
                                           else:
                                                stats_error_append_pg_id(stats[device_pair['rx']], 'rx_missing', pg_id)

                                           if str(device_pair['tx']) in results["flow_stats"][str(pg_id)]["tx_pkts"] and str(device_pair['rx']) in results["flow_stats"][str(pg_id)]["rx_pkts"]:
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
                                                else:
                                                     if traffic_type == 'measurement':
                                                          if float(results["flow_stats"][str(pg_id)]["loss"]["pct"][device_pair['path']]) == 100.0:
                                                               stats_error_append_pg_id(stats[device_pair['rx']], 'rx_total_loss', pg_id)
                                                          elif float(results["flow_stats"][str(pg_id)]["loss"]["pct"][device_pair['path']]) > trial_params["max_loss_pct"]:
                                                               stats_error_append_pg_id(stats[device_pair['rx']], 'rx_loss', pg_id)
                                                     elif traffic_type == 'ddos':
                                                          if float(results["flow_stats"][str(pg_id)]["loss"]["pct"][device_pair['path']]) != 100.0:
                                                               stats_error_append_pg_id(stats[device_pair['rx']], 'ddos_rx', pg_id)

                            if 'bits_per_byte' in tmp_stats[device_pair['tx']]:
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

                                 bs_logger("Device Pair: %s |   All TX   | packets=%s rate=%s l1_bps=%s l2_bps=%s" % (device_pair['path'], commify(stats[device_pair['tx']]['tx_packets']), commify(stats[device_pair['tx']]['tx_pps']), commify(stats[device_pair['tx']]['tx_l1_bps']), commify(stats[device_pair['tx']]['tx_l2_bps'])))
                                 bs_logger("Device Pair: %s |   All RX   | packets=%s rate=%s l1_bps=%s l2_bps=%s" % (device_pair['path'], commify(stats[device_pair['rx']]['rx_packets']), commify(stats[device_pair['rx']]['rx_pps']), commify(stats[device_pair['rx']]['rx_l1_bps']), commify(stats[device_pair['rx']]['rx_l2_bps'])))

                            if trial_params['measure_latency'] and 'bits_per_byte' in tmp_stats[device_pair['tx']]:
                                 stats[device_pair['tx']]['tx_active'] = True
                                 stats[device_pair['rx']]['rx_active'] = True

                                 stats[device_pair['rx']]['rx_latency_lost_packets'] = stats[device_pair['tx']]['tx_latency_packets'] - stats[device_pair['rx']]['rx_latency_packets']
                                 if stats[device_pair['tx']]['tx_latency_packets']:
                                      stats[device_pair['rx']]['rx_latency_lost_packets_pct'] = 100.0 * stats[device_pair['rx']]['rx_latency_lost_packets'] / stats[device_pair['tx']]['tx_latency_packets']
                                 else:
                                      stats[device_pair['rx']]['rx_latency_lost_packets_pct'] = 0.0

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

                                 bs_logger("Device Pair: %s | Latency TX | packets=%s rate=%s l1_bps=%s l2_bps=%s" % (device_pair['path'], commify(stats[device_pair['tx']]['tx_latency_packets']), commify(stats[device_pair['tx']]['tx_latency_pps']), commify(stats[device_pair['tx']]['tx_latency_l1_bps']), commify(stats[device_pair['tx']]['tx_latency_l2_bps'])))
                                 bs_logger("Device Pair: %s | Latency RX | packets=%s rate=%s l1_bps=%s l2_bps=%s average=%s minimum=%s maximum=%s" % (device_pair['path'], commify(stats[device_pair['rx']]['rx_latency_packets']), commify(stats[device_pair['rx']]['rx_latency_pps']), commify(stats[device_pair['rx']]['rx_latency_l1_bps']), commify(stats[device_pair['rx']]['rx_latency_l2_bps']), commify(stats[device_pair['rx']]['rx_latency_average']), commify(stats[device_pair['rx']]['rx_latency_minimum']), commify(stats[device_pair['rx']]['rx_latency_maximum'])))

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

    if tertiary_close_file:
         tertiary_output_file.close()

    return(0)

def print_stats(trial_params, stats):
     if t_global.args.traffic_generator == 'null-txrx':
          string = ""

          string += '[\n'
          string += dump_json_readable(stats[0])
          string += '\n,\n'
          string += dump_json_readable(stats[1])
          string += '\n]\n'

          bs_logger(string)
     elif t_global.args.traffic_generator == 'trex-txrx' or t_global.args.traffic_generator == 'trex-txrx-profile':
          string = ""

          string += '[\n'
          port = 0
          while port <= trial_params['max_port']:
               if port in stats:
                    string += dump_json_readable(stats[port])
               else:
                    string += dump_json_readable(trial_params['null_stats'])
               if port < trial_params['max_port']:
                    string += '\n,\n'
               port += 1
          string += '\n]\n'

          bs_logger(string)

def setup_config_var(variable, value, trial_params, config_tag = True, silent = False):
     trial_params[variable] = value

     if config_tag:
          bs_logger("CONFIG | %s=%s" % (variable, value))
     else:
          if not silent:
               bs_logger("%s=%s" % (variable, value))

def evaluate_trial(trial_params, trial_stats):
     bs_logger("(Evaluating trial)")

     trial_result = 'pass'
     total_tx_packets = 0
     total_rx_packets = 0

     for dev_pair in trial_params['test_dev_pairs']:
          if trial_stats[dev_pair['tx']]['tx_active'] and trial_stats[dev_pair['tx']]['tx_packets'] == 0:
               trial_result = 'abort'
               bs_logger("\t(critical requirement failure, no packets were transmitted between device pair: %d -> %d, trial result: %s)" %
                         (dev_pair['tx'],
                          dev_pair['rx'],
                          trial_result))

          if trial_stats[dev_pair['rx']]['rx_active'] and trial_stats[dev_pair['rx']]['rx_packets'] == 0:
               trial_result = 'abort'
               bs_logger("\t(critical requirement failure, no packets were received between device pair: %d -> %d, trial result: %s)" %
                         (dev_pair['tx'],
                          dev_pair['rx'],
                          trial_result))

          if 'tx_invalid_error' in trial_stats[dev_pair['rx']]:
               trial_result = 'abort'
               bs_logger("\t(critical requirement failure, packets were transmitted on an incorrect port between device pair: %d -> %d, pg_ids: [%s], trial result: %s)" %
                         (dev_pair['tx'],
                          dev_pair['rx'],
                          trial_stats[dev_pair['rx']]['tx_invalid_error'],
                          trial_result))

          if 'rx_invalid_error' in trial_stats[dev_pair['tx']]:
               trial_result = 'abort'
               bs_logger("\t(critical requirement failure, packets were received on an incorrect port between device pair: %d -> %d, pg_ids: [%s], trial result: %s)" %
                         (dev_pair['tx'],
                          dev_pair['rx'],
                          trial_stats[dev_pair['tx']]['rx_invalid_error'],
                          trial_result))

          if 'latency_duplicate_error' in trial_stats[dev_pair['rx']]:
               if trial_params['duplicate_packet_failure_mode'] == 'quit':
                    trial_result = 'abort'
                    bs_logger("\t(critical requirement failure, duplicate latency packets detected, device pair: %d -> %d, pg_ids: [%s], trial result: %s)" %
                              (dev_pair['tx'],
                               dev_pair['rx'],
                               trial_stats[dev_pair['rx']]['latency_duplicate_error'],
                               trial_result))

          if 'rx_total_loss_error' in trial_stats[dev_pair['rx']]:
               trial_result = 'abort'
               bs_logger("\t(critical requirement failure, individual stream 100%% RX packet loss , device pair: %d -> %d, pg_ids: [%s], trial result: %s)" %
                         (dev_pair['tx'],
                          dev_pair['rx'],
                          trial_stats[dev_pair['rx']]['rx_total_loss_error'],
                          trial_result))

          if 'rx_negative_loss_error' in trial_stats[dev_pair['rx']]:
               if trial_params['negative_packet_loss_mode'] == 'quit':
                    trial_result = 'abort'
                    bs_logger("\t(critical requirement failure, negative individual stream RX packet loss, device pair: %d -> %d, pg_ids: [%s], trial result: %s)" %
                              (dev_pair['tx'],
                               dev_pair['rx'],
                               trial_stats[dev_pair['rx']]['rx_negative_loss_error'],
                               trial_result))

          if trial_params['loss_granularity'] == 'device' and trial_stats[dev_pair['rx']]['rx_active']:
               if trial_stats[dev_pair['rx']]['rx_lost_packets_pct'] < 0:
                    if trial_params['negative_packet_loss_mode'] == 'quit':
                         trial_result = 'abort'
                         bs_logger("\t(critical requirement failure, negative device packet loss, device pair: %d -> %d, trial result: %s)" %
                                   (dev_pair['tx'],
                                    dev_pair['rx'],
                                    trial_result))

     if trial_params['loss_granularity'] == 'direction':
          for direction in trial_stats['directional']:
               if trial_stats['directional'][direction]['active']:
                    if trial_stats['directional'][direction]['rx_lost_packets_pct'] < 0:
                         if trial_params['negative_packet_loss_mode'] == 'quit':
                              trial_result = 'abort'
                              bs_logger("\t(critical requirement failure, negative direction packet loss, direction: %s, trial result: %s)" %
                                        (direction,
                                         trial_result))

     if 'latency_device_pair' in trial_params and trial_params['latency_device_pair'] != '--':
          latency_device_pair = trial_params['latency_device_pair'].split(':')
          latency_device_pair[0] = int(latency_device_pair[0])
          latency_device_pair[1] = int(latency_device_pair[1])

          if trial_params['latency_traffic_direction'] == 'bidirectional' or trial_params['latency_traffic_direction'] == 'unidirectional':
               if trial_stats['latency']['Forward']['TX Samples'] == 0:
                    trial_result = 'abort'
                    bs_logger("\t(critical requirement failure, no forward packets were transmitted between latency device pair: %d -> %d, trial result: %s)" %
                              (latency_device_pair[0],
                               latency_device_pair[1],
                               trial_result))

               if trial_stats['latency']['Forward']['RX Samples'] == 0:
                    trial_result = 'abort'
                    bs_logger("\t(critical requirement failure, no forward packets were received between latency device pair: %d -> %d, trial result: %s)" %
                              (latency_device_pair[0],
                               latency_device_pair[1],
                               trial_result))

          if trial_params['latency_traffic_direction'] == 'bidirectional' or trial_params['latency_traffic_direction'] == 'revunidirectional':
               if trial_stats['latency']['Reverse']['TX Samples'] == 0:
                    trial_result = 'abort'
                    bs_logger("\t(critical requirement failure, no reverse packets were transmitted between latency device pair: %d -> %d, trial result: %s)" %
                              (latency_device_pair[1],
                               latency_device_pair[0],
                               trial_result))

               if trial_stats['latency']['Reverse']['RX Samples'] == 0:
                    trial_result = 'abort'
                    bs_logger("\t(critical requirement failure, no reverse packets were received between latency device pair: %d -> %d, trial result: %s)" %
                              (latency_device_pair[1],
                               latency_device_pair[0],
                               trial_result))

          if trial_params['loss_granularity'] == 'device' and trial_params['negative_packet_loss_mode'] == 'quit':
               if trial_params['latency_traffic_direction'] == 'bidirectional' or trial_params['latency_traffic_direction'] == 'unidirectional':
                    if trial_stats['latency']['Forward']['Loss Ratio'] < 0:
                         trial_result = 'abort'
                         bs_logger("\t(critical requirement failure, negative device packet loss, forward latency device pair: %d -> %d, trial result: %s)" %
                                   (latency_device_pair[0],
                                    latency_device_pair[1],
                                    trial_result))

               if trial_params['latency_traffic_direction'] == 'bidirectional' or trial_params['latency_traffic_direction'] == 'revunidirectional':
                    if trial_stats['latency']['Reverse']['Loss Ratio'] < 0:
                         trial_result = 'abort'
                         bs_logger("\t(critical requirement failure, negative device packet loss, reverse latency device pair: %d -> %d, trial result: %s)" %
                                   (latency_device_pair[1],
                                    latency_device_pair[0],
                                    trial_result))


     if trial_result == 'abort':
          trial_result = 'quit'
          bs_logger(error("(binary search aborting due to critical error, trial result: %s)" %
                          (trial_result)))
          return(trial_result)

     for dev_pair in trial_params['test_dev_pairs']:
          if t_global.args.traffic_generator != 'null-txrx' and trial_stats[dev_pair['tx']]['tx_active']:
               requirement_msg = "passed"
               result_msg = "unmodified"
               tx_rate = trial_stats[dev_pair['tx']]['tx_pps'] / 1000000.0
               tolerance_min = 0.0
               tolerance_max = 0.0
               if t_global.args.traffic_generator == 'trex-txrx' or t_global.args.traffic_generator == 'trex-txrx-profile':
                    tolerance_min = (trial_stats[dev_pair['tx']]['tx_pps_target'] / 1000000) * ((100.0 - trial_params['rate_tolerance']) / 100)
                    tolerance_max = (trial_stats[dev_pair['tx']]['tx_pps_target'] / 1000000) * ((100.0 + trial_params['rate_tolerance']) / 100)
                    if tx_rate > tolerance_max or tx_rate < tolerance_min:
                         requirement_msg = "failed"
                         result_msg = "modified"
                         trial_result = "retry-to-%s" % trial_params['rate_tolerance_failure']
                    tolerance_min *= 1000000
                    tolerance_max *= 1000000
               trial_stats[dev_pair['tx']]['tx_tolerance_min'] = tolerance_min
               trial_stats[dev_pair['tx']]['tx_tolerance_max'] = tolerance_max
               bs_logger("\t(trial %s requirement, TX rate tolerance, device pair: %d -> %d, unit: mpps, tolerance: %s - %s, achieved: %s, trial result status: %s, trial result: %s)" %
                         (requirement_msg,
                          dev_pair['tx'],
                          dev_pair['rx'],
                          commify(tolerance_min/1000000),
                          commify(tolerance_max/1000000),
                          commify(tx_rate),
                          result_msg,
                          trial_result))

     for dev_pair in trial_params['test_dev_pairs']:
          if 'latency_duplicate_error' in trial_stats[dev_pair['rx']]:
               trial_result = trial_params['duplicate_packet_failure_mode']
               bs_logger("\t(trial failed requirement, duplicate latency packets detected, device pair: %d -> %d, pg_ids: [%s], trial result status: modified, trial result: %s)" %
                         (dev_pair['tx'],
                          dev_pair['rx'],
                          trial_stats[dev_pair['rx']]['latency_duplicate_error'],
                          trial_result) )

          if 'rx_negative_loss_error' in trial_stats[dev_pair['rx']]:
               trial_result = trial_params['negative_packet_loss_mode']
               bs_logger("\t(trial failed requirement, negative individual stream RX packet loss, device pair: %d -> %d, pg_ids: [%s], trial result status: modified, trial result: %s)" %
                         (dev_pair['tx'],
                          dev_pair['rx'],
                          trial_stats[dev_pair['rx']]['rx_negative_loss_error'],
                          trial_result))

          if 'tx_missing_error' in trial_stats[dev_pair['tx']]:
               trial_result = 'fail'
               bs_logger("\t(trial failed requirement, missing TX results, device pair: %d -> %d, pg_ids: [%s], trial result status: modified, trial result: %s)" %
                         (dev_pair['tx'],
                          dev_pair['rx'],
                          trial_stats[dev_pair['tx']]['tx_missing_error'],
                          trial_result))

          if 'rx_missing_error' in trial_stats[dev_pair['rx']]:
               trial_result = 'fail'
               bs_logger("\t(trial failed requirement, missing RX results, device pair: %d -> %d, pg_ids: [%s], trail result status: modified, trial result: %s)" %
                         (dev_pair['tx'],
                          dev_pair['rx'],
                          trial_stats[dev_pair['rx']]['rx_missing_error'],
                          trial_result))

          if 'ddos_rx_error' in trial_stats[dev_pair['rx']]:
               trial_result = 'fail'
               bs_logger("\t(trial failed requirement, individual DDoS stream RX packets received, device pair: %d -> %d, pg_ids: [%s], trial result status: modified, trial result: %s)" %
                         (dev_pair['tx'],
                          dev_pair['rx'],
                          trial_stats[dev_pair['rx']]['ddos_rx_error'],
                          trial_result))

     if trial_params['loss_granularity'] == 'direction':
          for direction in trial_stats['directional']:
               if trial_stats['directional'][direction]['active']:
                    if trial_stats['directional'][direction]['rx_lost_packets_pct'] < 0:
                         trial_result = trial_params['negative_packet_loss_mode']
                         bs_logger("\t(trial failed requirement, negative direction packet loss, direction: %s, trial result status: modified, trial result: %s)" %
                                   (direction,
                                    trial_result))

                    requirement_msg = "passed"
                    result_msg = "unmodified"
                    if trial_stats['directional'][direction]['rx_lost_packets_pct'] > t_global.args.max_loss_pct:
                         requirement_msg = "failed"
                         result_msg = "modified"
                         trial_result = 'fail'
                    bs_logger("\t(trial %s requirement, percent loss, direction: %s, requested: %s%%, achieved: %s%%, lost packets: %s, trial result status: %s, trial result: %s)" %
                              (requirement_msg,
                               direction,
                               commify(t_global.args.max_loss_pct),
                               commify(trial_stats['directional'][direction]['rx_lost_packets_pct']),
                               commify(trial_stats['directional'][direction]['rx_lost_packets']),
                               result_msg,
                               trial_result))
     else:
          if 'latency_device_pair' in trial_params and trial_params['latency_device_pair'] != '--':
               # for the latency device pair, trial_params['loss_granularity'] == 'segment' == 'device'
               latency_device_pair = trial_params['latency_device_pair'].split(':')
               latency_device_pair[0] = int(latency_device_pair[0])
               latency_device_pair[1] = int(latency_device_pair[1])

               if trial_params['latency_traffic_direction'] == 'bidirectional' or trial_params['latency_traffic_direction'] == 'unidirectional':
                    if trial_stats['latency']['Forward']['Loss Ratio'] > trial_params["max_loss_pct"]:
                         trial_result = 'fail'
                         bs_logger("\t(trial failed requirement, latency RX packet loss, forward latency device pair: %d -> %d, trial result status: modified, trial result: %s)" %
                                   (latency_device_pair[0],
                                    latency_device_pair[1],
                                    trial_result))

               if trial_params['latency_traffic_direction'] == 'bidirectional' or trial_params['latency_traffic_direction'] == 'revunidirectional':
                    if trial_stats['latency']['Reverse']['Loss Ratio'] > trial_params["max_loss_pct"]:
                         trial_result = 'fail'
                         bs_logger("\t(trial failed requirement, latency RX packet loss, reverse latency device pair: %d -> %d, trial result status: modified, trial result: %s)" %
                                   (latency_device_pair[1],
                                    latency_device_pair[0],
                                    trial_result))

          for dev_pair in trial_params['test_dev_pairs']:
               if trial_params['loss_granularity'] == 'segment':
                    if 'rx_loss_error' in trial_stats[dev_pair['rx']]:
                         trial_result = 'fail'
                         bs_logger("\t(trial failed requirement, individual stream RX packet loss, device pair: %d -> %d, pg_ids: [%s], trial result status: modified, trial result: %s)" %
                                   (dev_pair['tx'],
                                    dev_pair['rx'],
                                    trial_stats[dev_pair['rx']]['rx_loss_error'],
                                    trial_result))
               elif trial_params['loss_granularity'] == 'device':
                    if trial_stats[dev_pair['rx']]['rx_active']:
                         if trial_stats[dev_pair['rx']]['rx_lost_packets_pct'] < 0:
                              trial_result = trial_params['negative_packet_loss_mode']
                              bs_logger("\t(trial failed requirement, negative device packet loss, device pair: %d -> %d, trial result status: modified, trial result: %s)" %
                                        (dev_pair['tx'],
                                         dev_pair['rx'],
                                         trial_result))

                         requirement_msg = "passed"
                         result_msg = "unmodified"
                         if trial_stats[dev_pair['rx']]['rx_lost_packets_pct'] > t_global.args.max_loss_pct:
                              requirement_msg = "failed"
                              result_msg = "modified"
                              trial_result = 'fail'
                         bs_logger("\t(trial %s requirement, percent loss, device pair: %d -> %d, requested: %s%%, achieved: %s%%, lost packets: %s, trial result status: %s, trial result: %s)" %
                                   (requirement_msg,
                                    dev_pair['tx'],
                                    dev_pair['rx'],
                                    commify(t_global.args.max_loss_pct),
                                    commify(trial_stats[dev_pair['rx']]['rx_lost_packets_pct']),
                                    commify(trial_stats[dev_pair['rx']]['rx_lost_packets']),
                                    result_msg,
                                    trial_result))

                         if t_global.args.measure_latency:
                              requirement_msg = "passed"
                              result_msg = "unmodified"
                              if trial_stats[dev_pair['rx']]['rx_latency_lost_packets_pct'] > t_global.args.max_loss_pct:
                                   requirement_msg = "failed"
                                   result_msg = "modified"
                                   trial_result = 'fail'
                              bs_logger("\t(trial %s requirement, latency percent loss, device pair: %d -> %d, requested: %s%%, achieved: %s%%, lost packets: %s, trial result status: %s, trial result: %s)" %
                                        (requirement_msg,
                                         dev_pair['tx'],
                                         dev_pair['rx'],
                                         commify(t_global.args.max_loss_pct),
                                         commify(trial_stats[dev_pair['rx']]['rx_latency_lost_packets_pct']),
                                         commify(trial_stats[dev_pair['rx']]['rx_latency_lost_packets']),
                                         result_msg,
                                         trial_result))

     if 'global' in trial_stats:
          tolerance_min = float(trial_params['runtime']) * (1 - (float(trial_params['runtime_tolerance']) / 100))
          tolerance_max = float(trial_params['runtime']) * (1 + (float(trial_params['runtime_tolerance']) / 100))
          trial_stats['global']['runtime_tolerance_min'] = tolerance_min
          trial_stats['global']['runtime_tolerance_max'] = tolerance_max

          if trial_stats['global']['timeout']:
               trial_result = "retry-to-fail"
               bs_logger("\t(trial timeout, forcing a retry, timeouts can cause inconclusive trial results, trial result status: modified, trial result: %s)" %
                         (trial_result))
          else:
               if trial_stats['global']['runtime'] < tolerance_min or trial_stats['global']['runtime'] > tolerance_max:
                    result_msg = "unmodified"
                    if trial_result == "pass":
                         trial_result = "retry-to-fail"
                         result_msg = "modified"
                    bs_logger("\t(trial failed requirement, runtime tolerance test, forcing retry, tolerance: %s - %s, achieved: %s, trial result status: %s, trial result: %s)" %
                              (commify(tolerance_min),
                               commify(tolerance_max),
                               commify(trial_stats['global']['runtime']),
                               result_msg,
                               trial_result))

          if trial_stats['global']['early_exit']:
               trial_result = 'fail'
               bs_logger("\t(trial failed due to early exit, trial result status: modified, trial result: %s)" %
                         (trial_result))

          if trial_stats['global']['force_quit']:
               trial_result = 'quit'
               bs_logger("\t(received force quit, trial result status: modified, trial result: %s" %
                         (trial_result))
               return(trial_result)

     if trial_params['trial_mode'] == 'warmup':
          # when in warmup we want to ignore the results of the
          # validations, but it is potentially helpful to see the test
          # output so rather than short circuit we do all the tests but
          # then just report a passing result
          trial_result = 'pass'
          bs_logger("\t(since this was a warmup trial the actual results do not matter and are ignored, trial result status: modified, trial result: %s)" %
                    (trial_result))
          return(trial_result)
     else:
          return(trial_result)

def main():
    trial_results = { 'trials': [],
                      'log':    [] }

    bs_logger_exit = threading.Event()
    bs_logger_thread = threading.Thread(target = bs_logger_worker, args = (trial_results['log'], bs_logger_exit))
    bs_logger_thread.start()

    final_validation = t_global.args.one_shot == 1
    rate = t_global.args.rate

    if t_global.args.traffic_generator == 'null-txrx':
         random.seed()

    if t_global.args.traffic_generator == 'trex-txrx' and t_global.args.rate_unit == "%" and rate > 100.0:
         bs_logger("The trex-txrx traffic generator does not support a rate larger than 100.0 when --rate-unit=% since that equates to line rate")
         bs_logger_cleanup(bs_logger_exit, bs_logger_thread)
         return(1)

    if t_global.args.traffic_generator == 'null-txrx' and t_global.args.rate_unit == "mpps":
         bs_logger("The null-txrx traffic generator does not support --rate-unit=mpps")
         bs_logger_cleanup(bs_logger_exit, bs_logger_thread)
         return(1)

    if t_global.args.traffic_generator == 'trex-txrx-profile' and t_global.args.rate_unit == "mpps":
         bs_logger("The trex-txrx-profile traffic generator does not support --rate-unit=mpps")
         bs_logger_cleanup(bs_logger_exit, bs_logger_thread)
         return(1)

    if t_global.args.traffic_generator == 'null-txrx' and t_global.args.measure_latency:
         bs_logger("The null-txrx traffic generator does not support latency measurements")
         bs_logger_cleanup(bs_logger_exit, bs_logger_thread)
         return(1)

    if t_global.args.frame_size == "imix":
         if t_global.args.rate_unit == "mpps":
              bs_logger("When --frame-size=imix then --rate-unit must be set to %")
              bs_logger_cleanup(bs_logger_exit, bs_logger_thread)
              return(1)
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

    # make sure that the output directory exists
    if not os.path.isdir(trial_params['output_dir']):
         bs_logger("The specified output directory '%s' does not exist" % (trial_params['output_dir']))
         bs_logger_cleanup(bs_logger_exit, bs_logger_thread)
         return(1)
    else:
         # make sure that the output directory can be written to
         perm_test_path = "%s/perm.test" % (trial_params['output_dir'])
         try:
              perm_test_file = open(perm_test_path, 'w')
              print("testing permissions", file=perm_test_file)
              perm_test_file.close()
              os.unlink(perm_test_path)
         except IOError:
              bs_logger(error("Permissions test to output directory '%s' failed" % (trial_params['output_dir'])))
              bs_logger_cleanup(bs_logger_exit, bs_logger_thread)
              return(1)

    setup_config_var("traffic_generator", t_global.args.traffic_generator, trial_params)
    setup_config_var("rate", rate, trial_params)
    setup_config_var("runtime_tolerance", t_global.args.runtime_tolerance, trial_params)
    setup_config_var("rate_tolerance_failure", t_global.args.rate_tolerance_failure, trial_params)
    setup_config_var("rate_tolerance", t_global.args.rate_tolerance, trial_params)
    setup_config_var("negative_packet_loss_mode", t_global.args.negative_packet_loss_mode, trial_params)
    setup_config_var("duplicate_packet_failure_mode", t_global.args.duplicate_packet_failure_mode, trial_params)
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
    setup_config_var("repeat_final_validation", t_global.args.repeat_final_validation, trial_params)
    setup_config_var('warmup_trial', t_global.args.warmup_trial, trial_params)
    setup_config_var('warmup_trial_runtime', t_global.args.warmup_trial_runtime, trial_params)
    setup_config_var('disable_upward_search', t_global.args.disable_upward_search, trial_params)

    # set configuration from the argument parser
    if t_global.args.traffic_generator == "trex-txrx":
         setup_config_var("traffic_direction", t_global.args.traffic_direction, trial_params)
         setup_config_var("latency_traffic_direction", t_global.args.traffic_direction, trial_params)
         setup_config_var("num_flows", t_global.args.num_flows, trial_params)
         setup_config_var("frame_size", t_global.args.frame_size, trial_params)
         setup_config_var("use_src_mac_flows", t_global.args.use_src_mac_flows, trial_params)
         setup_config_var("use_dst_mac_flows", t_global.args.use_dst_mac_flows, trial_params)
         setup_config_var("use_src_ip_flows", t_global.args.use_src_ip_flows, trial_params)
         setup_config_var("use_dst_ip_flows", t_global.args.use_dst_ip_flows, trial_params)
         setup_config_var("use_src_port_flows", t_global.args.use_src_port_flows, trial_params)
         setup_config_var("use_dst_port_flows", t_global.args.use_dst_port_flows, trial_params)
         setup_config_var("src_macs", t_global.args.src_macs, trial_params)
         setup_config_var("dst_macs", t_global.args.dst_macs, trial_params)
         setup_config_var("src_ips", t_global.args.src_ips, trial_params)
         setup_config_var("dst_ips", t_global.args.dst_ips, trial_params)
         setup_config_var("src_ports", t_global.args.src_ports, trial_params)
         setup_config_var("dst_ports", t_global.args.dst_ports, trial_params)
         setup_config_var("vlan_ids", t_global.args.vlan_ids, trial_params)
         setup_config_var("use_protocol_flows", t_global.args.use_protocol_flows, trial_params)
         setup_config_var("packet_protocol", t_global.args.packet_protocol, trial_params)
         setup_config_var("stream_mode", t_global.args.stream_mode, trial_params)
         setup_config_var("enable_segment_monitor", t_global.args.enable_segment_monitor, trial_params)
         setup_config_var('teaching_warmup_packet_type', t_global.args.teaching_warmup_packet_type, trial_params)
         setup_config_var('teaching_measurement_packet_type', t_global.args.teaching_measurement_packet_type, trial_params)
         setup_config_var("use_device_stats", t_global.args.use_device_stats, trial_params)
         setup_config_var('send_teaching_warmup', t_global.args.send_teaching_warmup, trial_params)
         setup_config_var('send_teaching_measurement', t_global.args.send_teaching_measurement, trial_params)

    if t_global.args.traffic_generator == "trex-txrx" or t_global.args.traffic_generator == "trex-txrx-profile":
         setup_config_var("trex_host", t_global.args.trex_host, trial_params)
         setup_config_var("device_pairs", t_global.args.device_pairs, trial_params)
         setup_config_var('active_device_pairs', t_global.args.active_device_pairs, trial_params)
         setup_config_var("rate_unit", t_global.args.rate_unit, trial_params)
         setup_config_var("measure_latency", t_global.args.measure_latency, trial_params)
         setup_config_var("latency_rate", t_global.args.latency_rate, trial_params)
         setup_config_var('enable_flow_cache', t_global.args.enable_flow_cache, trial_params)
         setup_config_var('teaching_measurement_interval', t_global.args.teaching_measurement_interval, trial_params)
         setup_config_var('teaching_warmup_packet_rate', t_global.args.teaching_warmup_packet_rate, trial_params)
         setup_config_var('teaching_measurement_packet_rate', t_global.args.teaching_measurement_packet_rate, trial_params)
         setup_config_var('no_promisc', t_global.args.no_promisc, trial_params)
         setup_config_var('latency_device_pair', t_global.args.latency_device_pair, trial_params)

    if t_global.args.traffic_generator == "null-txrx":
         # empty for now
         foo = None

    if t_global.args.traffic_generator == "trex-txrx-profile":
         setup_config_var('random_seed', t_global.args.random_seed, trial_params)
         setup_config_var('traffic_profile', t_global.args.traffic_profile, trial_params)
         setup_config_var('warmup_traffic_profile', t_global.args.warmup_traffic_profile, trial_params)
         setup_config_var("enable_trex_profiler", t_global.args.enable_trex_profiler, trial_params)
         setup_config_var("trex_profiler_interval", t_global.args.trex_profiler_interval, trial_params)
         setup_config_var('process_all_profiler_data', t_global.args.process_all_profiler_data, trial_params)

         setup_config_var('traffic_direction', 'bidirectional', trial_params, config_tag = False, silent = True)

    if t_global.args.traffic_generator == "trex-txrx" and t_global.args.rate_unit == "%" and rate == 100.0:
         bs_logger("Disabling upward binary searching since the traffic generator is trex-txrx and the rate is 100% which is line rate")
         trial_params['disable_upward_search'] = True

    if t_global.args.traffic_generator == 'trex-txrx-profile':
         trial_params['loaded_traffic_profile'] = load_traffic_profile(traffic_profile = trial_params['traffic_profile'],
                                                                       rate_modifier = 100.0,
                                                                       log_function = bs_logger)
         if trial_params['loaded_traffic_profile'] == 1:
              bs_logger_cleanup(bs_logger_exit, bs_logger_thread)
              return(1)

         tmp_latency_traffic_direction = trial_params["loaded_traffic_profile"]["streams"][0]["traffic_direction"]
         if tmp_latency_traffic_direction != "bidirectional":
              for stream in trial_params['loaded_traffic_profile']['streams']:
                   if stream["traffic_direction"] != tmp_latency_traffic_direction:
                        tmp_latency_traffic_direction = "bidirectional"
                        break
         bs_logger("Configured via traffic profile introspection:")
         setup_config_var("latency_traffic_direction", tmp_latency_traffic_direction, trial_params)

         trial_params['loaded_warmup_traffic_profile'] = None
         if t_global.args.warmup_trial and len(t_global.args.warmup_traffic_profile):
              trial_params['loaded_warmup_traffic_profile'] = load_traffic_profile(traffic_profile = trial_params['warmup_traffic_profile'],
                                                                                   rate_modifier = 100.0,
                                                                                   log_function = bs_logger)
              if trial_params['loaded_warmup_traffic_profile'] == 1:
                   bs_logger_cleanup(bs_logger_exit, bs_logger_thread)
                   return(1)

              bs_logger("Loaded warmup traffic profile from %s:" % (trial_params['warmup_traffic_profile']))
              bs_logger(dump_json_readable(trial_params['loaded_warmup_traffic_profile']))

         bs_logger("Loaded traffic profile from %s:" % (trial_params['traffic_profile']))
         bs_logger(dump_json_readable(trial_params['loaded_traffic_profile']))

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
                                        'rx_latency_minimum':          0.0,
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

         if not isinstance(port_info, list) and 'retval' in port_info:
              bs_logger(error("Acquiring trex port info exited with a non-zero return value"))
              bs_logger_cleanup(bs_logger_exit, bs_logger_thread)
              return(1)

         trial_results['port_info'] = port_info

         for port in port_info:
              if port['speed'] == 0:
                   port_speed_verification_fail = True
                   bs_logger(error("Port with HW MAC %s failed speed verification test" % (port['hw_mac'])))
              else:
                   if port['driver'] == "net_ixgbe" and not trial_params['use_device_stats']:
                        bs_logger("WARNING: Forcing use of device stats instead of stream stats due to issue with Intel 82599/Niantic flow programming")
                        trial_params['use_device_stats'] = True

    if port_speed_verification_fail:
         bs_logger_cleanup(bs_logger_exit, bs_logger_thread)
         return(1)

    if len(trial_params['pre_trial_cmd']):
         if not os.path.isfile(trial_params['pre_trial_cmd']):
              bs_logger(error("The pre-trial-cmd file does not exist [%s]" % (trial_params['pre_trial_cmd'])))
              bs_logger_cleanup(bs_logger_exit, bs_logger_thread)
              return(1)

         if not os.access(trial_params['pre_trial_cmd'], os.X_OK):
              bs_logger(error("The pre-trial-cmd file is not executable [%s]" % (trial_params['pre_trial_cmd'])))
              bs_logger_cleanup(bs_logger_exit, bs_logger_thread)
              return(1)

    in_repeat_validation = False
    perform_sniffs = False
    do_sniff = False
    do_search = True
    do_warmup = False
    if t_global.args.sniff_runtime:
         perform_sniffs = True
         do_sniff = True
         do_search = False
    if t_global.args.warmup_trial:
         do_warmup = True
         final_validation = False
         do_sniff = False
         do_search = False

    trial_params['trial'] = 0

    minimum_rate = initial_rate * trial_params['search_granularity'] / 100
    if trial_params['min_rate'] != 0:
         minimum_rate = trial_params['min_rate']

    bs_logger("Starting binary-search") # this message triggers pbench to start default tools
    try:
         retries = 0
         # the actual binary search to find the maximum packet rate
         while final_validation or do_sniff or do_search or do_warmup:
              # support a longer measurement for the last trial, AKA "final validation"
              if final_validation:
                   trial_params['runtime'] = t_global.args.validation_runtime
                   trial_params['trial_mode'] = 'validation'
                   if in_repeat_validation:
                        bs_logger('\nTrial Mode: Repeat Final Validation')
                   else:
                        bs_logger('\nTrial Mode: Final Validation')
              elif do_search:
                   trial_params['runtime'] = t_global.args.search_runtime
                   trial_params['trial_mode'] = 'search'
                   bs_logger('\nTrial Mode: Search')
              elif do_sniff:
                   trial_params['runtime'] = t_global.args.sniff_runtime
                   trial_params['trial_mode'] = 'sniff'
                   bs_logger('\nTrial Mode: Sniff')
              elif do_warmup:
                   trial_params['runtime'] = t_global.args.warmup_trial_runtime
                   trial_params['trial_mode'] = 'warmup'
                   bs_logger('\nTrial Mode: Warmup')

              trial_params['rate'] = rate
              # run the actual trial
              trial_params['trial'] += 1
              stream_info = { 'streams': None }
              detailed_stats = { 'stats': None }

              bs_logger('running trial %03d, rate %s%s' % (trial_params['trial'], commify(trial_params['rate']), trial_params['rate_unit']))

              trial_params['pre_trial_cmd_output_file'] = None
              if len(trial_params['pre_trial_cmd']):
                   if execute_pre_trial_cmd(trial_params):
                        bs_logger(error("pre trial command exited with a non-zero return value"))
                        bs_logger_cleanup(bs_logger_exit, bs_logger_thread)
                        return(1)

              trial_stats = run_trial(trial_params, port_info, stream_info, detailed_stats)
              if trial_stats['retval']:
                   bs_logger(error("run trial command exited with a non-zero return value"))
                   bs_logger_cleanup(bs_logger_exit, bs_logger_thread)
                   return(1)

              trial_result = evaluate_trial(trial_params, trial_stats)
              if trial_result == 'quit':
                   return(1)

              if not in_repeat_validation:
                   trial_results['trials'].append({ 'trial': trial_params['trial'],
                                                    'rate': trial_params['rate'],
                                                    'rate_unit': trial_params['rate_unit'],
                                                    'result': trial_result,
                                                    'logfile': trial_params['trial_primary_output_file'],
                                                    'extra-logfile': trial_params['trial_secondary_output_file'],
                                                    'profiler-logfile': trial_params['trial_profiler_file'],
                                                    'pre-trial-cmd-logfile': trial_params['pre_trial_cmd_output_file'],
                                                    'profiler-data': None,
                                                    'stats': trial_stats,
                                                    'trial_params': copy.deepcopy(trial_params),
                                                    'stream_info': copy.deepcopy(stream_info['streams']),
                                                    'detailed_stats': copy.deepcopy(detailed_stats['stats']) })
              else:
                   bs_logger("Not appending stats because this is a repeat of the final validation")

              if trial_result == "pass":
                   if not do_warmup:
                        bs_logger('(trial passed all requirements)')
                   else:
                        bs_logger('(trial results are ignored since this is a warmup run)')
              elif trial_result == "retry-to-fail" or trial_result == "retry-to-quit":
                   if final_validation and in_repeat_validation:
                        bs_logger("Finished repeat final validation for debug collection") # this message triggers pbench to stop debug tools
                        break

                   bs_logger('(trial must be repeated because one or more requirements did not pass, but allow a retry)')

                   if retries >= trial_params['max_retries']:
                        if trial_result == "retry-to-quit":
                             bs_logger("\tEXCEPTION: The retry limit for a trial has been reached with quiting being the configured behavior.")
                             return(1)
                        elif trial_result == "retry-to-fail":
                             bs_logger("\tEXCEPTION: The retry limit for a trial has been reached with failing and continuing being the configured behavior.")
                             retries = 0
                             trial_result = "fail"
                   else:
                        # if trial_result is retry, then don't adjust anything and repeat
                        retries = retries + 1
              else:
                   bs_logger('(trial failed one or more requirements)')

              if t_global.args.one_shot == 1 and not do_warmup:
                   bs_logger("Finished binary-search") # this message triggers pbench to stop default tools
                   break

              if trial_result == "fail":
                   if final_validation:
                        if in_repeat_validation:
                             bs_logger("Finished repeat final validation for debug collection") # this message triggers pbench to stop debug tools
                             break
                        else:
                             final_validation = False
                             next_rate = rate - (trial_params['search_granularity'] * rate / 100) # subtracting by at least search_granularity percent avoids very small reductions in rate
                   else:
                        if len(prev_pass_rate) > 1 and rate < prev_pass_rate[len(prev_pass_rate)-1]:
                             # if the attempted rate drops below the most recent passing rate then that
                             # passing rate is considered a false positive and should be removed; ensure
                             # that at least the original passing rate (which is a special rate of 0) is never
                             # removed from the stack
                             bs_logger("Removing false positive passing result: %s" % (commify(prev_pass_rate.pop())))
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
                   if in_repeat_validation or do_warmup:
                        debug_stats = trial_stats
                   else:
                        passed_stats = trial_stats

                   if final_validation: # no longer necessary to continue searching
                        if initial_rate == rate and not trial_params['disable_upward_search']:
                             bs_logger("Detected requested rate is too low, doubling rate and restarting search")

                             final_validation = False

                             if perform_sniffs:
                                  do_sniff = True
                                  do_search = False
                             else:
                                  do_sniff = False
                                  do_search = True

                             rate = 2 * initial_rate
                             if t_global.args.traffic_generator == "trex-txrx" and t_global.args.rate_unit == "%" and rate >= 100.0:
                                  bs_logger("Limiting upward search to maximum of 100% when traffic generator is trex-txrx (line rate)")
                                  rate = 100.0
                                  bs_logger("Disabling upward binary searching since the traffic generator is trex-txrx and the rate is 100% which is line rate")
                                  trial_params['disable_upward_search'] = True
                             initial_rate = rate
                             prev_rate = 0
                             prev_pass_rate = [0]
                             prev_fail_rate = rate
                             retries = 0
                        else:
                             if trial_params['repeat_final_validation']:
                                  if in_repeat_validation:     
                                       # the repeat of the final validation is done, so stop running trials
                                       bs_logger("Finished repeat final validation for debug collection") # this message triggers pbench to stop debug tools
                                       break
                                  else:    
                                       # normally we would be done, but user wants to rerun final validation trial to collect invasive tool or debug information
                                       # when running in this mode, ignore pass/fail logic after the trial by setting in_repeat_validation = True
                                       in_repeat_validation = True      
                                       bs_logger("Finished binary-search") # this message triggers pbench to stop default tools
                                       bs_logger("Starting repeat final validation for debug collection") # this message triggers pbench to stop debug tools
                             else:
                                  bs_logger("Finished binary-search") # this message triggers pbench to stop default tools
                                  break
                   else:
                        if do_warmup:
                             do_warmup = False
                             if t_global.args.one_shot == 1:
                                  final_validation = True
                             else:
                                  if perform_sniffs:
                                       do_sniff = True
                                  else:
                                       do_search = True
                             next_rate = rate # since this was only the warmup, keep the current rate
                        elif do_sniff:
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
                   bs_logger("Setting the rate to the minimum allowed by the search granularity as a last attempt at passing.")
                   prev_rate = rate
                   rate = minimum_rate
              elif (rate == minimum_rate or prev_rate <= minimum_rate) and trial_result == 'fail':
                   bs_logger("Binary search ended up at rate which is below minimum allowed")
                   bs_logger("There is no trial which passed")
                   failed_stats = []

                   if t_global.args.traffic_generator == 'null-txrx':
                        failed_stats.append(copy.deepcopy(trial_params['null_stats']))
                        failed_stats.append(copy.deepcopy(trial_params['null_stats']))
                   elif t_global.args.traffic_generator == 'trex-txrx' or t_global.args.traffic_generator == 'trex-txrx-profile':
                        port = 0
                        while port <= trial_params['max_port']:
                             failed_stats.append(copy.deepcopy(trial_params['null_stats']))
                             port += 1

                   bs_logger("RESULT:")
                   print_stats(trial_params, failed_stats)
                   return(0)

              if t_global.args.trial_gap:
                   bs_logger("Sleeping for %s seconds between trial attempts" % (commify(t_global.args.trial_gap)))
                   time.sleep(t_global.args.trial_gap)

         bs_logger("RESULT:")
         if prev_pass_rate[len(prev_pass_rate)-1] != 0: # show the stats for the most recent passing trial
              print_stats(trial_params, passed_stats)
         else:
              if t_global.args.one_shot == 1:
                   print_stats(trial_params, trial_stats)
              else:
                   bs_logger("There is no trial which passed")

    finally:
         if trial_params['traffic_generator'] == 'trex-txrx-profile' and trial_params['enable_trex_profiler'] and len(trial_results['trials']):
              bs_logger("Processing profiler data")
              for trial_result_idx in range(0, len(trial_results['trials'])):
                   # unless told otherwise, only the last trial's profiler data will be processed
                   # this serves to conserve processing time and storage space in frameworks where the data will not be used
                   if (not trial_params['process_all_profiler_data']) and (trial_result_idx != (len(trial_results['trials']) - 1)):
                        bs_logger("\tSkipping processing of profiler data for trial %d" % (trial_results['trials'][trial_result_idx]['trial']))
                        continue

                   profile_file = "%s/%s" % (trial_params['output_dir'], trial_results['trials'][trial_result_idx]['profiler-logfile'])
                   if os.path.isfile(profile_file):
                        bs_logger("\tProcessing profiler data for trial %d from %s" % (trial_results['trials'][trial_result_idx]['trial'], profile_file))

                        trial_results['trials'][trial_result_idx]['profiler-data'] = trex_profiler_postprocess_file(profile_file)

                        # since we have profiler data for this trial, update the trial start/stop timestamps
                        # with the first and last values from the profiler which should be more accurate
                        timestamps = sorted(trial_results['trials'][trial_result_idx]['profiler-data'])
                        trial_results['trials'][trial_result_idx]['trial_start'] = timestamps[0]
                        trial_results['trials'][trial_result_idx]['trial_stop']  = timestamps[len(timestamps) - 1]

                        bs_logger("\t\tProfiler data processing complete")
                   else:
                        bs_logger("\t%s" % (error("Could not open trial %d's profiler data file (%s) for processing because it does not exist" % (trial_results['trials'][trial_result_idx]['trial'], profiler_file))))

              # compress the profiler data for all trials to save
              # space (potentially a lot)
              bs_logger("Compressing profiler data for all trials")
              for trial_result in trial_results['trials']:
                   output = ""
                   profile_file = "%s/%s" % (trial_params['output_dir'], trial_result['profiler-logfile'])
                   if os.path.isfile(profile_file):
                        try:
                             bs_logger("\tCompressing %s" % (trial_result['profiler-logfile']))
                             output = subprocess.check_output(["xz", "-9", "--threads=0", "--verbose", profile_file], stderr=subprocess.STDOUT)
                             bs_logger("\t\t%s" % (output.decode()))
                        except subprocess.CalledProcessError as e:
                             bs_logger("\tError compressing %s (return code = %d)" % (trial_result['profiler-logfile'], e.returncode))
                             bs_logger(e.output)
                   else:
                        bs_logger(error("Could not compress profiler data file %s because it does not exist" % (profiler_file)))

         trial_json_filename = "%s/binary-search.json" % (trial_params['output_dir'])
         try:
              trial_json_file = open(trial_json_filename, 'w')

              # drain the log prior to writing out the file
              bs_logger_cleanup(bs_logger_exit, bs_logger_thread)

              print(dump_json_readable(trial_results), file=trial_json_file)
              trial_json_file.close()
         except IOError:
              bs_logger(error("Could not open %s for writing" % (trial_json_filename)))
              bs_logger("TRIALS:")
              bs_logger(dump_json_readable(trial_results))

              bs_logger_cleanup(bs_logger_exit, bs_logger_thread)

if __name__ == "__main__":
    process_options()
    bs_logger(str(t_global.args))

    # only import the posix_ipc library if traffic generator
    # synchronization needs to be managed.
    # imports must be done at the module level which is why this is
    # done here instead of in main()
    if t_global.args.latency_device_pair != '--':
         bs_logger("Enabling traffic generator synchronization")
         import posix_ipc

    exit(main())

