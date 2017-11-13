from __future__ import print_function

import sys, getopt
sys.path.append('/opt/trex/current/automation/trex_control_plane/stl/examples')
sys.path.append('/opt/trex/current/automation/trex_control_plane/stl')
import argparse
import stl_path
import json
import string
import datetime
import math
import threading
import thread
from decimal import *
from trex_stl_lib.api import *

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

def not_json_serializable(obj):
     return "not JSON serializable"

def dump_json_readable(obj):
     return json.dumps(obj, indent = 4, separators=(',', ': '), sort_keys = True, default = not_json_serializable)

def dump_json_parsable(obj):
     return json.dumps(obj, separators=(',', ':'), default = not_json_serializable)

def ip_to_int (ip):
    ip_fields = ip.split(".")
    if len(ip_fields) != 4:
         raise ValueError("IP addresses should be in the form of W.X.Y.Z")
    ip_int = 256**3 * int(ip_fields[0]) + 256**2 * int(ip_fields[1]) + 256**1 * int(ip_fields[2]) + int(ip_fields[3])
    return ip_int

def calculate_latency_pps (dividend, divisor, total_rate, protocols):
     return int((float(dividend) / float(divisor) * total_rate / protocols))

def create_traffic_profile (direction, device_pair, rate_multiplier, port_speed, rate_unit, run_time, stream_mode, measure_latency, latency_rate, frame_size, num_flows, src_mac_flows, dst_mac_flows, src_ip_flows, dst_ip_flows, src_port_flows, dst_port_flows, protocol_flows, packet_protocol, skip_hw_flow_stats):
     streams = { 'default': { 'protocol': [],
                              'pps': [],
                              'pg_ids': [],
                              'names': [],
                              'next_stream_names': [],
                              'frame_sizes': [],
                              'traffic_shares': [],
                              'self_starts': [],
                              'run_time': [],
                              'stream_modes': [] } }
     streams['latency'] = copy.deepcopy(streams['default'])

     profile_streams = []

     # packet overhead is (7 byte preamable + 1 byte SFD -- Start of Frame Delimiter -- + 12 byte IFG -- Inter Frame Gap)
     packet_overhead_bytes = 20
     ethernet_frame_overhead = 18
     bits_per_byte = 8

     protocols = [ packet_protocol ]
     if protocol_flows:
          if packet_protocol == "UDP":
               protocols.append("TCP")
          elif packet_protocol == "TCP":
               protocols.append("UDP")

     for protocols_index, protocols_value in enumerate(protocols):
          if frame_size == "imix" and stream_mode == "continuous":
               # imix is defined as the following packets (including IP header): 7 of size 40 bytes, 4 of size 576 bytes, and 1 of size 1500 bytes
               # from https://en.wikipedia.org/wiki/Internet_Mix

               small_packets = 7
               medium_packets = 4
               large_packets = 1
               total_packets = small_packets + medium_packets + large_packets

               small_packet_bytes = 40 + ethernet_frame_overhead
               medium_packet_bytes = 576 + ethernet_frame_overhead
               large_packet_bytes = 1500 + ethernet_frame_overhead

               small_stream_pg_id = device_pair[direction]['pg_ids']['default']['start_index'] + protocols_index
               medium_stream_pg_id = device_pair[direction]['pg_ids']['default']['start_index'] + 2 + protocols_index
               large_stream_pg_id = device_pair[direction]['pg_ids']['default']['start_index'] + 4 + protocols_index

               small_stream_name = "small_stream_" + direction + "_" + protocols_value
               medium_stream_name = "medium_stream_" + direction + "_" + protocols_value
               large_stream_name = "large_stream_" + direction + "_" + protocols_value

               streams['default']['protocol'].extend([protocols_value, protocols_value, protocols_value])
               streams['default']['pps'].extend([small_packets, medium_packets, large_packets])
               streams['default']['pg_ids'].extend([small_stream_pg_id, medium_stream_pg_id, large_stream_pg_id])
               streams['default']['names'].extend([small_stream_name, medium_stream_name, large_stream_name])
               streams['default']['next_stream_names'].extend([None, None, None])
               streams['default']['frame_sizes'].extend([small_packet_bytes, medium_packet_bytes, large_packet_bytes])
               streams['default']['traffic_shares'].extend([(float(small_packets)/float(total_packets)/len(protocols)), (float(medium_packets)/float(total_packets)/len(protocols)), (float(large_packets)/float(total_packets)/len(protocols))])
               streams['default']['self_starts'].extend([True, True, True])
               streams['default']['stream_modes'].extend(["continuous", "continuous", "continuous"])
               streams['default']['run_time'].extend([-1, -1, -1])

               if measure_latency:
                    small_latency_stream_pg_id = device_pair[direction]['pg_ids']['latency']['start_index'] + protocols_index
                    medium_latency_stream_pg_id = device_pair[direction]['pg_ids']['latency']['start_index'] + 2 + protocols_index
                    large_latency_stream_pg_id = device_pair[direction]['pg_ids']['latency']['start_index'] + 4 + protocols_index

                    small_latency_stream_name = "small_latency_stream_" + direction + "_" + protocols_value
                    medium_latency_stream_name = "medium_latency_stream_" + direction + "_" + protocols_value
                    large_latency_stream_name = "large_latency_stream_" + direction + "_" + protocols_value

                    streams['latency']['protocol'].extend([protocols_value, protocols_value, protocols_value])
                    streams['latency']['pps'].extend([calculate_latency_pps(small_packets, total_packets, latency_rate, len(protocols)), calculate_latency_pps(medium_packets, total_packets, latency_rate, len(protocols)), calculate_latency_pps(large_packets, total_packets, latency_rate, len(protocols))])
                    streams['latency']['pg_ids'].extend([small_latency_stream_pg_id, medium_latency_stream_pg_id, large_latency_stream_pg_id])
                    streams['latency']['names'].extend([small_latency_stream_name, medium_latency_stream_name, large_latency_stream_name])
                    streams['latency']['next_stream_names'].extend([None, None, None])
                    streams['latency']['frame_sizes'].extend([small_packet_bytes, medium_packet_bytes, large_packet_bytes])
                    streams['latency']['traffic_shares'].extend([(float(small_packets)/float(total_packets)/len(protocols)), (float(medium_packets)/float(total_packets)/len(protocols)), (float(large_packets)/float(total_packets)/len(protocols))])
                    streams['latency']['self_starts'].extend([True, True, True])
                    streams['latency']['stream_modes'].extend(["continuous", "continuous", "continuous"])
                    streams['latency']['run_time'].extend([-1, -1, -1])

          elif frame_size == "imix" and stream_mode == "segmented":
               print("Support for segmented IMIX needs to be coded...")
          elif stream_mode == "continuous":
               default_stream_pg_id = device_pair[direction]['pg_ids']['default']['start_index'] + protocols_index

               default_stream_name = "default_stream_" + direction + "_" + protocols_value

               streams['default']['protocol'].extend([protocols_value])
               streams['default']['pps'].extend([100])
               streams['default']['pg_ids'].extend([default_stream_pg_id])
               streams['default']['names'].extend([default_stream_name])
               streams['default']['next_stream_names'].extend([None])
               streams['default']['frame_sizes'].extend([int(frame_size)])
               streams['default']['traffic_shares'].extend([1.0/len(protocols)])
               streams['default']['self_starts'].extend([True])
               streams['default']['stream_modes'].extend(["continuous"])
               streams['default']['run_time'].extend([-1])

               if measure_latency:
                    latency_stream_pg_id = device_pair[direction]['pg_ids']['latency']['start_index'] + protocols_index

                    latency_stream_name = "latency_stream_" + direction + "_" + protocols_value

                    streams['latency']['protocol'].extend([protocols_value])
                    streams['latency']['pps'].extend([latency_rate/len(protocols)])
                    streams['latency']['pg_ids'].extend([latency_stream_pg_id])
                    streams['latency']['names'].extend([latency_stream_name])
                    streams['latency']['next_stream_names'].extend([None])
                    streams['latency']['frame_sizes'].extend([int(frame_size)])
                    streams['latency']['traffic_shares'].extend([1.0/len(protocols)])
                    streams['latency']['self_starts'].extend([True])
                    streams['latency']['stream_modes'].extend(["continuous"])
                    streams['latency']['run_time'].extend([-1])
          elif stream_mode == "segmented":
               stream_types = [ "default" ]
               if measure_latency:
                    stream_types.append("latency")

               for streams_type_index, streams_type_value in enumerate(stream_types):
                    if len(protocols) > 1 and (device_pair[direction]['pg_ids'][streams_type_value]['available'] % 2) != 0:
                         device_pair[direction]['pg_ids'][streams_type_value]['available'] -= 1

                    min_pg_id = device_pair[direction]['pg_ids'][streams_type_value]['start_index'] + protocols_index
                    max_pg_id = device_pair[direction]['pg_ids'][streams_type_value]['start_index'] + device_pair[direction]['pg_ids'][streams_type_value]['available']

                    counter=1
                    for current_pg_id in range(min_pg_id, max_pg_id, len(protocols)):
                         stream_name_prefix = streams_type_value + "_stream_" + direction + "_" + protocols_value + "_segment_"

                         stream_name = stream_name_prefix + str(counter)

                         next_stream_name = None
                         if (current_pg_id + len(protocols)) < max_pg_id:
                              next_stream_name = stream_name_prefix + str(counter+1)

                         self_start = False
                         if current_pg_id == min_pg_id:
                              self_start = True

                         streams[streams_type_value]['protocol'].extend([protocols_value])
                         if streams_type_value == "latency":
                              streams[streams_type_value]['pps'].extend([latency_rate/len(protocols)])
                         else:
                              if rate_unit == "mpps":
                                   streams[streams_type_value]['pps'].extend([rate_multiplier/len(protocols)*1000000])
                              else:
                                   streams[streams_type_value]['pps'].extend([((rate_multiplier/100)/len(protocols)) * (port_speed / bits_per_byte) / (int(frame_size) + packet_overhead_bytes)])
                         streams[streams_type_value]['pg_ids'].extend([current_pg_id])
                         streams[streams_type_value]['names'].extend([stream_name])
                         streams[streams_type_value]['next_stream_names'].extend([next_stream_name])
                         streams[streams_type_value]['frame_sizes'].extend([int(frame_size)])
                         streams[streams_type_value]['traffic_shares'].extend([1.0/device_pair[direction]['pg_ids'][streams_type_value]["available"]])
                         streams[streams_type_value]['self_starts'].extend([self_start])
                         streams[streams_type_value]['stream_modes'].extend(["burst"])
                         streams[streams_type_value]['run_time'].extend([float(run_time)/(device_pair[direction]['pg_ids'][streams_type_value]["available"]/len(protocols))])

                         counter += 1

     for streams_index, streams_packet_type in enumerate(streams):
          for stream_packet_protocol, stream_pps, stream_pg_id, stream_name, stream_frame_size, stream_traffic_share, stream_next_stream_name, stream_self_start, stream_mode, stream_run_time in zip(streams[streams_packet_type]['protocol'], streams[streams_packet_type]['pps'], streams[streams_packet_type]['pg_ids'], streams[streams_packet_type]['names'], streams[streams_packet_type]['frame_sizes'], streams[streams_packet_type]['traffic_shares'], streams[streams_packet_type]['next_stream_names'], streams[streams_packet_type]['self_starts'], streams[streams_packet_type]['stream_modes'], streams[streams_packet_type]['run_time']):
               myprint("Creating stream with packet_type=[%s], protocol=[%s], pps=[%f], pg_id=[%d], name=[%s], frame_size=[%d], next_stream_name=[%s], self_start=[%s], stream_mode=[%s], run_time=[%f], and traffic_share=[%f]." %
                       (streams_packet_type,
                        stream_packet_protocol,
                        stream_pps,
                        stream_pg_id,
                        stream_name,
                        stream_frame_size,
                        stream_next_stream_name,
                        stream_self_start,
                        stream_mode,
                        stream_run_time,
                        stream_traffic_share))

               stream_flow_stats = None
               if streams_packet_type == "default" and not skip_hw_flow_stats:
                    stream_flow_stats = STLFlowStats(pg_id = stream_pg_id)
               elif streams_packet_type == "latency":
                    stream_flow_stats = STLFlowLatencyStats(pg_id = stream_pg_id)
               device_pair[direction]['pg_ids'][streams_packet_type]['list'].append(stream_pg_id)

               if stream_mode == "burst":
                    stream_mode_obj = STLTXSingleBurst(pps = stream_pps, total_pkts = int(stream_run_time * stream_pps))
               elif stream_mode == "continuous":
                    stream_mode_obj = STLTXCont(pps = stream_pps)

               profile_streams.append(STLStream(packet = create_pkt(stream_frame_size, num_flows, src_mac_flows, dst_mac_flows, src_ip_flows, dst_ip_flows, src_port_flows, dst_port_flows, device_pair[direction]['packet_values']['macs']['src'], device_pair[direction]['packet_values']['macs']['dst'], device_pair[direction]['packet_values']['ips']['src'], device_pair[direction]['packet_values']['ips']['dst'], device_pair[direction]['packet_values']['ports']['src'], device_pair[direction]['packet_values']['ports']['dst'], stream_packet_protocol, device_pair[direction]['packet_values']['vlan']),
                                                flow_stats = stream_flow_stats,
                                                mode = stream_mode_obj,
                                                name = stream_name,
                                                next = stream_next_stream_name,
                                                self_start = stream_self_start))

     myprint("DEVICE PAIR %d:%d | READABLE STREAMS FOR DIRECTION '%s':" % (device_pair['a']['port_index'], device_pair['b']['port_index'], direction), stderr_only = True)
     myprint(dump_json_readable(streams), stderr_only = True)
     myprint("DEVICE PAIR %d:%d | PARSABLE STREAMS FOR DIRECTION '%s': %s" % (device_pair['a']['port_index'], device_pair['b']['port_index'], direction, dump_json_parsable(streams)), stderr_only = True)

     return STLProfile(profile_streams)

# simple packet creation
def create_pkt (size, num_flows, src_mac_flows, dst_mac_flows, src_ip_flows, dst_ip_flows, src_port_flows, dst_port_flows, mac_src, mac_dst, ip_src, ip_dst, port_src, port_dst, packet_protocol, vlan_id):
    # adjust packet size
    size = int(size)
    size -= 4

    port_range = { "start": 0, "end": 65535 }
    if num_flows > 1 and (src_port_flows or dst_port_flows):
         if num_flows < 1000:
              num_flows_divisor = num_flows
         elif (num_flows % 1000) == 0:
              num_flows_divisor = 1000
         elif (num_flows % 1024 == 0):
              num_flows_divisor = 1024

         if (port_src + num_flows_divisor) > port_range["end"]:
              port_start = port_range["end"] - num_flows_divisor + 1
              port_end = port_range["end"]
         else:
              port_start = port_src
              port_end = port_src + num_flows_divisor - 1

         port_src = { "start": port_start, "end": port_end, "init": port_src }

         if (port_dst + num_flows_divisor) > port_range["end"]:
              port_start = port_range["end"] - num_flows_divisor + 1
              port_end = port_range["end"]
         else:
              port_start = port_dst
              port_end = port_dst + num_flows_divisor - 1

         port_dst = { "start": port_start, "end": port_end, "init": port_dst }
    else:
         port_src = { "init": port_src }
         port_dst = { "init": port_dst }

    num_flows -= 1

    ip_src = { "start": ip_to_int(ip_src), "end": ip_to_int(ip_src) + num_flows }
    ip_dst = { "start": ip_to_int(ip_dst), "end": ip_to_int(ip_dst) + num_flows }

    vm = []
    if src_ip_flows and num_flows:
        vm = vm + [
            STLVmFlowVar(name="ip_src",min_value=ip_src['start'],max_value=ip_src['end'],size=4,op="inc"),
            STLVmWrFlowVar(fv_name="ip_src",pkt_offset= "IP.src")
        ]

    if dst_ip_flows and num_flows:
        vm = vm + [
            STLVmFlowVar(name="ip_dst",min_value=ip_dst['start'],max_value=ip_dst['end'],size=4,op="inc"),
            STLVmWrFlowVar(fv_name="ip_dst",pkt_offset= "IP.dst")
        ]

    if src_mac_flows and num_flows:
        vm = vm + [
            STLVmFlowVar(name="mac_src",min_value=0,max_value=num_flows,size=4,op="inc"),
            STLVmWrFlowVar(fv_name="mac_src",pkt_offset=7)
        ]

    if dst_mac_flows and num_flows:
        vm = vm + [
            STLVmFlowVar(name="mac_dst",min_value=0,max_value=num_flows,size=4,op="inc"),
            STLVmWrFlowVar(fv_name="mac_dst",pkt_offset=1)
        ]

    if src_port_flows and num_flows:
        vm = vm + [
            STLVmFlowVar(name = "port_src", init_value = port_src['init'], min_value = port_src['start'], max_value = port_src['end'], size = 2, op = "inc"),
            STLVmWrFlowVar(fv_name = "port_src", pkt_offset = packet_protocol + ".sport"),
        ]

    if dst_port_flows and num_flows:
        vm = vm + [
            STLVmFlowVar(name = "port_dst", init_value = port_dst['init'], min_value = port_dst['start'], max_value = port_dst['end'], size = 2, op = "inc"),
            STLVmWrFlowVar(fv_name = "port_dst", pkt_offset = packet_protocol + ".dport"),
        ]

    base = Ether(src = mac_src, dst = mac_dst)

    if vlan_id is not None:
        base = base/Dot1Q(vlan = vlan_id)

    base = base/IP(src = str(ip_src['start']), dst = str(ip_dst['start']))

    if packet_protocol == "UDP":
         base = base/UDP(sport = port_src['init'], dport = port_dst['init'] )
    elif packet_protocol == "TCP":
         base = base/TCP(sport = port_src['init'], dport = port_dst['init'] )
    pad = max(0, size-len(base)) * 'x'

    the_packet = base/pad
    #the_packet.show2()

    if num_flows and (src_ip_flows or dst_ip_flows or src_mac_flows or dst_mac_flows or src_port_flows or dst_port_flows):
         if packet_protocol == "UDP":
              vm = vm + [STLVmFixChecksumHw(l3_offset="IP",l4_offset="UDP",l4_type=CTRexVmInsFixHwCs.L4_TYPE_UDP)]
         elif packet_protocol == "TCP":
              vm = vm + [STLVmFixChecksumHw(l3_offset="IP",l4_offset="TCP",l4_type=CTRexVmInsFixHwCs.L4_TYPE_TCP)]
         return STLPktBuilder(pkt = the_packet,
                              vm  = vm)
    else:
         return STLPktBuilder(pkt = the_packet)


def process_options ():
    parser = argparse.ArgumentParser(usage=""" 
    generate network traffic and report packet loss
    """);

    parser.add_argument('--mirrored-log',
                        dest='mirrored_log',
                        help='Should the logging sent to STDOUT be mirrored on STDERR',
                        action = 'store_true',
                        )
    parser.add_argument('--size', 
                        dest='frame_size',
                        help='L2 frame size in bytes or IMIX',
                        default=64
                        )
    parser.add_argument('--device-pairs',
                        dest='device_pairs',
                        help='List of device pairs in the for A:B[,C:D][,E:F][,...]',
                        default="0:1",
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
                        help='implement flows by dst MAC',
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
    #parser.add_argument('--use-encap-ip-flows',
    #                    dest='use_encap_ip_flows',
    #                    help='implement flows by IP in the encapsulated packet',
    #                    default=0,
    #                    type = int,
    #                    )
    #parser.add_argument('--use-encap-mac-flows',
    #                    dest="use_encap_mac_flows",
    #                    help='implement flows by MAC in the encapsulated packet',
    #                    default=0,
    #                    type = int,
    #                    )
    parser.add_argument('--run-bidirec', 
                        dest='run_bidirec',
                        help='0 = Tx on first device, 1 = Tx on both devices',
                        default=1,
                        type = int,
                        )
    parser.add_argument('--run-revunidirec',
                        dest='run_revunidirec',
                        help='0 = Tx on first device, 1 = Tx on second devices',
                        default=0,
                        type = int,
                        )
    parser.add_argument('--runtime', 
                        dest='runtime',
                        help='trial period in seconds',
                        default=30,
                        type = int,
                        )
    parser.add_argument('--runtime-tolerance',
                        dest='runtime_tolerance',
                        help='The percentage of time that the test is allowed in excess of the requested runtime before it is stopped',
                        default=5,
                        type = float,
                        )
    parser.add_argument('--rate', 
                        dest='rate',
                        help='rate per device',
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
    parser.add_argument('--src-ports-list',
                        dest='src_ports_list',
                        help='comma separated list of source ports, 1 per device',
                        default=""
                        )
    parser.add_argument('--dst-ports-list',
                        dest='dst_ports_list',
                        help='comma separated list of destination ports, 1 per device',
                        default=""
                        )
    parser.add_argument('--dst-macs-list',
                        dest='dst_macs_list',
                        help='comma separated list of destination MACs, 1 per device',
                        default=""
                        )
    parser.add_argument('--src-macs-list',
                        dest='src_macs_list',
                        help='comma separated list of src MACs, 1 per device',
                        default=""
                        )
    #parser.add_argument('--encap-dst-macs-list',
    #                    dest='encap_dst_macs_list',
    #                    help='comma separated list of destination MACs for encapulsated network, 1 per device',
    #                    default=""
    #                    )
    #parser.add_argument('--encap-src-macs-list',
    #                    dest='encap_src_macs_list',
    #                    help='comma separated list of src MACs for encapulsated network, 1 per device',
    #                    default=""
    #                    )
    parser.add_argument('--dst-ips-list',
                        dest='dst_ips_list',
                        help='comma separated list of destination IPs 1 per device',
                        default=""
                        )
    parser.add_argument('--src-ips-list',
                        dest='src_ips_list',
                        help='comma separated list of src IPs, 1 per device',
                        default=""
                        )
    parser.add_argument('--vlan-ids-list',
                        dest='vlan_ids_list',
                        help='A list of VLAN IDs to use for Tx, one per device',
                        default = "",
                   )
    #parser.add_argument('--encap-dst-ips-list',
    #                    dest='encap_dst_macs_list',
    #                    help='comma separated list of destination IPs for excapsulated network, 1 per device',
    #                    default=""
    #                    )
    #parser.add_argument('--encap-src-ips-list',
    #                    dest='encap_src_macs_list',
    #                    help='comma separated list of src IPs for excapsulated network,, 1 per device',
    #                    default=""
    #                    )
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
    parser.add_argument('--stream-mode',
                        dest='stream_mode',
                        help='How the packet streams are constructed',
                        default = "continuous",
                        choices = [ 'continuous', 'segmented' ]
                        )
    parser.add_argument('--skip-hw-flow-stats',
                        dest='skip_hw_flow_stats',
                        help='Should hardware flow stat support be used',
                        action = 'store_true',
                        )
    parser.add_argument('--enable-segment-monitor',
                        dest='enable_segment_monitor',
                        help='Should individual segments be monitored for pass/fail status relative to --max-loss-pct in order to short circuit trials',
                        action = 'store_true',
                        )
    parser.add_argument('--max-loss-pct',
                        dest='max_loss_pct',
                        help='Maximum percentage of packet loss',
                        default=0.002,
                        type = float
                        )

    t_global.args = parser.parse_args();
    if t_global.args.frame_size == "IMIX":
         t_global.args.frame_size = "imix"
    myprint(t_global.args)

def segment_monitor(connection, device_pairs, all_ports, unidirec_ports, revunidirec_ports, bidirec, revunidirec, measure_latency, max_loss_pct, normal_exit_event, early_exit_event):
    try:
         myprint("Segment Monitor: Running")

         directions = [ 'a', 'b' ]
         for device_pair in device_pairs:
              for direction in directions:
                   if device_pair[direction]['active']:
                        device_pair[direction]['pg_ids']['default']['current_index'] = 2

                        if measure_latency:
                             device_pair[direction]['pg_ids']['latency']['current_index'] = 2

         analyzed_pg_ids = dict()

         while not normal_exit_event.is_set():
              time.sleep(1)

              #myprint("")
              for device_pair in device_pairs:
                   #myprint("Analyzing device pair %d:%d" % (device_pair['a']['port_index'], device_pair['b']['port_index']))
                   pg_id_list = []
                   pg_id_details = dict()
                   if not revunidirec:
                        if device_pair['a']['pg_ids']['default']['current_index'] <= (len(device_pair['a']['pg_ids']['default']['list']) - 1):
                             #myprint("Found default candidate %d for 'a'" % device_pair['a']['pg_ids']['default']['list'][device_pair['a']['pg_ids']['default']['current_index']])
                             pg_id_list.append(device_pair['a']['pg_ids']['default']['list'][device_pair['a']['pg_ids']['default']['current_index']])
                             pg_id_details[str(device_pair['a']['pg_ids']['default']['list'][device_pair['a']['pg_ids']['default']['current_index']])] = dict()
                             pg_id_details[str(device_pair['a']['pg_ids']['default']['list'][device_pair['a']['pg_ids']['default']['current_index']])]['direction'] = 'a'
                             pg_id_details[str(device_pair['a']['pg_ids']['default']['list'][device_pair['a']['pg_ids']['default']['current_index']])]['type'] = 'default'

                        if measure_latency and device_pair['a']['pg_ids']['latency']['current_index'] <= (len(device_pair['a']['pg_ids']['latency']['list']) - 1):
                             #myprint("Found latency candidate %d for 'a'" % device_pair['a']['pg_ids']['latency']['list'][device_pair['a']['pg_ids']['latency']['current_index']])
                             pg_id_list.append(device_pair['a']['pg_ids']['latency']['list'][device_pair['a']['pg_ids']['latency']['current_index']])
                             pg_id_details[str(device_pair['a']['pg_ids']['latency']['list'][device_pair['a']['pg_ids']['latency']['current_index']])] = dict()
                             pg_id_details[str(device_pair['a']['pg_ids']['latency']['list'][device_pair['a']['pg_ids']['latency']['current_index']])]['direction'] = 'a'
                             pg_id_details[str(device_pair['a']['pg_ids']['latency']['list'][device_pair['a']['pg_ids']['latency']['current_index']])]['type'] = 'latency'

                   if revunidirec or bidirec:
                        if device_pair['b']['pg_ids']['default']['current_index'] <= (len(device_pair['b']['pg_ids']['default']['list']) - 1):
                             #myprint("Found default candidate %d for 'b'" % device_pair['b']['pg_ids']['default']['list'][device_pair['b']['pg_ids']['default']['current_index']])
                             pg_id_list.append(device_pair['b']['pg_ids']['default']['list'][device_pair['b']['pg_ids']['default']['current_index']])
                             pg_id_details[str(device_pair['b']['pg_ids']['default']['list'][device_pair['b']['pg_ids']['default']['current_index']])] = dict()
                             pg_id_details[str(device_pair['b']['pg_ids']['default']['list'][device_pair['b']['pg_ids']['default']['current_index']])]['direction'] = 'b'
                             pg_id_details[str(device_pair['b']['pg_ids']['default']['list'][device_pair['b']['pg_ids']['default']['current_index']])]['type'] = 'default'

                        if measure_latency and device_pair['b']['pg_ids']['latency']['current_index'] <= (len(device_pair['a']['pg_ids']['latency']['list']) - 1):
                             #myprint("Found latency candidate %d for 'b'" % device_pair['b']['pg_ids']['latency']['list'][device_pair['b']['pg_ids']['latency']['current_index']])
                             pg_id_list.append(device_pair['b']['pg_ids']['latency']['list'][device_pair['b']['pg_ids']['latency']['current_index']])
                             pg_id_details[str(device_pair['b']['pg_ids']['latency']['list'][device_pair['b']['pg_ids']['latency']['current_index']])] = dict()
                             pg_id_details[str(device_pair['b']['pg_ids']['latency']['list'][device_pair['b']['pg_ids']['latency']['current_index']])]['direction'] = 'b'
                             pg_id_details[str(device_pair['b']['pg_ids']['latency']['list'][device_pair['b']['pg_ids']['latency']['current_index']])]['type'] = 'latency'

                   if len(pg_id_list):
                        pg_id_to_analyze = dict()
                        pg_id_to_analyze_list = []

                        pg_id_stats = connection.get_pgid_stats(pgid_list = pg_id_list)

                        for pg_id in pg_id_list:
                             if pg_id_stats['flow_stats'][pg_id]['tx_pkts']['total'] > 0 and not str(pg_id - 2) in analyzed_pg_ids:
                                  #myprint("Advancing current_index for pg_id=%d (direction='%s' and type='%s')" % (pg_id, pg_id_details[str(pg_id)]["direction"], pg_id_details[str(pg_id)]['type']))
                                  device_pair[pg_id_details[str(pg_id)]["direction"]]['pg_ids'][pg_id_details[str(pg_id)]['type']]['current_index'] += 1
                                  pg_id_to_analyze_list.append(pg_id - 2)
                                  pg_id_to_analyze[str(pg_id - 2)] = copy.deepcopy(pg_id_details[str(pg_id)])

                        if len(pg_id_to_analyze_list):
                             pg_id_stats = connection.get_pgid_stats(pgid_list = pg_id_to_analyze_list)

                             for pg_id in pg_id_to_analyze_list:
                                  analyzed_pg_ids[str(pg_id)] = True
                                  loss_ratio = 100.0 * (1.0 - float(pg_id_stats['flow_stats'][pg_id]['rx_pkts']['total']) / float(pg_id_stats['flow_stats'][pg_id]['tx_pkts']['total']))
                                  #myprint("Analyzing pg_id=%d with rx_pkts=%d, tx_pkts=%d, and loss_ratio=%f" % (pg_id,float(pg_id_stats['flow_stats'][pg_id]['rx_pkts']['total']), float(pg_id_stats['flow_stats'][pg_id]['tx_pkts']['total']), loss_ratio))
                                  if loss_ratio > max_loss_pct:
                                       normal_exit_event.set()
                                       early_exit_event.set()
                                       myprint("Segment Monitor: device pair %d:%d with pg_id=%d (direction=%s/type=%s) failed max loss percentage requirement: %f%% > %f%% (TX:%d/RX:%d)" %
                                               (
                                                    device_pair['a']['port_index'],
                                                    device_pair['b']['port_index'],
                                                    pg_id,
                                                    pg_id_to_analyze[str(pg_id)]["direction"],
                                                    pg_id_to_analyze[str(pg_id)]["type"],
                                                    loss_ratio,
                                                    max_loss_pct,
                                                    pg_id_stats['flow_stats'][pg_id]['tx_pkts']['total'],
                                                    pg_id_stats['flow_stats'][pg_id]['rx_pkts']['total']
                                               )
                                          )

    except STLError as e:
         myprint("Segment Monitor: STLERROR: %s" % e)

    except StandardError as e:
         myprint("Segment Monitor: STANDARDERROR: %s" % e)

    finally:
         if early_exit_event.is_set():
              myprint("Segment Monitor: Exiting early")

              if bidirec:
                   connection.stop(ports = all_ports)
              else:
                   if revunidirec:
                        connection.stop(ports = revunidirec_ports)
                   else:
                        connection.stop(ports = unidirec_ports)
         else:
               myprint("Segment Monitor: Did not detect any segment failures")

         return(0)

def main():
    process_options()

    directions = [ 'a', 'b' ]

    packet_values = { 'ports': { 'src': 32768,
                                 'dst': 53 },
                      'macs':  { 'src': None,
                                 'dst': None },
                      'ips':   { 'src': None,
                                 'dst': None },
                      'vlan': None }

    pg_id_values = { "default": { 'available':   None,
                                  'start_index': None,
                                  'list':        [] },
                     "latency": { 'available':   None,
                                  'start_index': None,
                                  'list':        [] } }

    all_ports = []
    unidirec_ports = []
    revunidirec_ports = []
    device_pairs = []
    for device_pair in t_global.args.device_pairs.split(','):
         ports = device_pair.split(':')
         port_a = int(ports[0])
         port_b = int(ports[1])
         string = ':'
         if t_global.args.run_bidirec:
              string = '<->'
         elif t_global.args.run_revunidirec:
              string = '<-'
         else:
              string = '->'

         myprint("Configuring device pair: %d%s%d" % (port_a, string, port_b))
         all_ports.extend([port_a, port_b])
         unidirec_ports.append(port_a)
         revunidirec_ports.append(port_b)
         device_pairs.append({ 'a': { 'port_index': port_a,
                                      'packet_values': copy.deepcopy(packet_values),
                                      'pg_ids': copy.deepcopy(pg_id_values),
                                      'traffic_profile': None,
                                      'active': False },
                               'b': { 'port_index': port_b,
                                      'packet_values': copy.deepcopy(packet_values),
                                      'pg_ids': copy.deepcopy(pg_id_values),
                                      'traffic_profile': None,
                                      'active': False },
                               'max_default_pg_ids': 0,
                               'max_latency_pg_ids': 0 })

    c = STLClient()
    passed = True

    stats = 0
    return_value = 1

    active_ports = 0
    if t_global.args.run_bidirec:
         active_ports = len(all_ports)

         for device_pair in device_pairs:
              device_pair['a']['active'] = True
              device_pair['b']['active'] = True
    else:
         active_ports = len(unidirec_ports)

         for device_pair in device_pairs:
              if t_global.args.run_revunidirec:
                   device_pair['b']['active'] = True
              else:
                   device_pair['a']['active'] = True

    myprint("Active TX Ports: %d" % active_ports)

    try:
        # turn this on for some information
        #c.set_verbose("high")

        # connect to server
        myprint("Establishing connection to TRex server...")
        c.connect()
        myprint("Connection established")

        if t_global.args.run_bidirec and t_global.args.run_revunidirec:
             raise ValueError("It does not make sense for both --run-bidirec=1 and --run-revunidirec=1")

        # prepare our ports
        c.acquire(ports = all_ports, force=True)
        c.reset(ports = all_ports)
        c.set_port_attr(ports = all_ports, promiscuous = True)

        port_info = c.get_port_info(ports = all_ports)
        myprint("READABLE PORT INFO:", stderr_only = True)
        myprint(dump_json_readable(port_info), stderr_only = True)
        myprint("PARSABLE PORT INFO: %s" % dump_json_parsable(port_info), stderr_only = True)

        for device_pair in device_pairs:
             device_pair['a']['packet_values']['macs']['src'] = port_info[device_pair['a']['port_index']]['src_mac']
             device_pair['a']['packet_values']['macs']['dst'] = port_info[device_pair['b']['port_index']]['src_mac']

             device_pair['b']['packet_values']['macs']['src'] = port_info[device_pair['b']['port_index']]['src_mac']
             device_pair['b']['packet_values']['macs']['dst'] = port_info[device_pair['a']['port_index']]['src_mac']

             device_pair['a']['packet_values']['ips']['src'] = port_info[device_pair['a']['port_index']]['src_ipv4']
             device_pair['a']['packet_values']['ips']['dst'] = port_info[device_pair['b']['port_index']]['src_ipv4']

             device_pair['b']['packet_values']['ips']['src'] = port_info[device_pair['b']['port_index']]['src_ipv4']
             device_pair['b']['packet_values']['ips']['dst'] = port_info[device_pair['a']['port_index']]['src_ipv4']

        if t_global.args.use_src_port_flows or t_global.args.use_dst_port_flows:
             if t_global.args.num_flows >= 1000:
                  if ((t_global.args.num_flows % 1000) != 0) and ((t_global.args.num_flows % 1024) != 0):
                       raise ValueError("when source of destination port flows are enabled the number of flows must be divisible by 1000 or 1024")

        if len(t_global.args.src_ports_list):
             src_ports = t_global.args.src_ports_list.split(",")
             if len(src_ports) < active_ports:
                  raise ValueError("--src-ports-list should be a comma separated list of at least %d source port(s)" % active_ports)
             index = 0
             for device_pair in device_pairs:
                  for direction in directions:
                       if device_pair[direction]['active']:
                            device_pair[direction]['packet_values']['ports']['src'] = int(src_ports[index])
                            index += 1

        if len(t_global.args.dst_ports_list):
             dst_ports = t_global.args.dst_ports_list.split(",")
             if len(dst_ports) < active_ports:
                  raise ValueError("--dst-ports-list should be a comma separated list of at least %d destination port(s)" % active_ports)
             index = 0
             for device_pair in device_pairs:
                  for direction in directions:
                       if device_pair[direction]['active']:
                            device_pair[direction]['packet_values']['ports']['dst'] = int(dst_ports[index])
                            index += 1

        if len(t_global.args.src_macs_list):
             src_macs = t_global.args.src_macs_list.split(",")
             if len(src_macs) < active_ports:
                  raise ValueError("--src-macs-list should be a comma separated list of at least %d MAC address(es)" % active_ports)
             index = 0
             for device_pair in device_pairs:
                  for direction in directions:
                       if device_pair[direction]['active']:
                            device_pair[direction]['packet_values']['macs']['src'] = src_macs[index]
                            index += 1

        if len(t_global.args.dst_macs_list):
             dst_macs = t_global.args.dst_macs_list.split(",")
             if len(dst_macs) < active_ports:
                  raise ValueError("--dst-macs-list should be a comma separated list of at least %d MAC address(es)" % active_ports)
             index = 0
             for device_pair in device_pairs:
                  for direction in directions:
                       if device_pair[direction]['active']:
                            device_pair[direction]['packet_values']['macs']['dst'] = dst_macs[index]
                            index += 1

        if len(t_global.args.src_ips_list):
             src_ips = t_global.args.src_ips_list.split(",")
             if len(src_ips) < active_ports:
                  raise ValueError("--src-ips-list should be a comma separated list of at least %d IP address(es)" % active_ports)
             index = 0
             for device_pair in device_pairs:
                  for direction in directions:
                       if device_pair[direction]['active']:
                            device_pair[direction]['packet_values']['ips']['src'] = src_ips[index]
                            index += 1

        if len(t_global.args.dst_ips_list):
             dst_ips = t_global.args.dst_ips_list.split(",")
             if len(dst_ips) < active_ports:
                  raise ValueError("--dst-ips-list should be a comma separated list of at least %d IP address(es)" % active_ports)
             index = 0
             for device_pair in device_pairs:
                  for direction in directions:
                       if device_pair[direction]['active']:
                            device_pair[direction]['packet_values']['ips']['dst'] = dst_ips[index]
                            index += 1

        if len(t_global.args.vlan_ids_list):
             vlan_ids = t_global.args.vlan_ids_list.split(",")
             if len(vlan_ids) < active_ports:
                  raise ValueError("--vlan-ids-list should be a comma separated list of at least %d VLAN ID(s)" % active_ports)
             index = 0
             for device_pair in device_pairs:
                  for direction in directions:
                       if device_pair[direction]['active']:
                            device_pair[direction]['packet_values']['vlan'] = int(vlan_ids[index])
                            index += 1

        for device_pair in device_pairs:
             if t_global.args.run_bidirec:
                  if port_info[device_pair['a']['port_index']]["rx"]["counters"] <= port_info[device_pair['b']['port_index']]["rx"]["counters"]:
                       device_pair['max_default_pg_ids'] = port_info[device_pair['a']['port_index']]["rx"]["counters"] / len(device_pairs)
                  else:
                       device_pair['max_default_pg_ids'] = port_info[device_pair['b']['port_index']]["rx"]["counters"] / len(device_pairs)
             else:
                  if t_global.args.run_revunidirec:
                       device_pair['max_default_pg_ids'] = port_info[device_pair['a']['port_index']]["rx"]["counters"] / len(device_pairs)
                  else:
                       device_pair['max_default_pg_ids'] = port_info[device_pair['b']['port_index']]["rx"]["counters"] / len(device_pairs)

             device_pair['max_latency_pg_ids'] = 128 / len(device_pairs) # 128 is the maximum number of software counters for latency in TRex

        pg_id_base = 1
        for device_pair in device_pairs:
             if not t_global.args.run_bidirec:
                  direction = 'a'
                  if t_global.args.run_revunidirec:
                       direction = 'b'

                  device_pair[direction]['pg_ids']['default']['available']   = device_pair['max_default_pg_ids']
                  device_pair[direction]['pg_ids']['default']['start_index'] = pg_id_base
                  device_pair[direction]['pg_ids']['latency']['available']   = device_pair['max_latency_pg_ids']
                  device_pair[direction]['pg_ids']['latency']['start_index'] = device_pair[direction]['pg_ids']['default']['start_index'] + device_pair[direction]['pg_ids']['default']['available']
             else:
                  device_pair['a']['pg_ids']['default']['available']   = device_pair['max_default_pg_ids'] / 2
                  device_pair['a']['pg_ids']['default']['start_index'] = pg_id_base
                  device_pair['a']['pg_ids']['latency']['available']   = device_pair['max_latency_pg_ids'] / 2
                  device_pair['a']['pg_ids']['latency']['start_index'] = device_pair['a']['pg_ids']['default']['start_index'] + device_pair['a']['pg_ids']['default']['available']

                  device_pair['b']['pg_ids']['default']['available']   = device_pair['a']['pg_ids']['default']['available']
                  device_pair['b']['pg_ids']['default']['start_index'] = device_pair['a']['pg_ids']['default']['start_index'] + device_pair['a']['pg_ids']['default']['available'] + device_pair['a']['pg_ids']['latency']['available']
                  device_pair['b']['pg_ids']['latency']['available']   = device_pair['a']['pg_ids']['latency']['available']
                  device_pair['b']['pg_ids']['latency']['start_index'] = device_pair['b']['pg_ids']['default']['start_index'] + device_pair['b']['pg_ids']['default']['available']

             pg_id_base = pg_id_base + device_pair['max_default_pg_ids'] + device_pair['max_latency_pg_ids']

        # if latency is enabled the requested packet rate needs to be
        # adjusted to account for the latency streams
        rate_multiplier = t_global.args.rate
        if t_global.args.rate_unit == "mpps" and t_global.args.measure_latency:
             rate_multiplier -= (float(t_global.args.latency_rate) / 1000000)

        for device_pair in device_pairs:
             if t_global.args.run_revunidirec:
                  device_pair['b']['traffic_profile'] = create_traffic_profile("b", device_pair, rate_multiplier, (port_info[device_pair['b']['port_index']]['speed'] * 1000 * 1000 * 1000), t_global.args.rate_unit, t_global.args.runtime, t_global.args.stream_mode, t_global.args.measure_latency, t_global.args.latency_rate, t_global.args.frame_size, t_global.args.num_flows, t_global.args.use_src_mac_flows, t_global.args.use_dst_mac_flows, t_global.args.use_src_ip_flows, t_global.args.use_dst_ip_flows, t_global.args.use_src_port_flows, t_global.args.use_dst_port_flows, t_global.args.use_protocol_flows, t_global.args.packet_protocol, t_global.args.skip_hw_flow_stats)
                  c.add_streams(streams = device_pair['b']['traffic_profile'], ports = device_pair['b']['port_index'])
             else:
                  device_pair['a']['traffic_profile'] = create_traffic_profile("a", device_pair, rate_multiplier, (port_info[device_pair['a']['port_index']]['speed'] * 1000 * 1000 * 1000), t_global.args.rate_unit, t_global.args.runtime, t_global.args.stream_mode, t_global.args.measure_latency, t_global.args.latency_rate, t_global.args.frame_size, t_global.args.num_flows, t_global.args.use_src_mac_flows, t_global.args.use_dst_mac_flows, t_global.args.use_src_ip_flows, t_global.args.use_dst_ip_flows, t_global.args.use_src_port_flows, t_global.args.use_dst_port_flows, t_global.args.use_protocol_flows, t_global.args.packet_protocol, t_global.args.skip_hw_flow_stats)
                  c.add_streams(streams = device_pair['a']['traffic_profile'], ports = device_pair['a']['port_index'])

                  if t_global.args.run_bidirec:
                       device_pair['b']['traffic_profile'] = create_traffic_profile("b", device_pair, rate_multiplier, (port_info[device_pair['b']['port_index']]['speed'] * 1000 * 1000 * 1000), t_global.args.rate_unit, t_global.args.runtime, t_global.args.stream_mode, t_global.args.measure_latency, t_global.args.latency_rate, t_global.args.frame_size, t_global.args.num_flows, t_global.args.use_src_mac_flows, t_global.args.use_dst_mac_flows, t_global.args.use_src_ip_flows, t_global.args.use_dst_ip_flows, t_global.args.use_src_port_flows, t_global.args.use_dst_port_flows, t_global.args.use_protocol_flows, t_global.args.packet_protocol, t_global.args.skip_hw_flow_stats)
                       c.add_streams(streams = device_pair['b']['traffic_profile'], ports = device_pair['b']['port_index'])

        myprint("DEVICE PAIR INFORMATION:", stderr_only = True)
        myprint(dump_json_readable(device_pairs), stderr_only = True)
        myprint("DEVICE PAIR INFORMATION: %s" % dump_json_parsable(device_pairs), stderr_only = True)

        # clear the event log
        c.clear_events()

        if t_global.args.stream_mode == "continuous":
             rate_multiplier = str(rate_multiplier) + t_global.args.rate_unit
        elif t_global.args.stream_mode == "segmented":
             rate_multiplier = str(1)

        # clear the stats
        c.clear_stats(ports = all_ports)

        thread_normal_exit = threading.Event()
        thread_early_exit = threading.Event()
        segment_monitor_thread = threading.Thread(target = segment_monitor, args = (c, device_pairs, all_ports, unidirec_ports, revunidirec_ports, t_global.args.run_bidirec, t_global.args.run_revunidirec, t_global.args.measure_latency, t_global.args.max_loss_pct, thread_normal_exit, thread_early_exit))

        # log start of test
        timeout_seconds = math.ceil(float(t_global.args.runtime) * (1 + (float(t_global.args.runtime_tolerance) / 100)))
        stop_time = datetime.datetime.now()
        start_time = datetime.datetime.now()
        myprint("Starting test at %s" % start_time.strftime("%H:%M:%S on %Y-%m-%d"))
        expected_end_time = start_time + datetime.timedelta(seconds = t_global.args.runtime)
        expected_timeout_time = start_time + datetime.timedelta(seconds = timeout_seconds)
        myprint("The test should end at %s" % expected_end_time.strftime("%H:%M:%S on %Y-%m-%d"))
        myprint("The test will timeout with an error at %s" % expected_timeout_time.strftime("%H:%M:%S on %Y-%m-%d"))

        # here we multiply the traffic lineaer to whatever given in rate
        if t_global.args.run_revunidirec:
             for device_pair in device_pairs:
                  myprint("Transmitting at {:}{:} from port {:} to port {:} for {:} seconds...".format(t_global.args.rate, t_global.args.rate_unit, device_pair['b']['port_index'], device_pair['a']['port_index'], t_global.args.runtime))
             c.start(ports = revunidirec_ports, force = True, mult = rate_multiplier, duration = t_global.args.runtime, total = False)
        else:
             for device_pair in device_pairs:
                  myprint("Transmitting at {:}{:} from port {:} to port {:} for {:} seconds...".format(t_global.args.rate, t_global.args.rate_unit, device_pair['a']['port_index'], device_pair['b']['port_index'], t_global.args.runtime))
             if t_global.args.run_bidirec:
                  for device_pair in device_pairs:
                       myprint("Transmitting at {:}{:} from port {:} to port {:} for {:} seconds...".format(t_global.args.rate, t_global.args.rate_unit, device_pair['b']['port_index'], device_pair['a']['port_index'], t_global.args.runtime))
                  c.start(ports = all_ports, force = True, mult = rate_multiplier, duration = t_global.args.runtime, total = False)
             else:
                  c.start(ports = unidirec_ports, force = True, mult = rate_multiplier, duration = t_global.args.runtime, total = False)

        if t_global.args.stream_mode == "segmented" and t_global.args.enable_segment_monitor:
             segment_monitor_thread.start()

        timeout = False
        force_quit = False

        try:
             myprint("Waiting...")
             if t_global.args.run_bidirec:
                  c.wait_on_traffic(ports = all_ports, timeout = timeout_seconds)
             else:
                  if t_global.args.run_revunidirec:
                       c.wait_on_traffic(ports = revunidirec_ports, timeout = timeout_seconds)
                  else:
                       c.wait_on_traffic(ports = unidirec_ports, timeout = timeout_seconds)
             stop_time = datetime.datetime.now()
        except STLTimeoutError as e:
             if t_global.args.run_bidirec:
                  c.stop(ports = all_ports)
             else:
                  if t_global.args.run_revunidirec:
                       c.stop(ports = revunidirec_ports)
                  else:
                       c.stop(ports = unidirec_ports)
             stop_time = datetime.datetime.now()
             myprint("TIMEOUT ERROR: The test did not end on it's own correctly within the allotted time.")
             timeout = True
        except STLError as e:
             if t_global.args.run_bidirec:
                  c.stop(ports = all_ports)
             else:
                  if t_global.args.run_revunidirec:
                       c.stop(ports = revunidirec_ports)
                  else:
                       c.stop(ports = unidirec_ports)
             stop_time = datetime.datetime.now()
             myprint("ERROR: wait_on_traffic: STLError: %s" % e)
             force_quit = True

        # log end of test
        myprint("Finished test at %s" % stop_time.strftime("%H:%M:%S on %Y-%m-%d"))
        total_time = stop_time - start_time
        myprint("Test ran for %d seconds (%s)" % (total_time.total_seconds(), total_time))

        if t_global.args.stream_mode == "segmented" and t_global.args.enable_segment_monitor:
             thread_normal_exit.set()
             segment_monitor_thread.join()

        stats = c.get_stats(sync_now = True)
        stats["global"]["runtime"] = total_time.total_seconds()
        stats["global"]["timeout"] = timeout
        stats["global"]["force_quit"] = force_quit
        stats["global"]["early_exit"] = False
        if thread_early_exit.is_set():
             stats["global"]["early_exit"] = True

        for device_pair in device_pairs:
             for flows_index, flows_id in enumerate(stats["flow_stats"]):
                  if flows_id == "global":
                       continue

                  if not int(flows_id) in device_pair['a']['pg_ids']['default']['list'] and not int(flows_id) in device_pair['b']['pg_ids']['default']['list'] and not int(flows_id) in device_pair['a']['pg_ids']['latency']['list'] and not int(flows_id) in device_pair['b']['pg_ids']['latency']['list']:
                       continue

                  flow_tx = 0
                  flow_rx = 0

                  if not "loss" in stats["flow_stats"][flows_id]:
                       stats["flow_stats"][flows_id]["loss"] = dict()
                       stats["flow_stats"][flows_id]["loss"]["pct"] = dict()
                       stats["flow_stats"][flows_id]["loss"]["cnt"] = dict()

                  direction_id = "%d->%d" % (device_pair['a']['port_index'], device_pair['b']['port_index'])

                  if device_pair['a']['port_index'] in stats["flow_stats"][flows_id]["tx_pkts"] and device_pair['b']['port_index'] in stats["flow_stats"][flows_id]["rx_pkts"] and stats["flow_stats"][flows_id]["tx_pkts"][device_pair['a']['port_index']]:
                       stats["flow_stats"][flows_id]["loss"]["pct"][direction_id] = (1 - (float(stats["flow_stats"][flows_id]["rx_pkts"][device_pair['b']['port_index']]) / float(stats["flow_stats"][flows_id]["tx_pkts"][device_pair['a']['port_index']]))) * 100
                       stats["flow_stats"][flows_id]["loss"]["cnt"][direction_id] = float(stats["flow_stats"][flows_id]["tx_pkts"][device_pair['a']['port_index']]) - float(stats["flow_stats"][flows_id]["rx_pkts"][device_pair['b']['port_index']])
                       flow_tx += stats["flow_stats"][flows_id]["tx_pkts"][device_pair['a']['port_index']]
                       flow_rx += stats["flow_stats"][flows_id]["rx_pkts"][device_pair['b']['port_index']]
                  else:
                       stats["flow_stats"][flows_id]["loss"]["pct"][direction_id] = "N/A"
                       stats["flow_stats"][flows_id]["loss"]["cnt"][direction_id] = "N/A"

                  direction_id = "%d->%d" % (device_pair['b']['port_index'], device_pair['a']['port_index'])

                  if device_pair['b']['port_index'] in stats["flow_stats"][flows_id]["tx_pkts"] and device_pair['a']['port_index'] in stats["flow_stats"][flows_id]["rx_pkts"] and stats["flow_stats"][flows_id]["tx_pkts"][device_pair['b']['port_index']]:
                       stats["flow_stats"][flows_id]["loss"]["pct"][direction_id] = (1 - (float(stats["flow_stats"][flows_id]["rx_pkts"][device_pair['a']['port_index']]) / float(stats["flow_stats"][flows_id]["tx_pkts"][device_pair['b']['port_index']]))) * 100
                       stats["flow_stats"][flows_id]["loss"]["cnt"][direction_id] = float(stats["flow_stats"][flows_id]["tx_pkts"][device_pair['b']['port_index']]) - float(stats["flow_stats"][flows_id]["rx_pkts"][device_pair['a']['port_index']])
                       flow_tx += stats["flow_stats"][flows_id]["tx_pkts"][device_pair['b']['port_index']]
                       flow_rx += stats["flow_stats"][flows_id]["rx_pkts"][device_pair['a']['port_index']]
                  else:
                       stats["flow_stats"][flows_id]["loss"]["pct"][direction_id] = "N/A"
                       stats["flow_stats"][flows_id]["loss"]["cnt"][direction_id] = "N/A"

                  if flow_tx:
                       stats["flow_stats"][flows_id]["loss"]["pct"]["total"] = (1 - (float(flow_rx) / float(flow_tx))) * 100
                       stats["flow_stats"][flows_id]["loss"]["cnt"]["total"] = float(flow_tx) - float(flow_rx)
                  else:
                       stats["flow_stats"][flows_id]["loss"]["pct"]["total"] = "N/A"
                       stats["flow_stats"][flows_id]["loss"]["cnt"]["total"] = "N/A"

        warning_events = c.get_warnings()
        if len(warning_events):
             myprint("TRex Warning Events:")
             for warning in warning_events:
                  myprint("    WARNING: %s" % warning)

        events = c.get_events()
        if len(events):
             myprint("TRex Events:")
             for event in events:
                  myprint("    EVENT: %s" % event)

        myprint("READABLE RESULT:", stderr_only = True)
        myprint(dump_json_readable(stats), stderr_only = True)
        myprint("PARSABLE RESULT: %s" % dump_json_parsable(stats), stderr_only = True)

        return_value = 0

    except STLError as e:
        myprint("STLERROR: %s" % e)

    except ValueError as e:
        myprint("ERROR: %s" % e)

    except:
        myprint("EXCEPTION: %s" % traceback.format_exc())

    finally:
        myprint("Disconnecting from TRex server...")
        c.disconnect()
        myprint("Connection severed")
        return return_value

if __name__ == "__main__":
    exit(main())
