from __future__ import print_function

import sys, getopt
sys.path.append('/opt/trex/current/automation/trex_control_plane/interactive')
import argparse
import string
import datetime
import math
import threading
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

def create_teaching_garp_packets (direction, other_direction, device_pair):
     garp_request_packet = create_garp_pkt(device_pair[direction]['packet_values']['macs']['dst'],
                                           device_pair[direction]['packet_values']['ips']['dst'],
                                           device_pair[other_direction]['packet_values']['vlan'],
                                           0x1,
                                           t_global.args.flow_mods,
                                           t_global.args.num_flows,
                                           t_global.args.enable_flow_cache)

     garp_reply_packet = create_garp_pkt(device_pair[direction]['packet_values']['macs']['dst'],
                                         device_pair[direction]['packet_values']['ips']['dst'],
                                         device_pair[other_direction]['packet_values']['vlan'],
                                         0x2,
                                         t_global.args.flow_mods,
                                         t_global.args.num_flows,
                                         t_global.args.enable_flow_cache)

     return [garp_request_packet, garp_reply_packet]

def create_teaching_icmp_packets (direction, other_direction, device_pair):
     return [ create_icmp_bcast_pkt(device_pair[direction]['packet_values']['macs']['dst'],
                                    device_pair[direction]['packet_values']['ips']['dst'],
                                    device_pair[other_direction]['packet_values']['vlan'],
                                    t_global.args.flow_mods,
                                    t_global.args.num_flows,
                                    t_global.args.enable_flow_cache) ]

def create_teaching_generic_packets (direction, other_direction, device_pair):
     return [ create_generic_pkt(64,
                                 device_pair[direction]['packet_values']['macs']['dst'],
                                 device_pair[direction]['packet_values']['macs']['src'],
                                 device_pair[direction]['packet_values']['ips']['dst'],
                                 device_pair[direction]['packet_values']['ips']['src'],
                                 device_pair[direction]['packet_values']['ports']['dst'],
                                 device_pair[direction]['packet_values']['ports']['src'],
                                 "UDP",
                                 device_pair[other_direction]['packet_values']['vlan'],
                                 t_global.args.flow_mods,
                                 t_global.args.num_flows,
                                 t_global.args.enable_flow_cache) ]

def create_teaching_warmup_traffic_profile (direction, other_direction, device_pair):
     myprint("Creating teaching warmup streams for device pair '%s' direction '%s' with TYPE=%s and MAC=%s and IP=%s" % (device_pair['device_pair'],
                                                                                                                     direction,
                                                                                                                     t_global.args.teaching_warmup_packet_type,
                                                                                                                     device_pair[direction]['packet_values']['macs']['dst'],
                                                                                                                     device_pair[direction]['packet_values']['ips']['dst']))

     teaching_packets = []
     if t_global.args.teaching_warmup_packet_type == "garp":
          teaching_packets = create_teaching_garp_packets(direction, other_direction, device_pair)
     elif t_global.args.teaching_warmup_packet_type == "generic":
          teaching_packets = create_teaching_generic_packets(direction, other_direction, device_pair)
     if t_global.args.teaching_warmup_packet_type == "icmp":
          teaching_packets = create_teaching_icmp_packets(direction, other_direction, device_pair)

     warmup_mode = STLTXSingleBurst(total_pkts = t_global.args.num_flows, pps = t_global.args.teaching_warmup_packet_rate)

     for packet in teaching_packets:
          device_pair[other_direction]['teaching_warmup_traffic_profile'].append(STLStream(packet = packet, mode = warmup_mode))

     return

def create_teaching_measurement_traffic_profile (direction, other_direction, device_pair):
     myprint("Creating teaching measurement streams for device pair '%s' direction '%s' with TYPE=%s and MAC=%s and IP=%s" % (device_pair['device_pair'],
                                                                                                                              direction,
                                                                                                                              t_global.args.teaching_measurement_packet_type,
                                                                                                                              device_pair[direction]['packet_values']['macs']['dst'],
                                                                                                                              device_pair[direction]['packet_values']['ips']['dst']))

     teaching_packets = []
     if t_global.args.teaching_measurement_packet_type == "garp":
          teaching_packets = create_teaching_garp_packets(direction, other_direction, device_pair)
     elif t_global.args.teaching_measurement_packet_type == "generic":
          teaching_packets = create_teaching_generic_packets(direction, other_direction, device_pair)
     if t_global.args.teaching_measurement_packet_type == "icmp":
          teaching_packets = create_teaching_icmp_packets(direction, other_direction, device_pair)

     burst_length = t_global.args.num_flows / t_global.args.teaching_measurement_packet_rate

     # IBG is in usec, so we multiply by 1,000,000 to convert to seconds
     measurement_mode = STLTXMultiBurst(pkts_per_burst = t_global.args.num_flows, ibg = (t_global.args.teaching_measurement_interval * 1000000), count = int(t_global.args.runtime / (t_global.args.teaching_measurement_interval + burst_length)), pps = t_global.args.teaching_measurement_packet_rate)

     for packet in teaching_packets:
          device_pair[other_direction]['teaching_measurement_traffic_profile'].append(STLStream(packet = packet, mode = measurement_mode))

     return

def create_traffic_profile (direction, device_pair, rate_multiplier, port_speed):
     streams = { 'default': { 'protocol': [],
                              'pps': [],
                              'pg_ids': [],
                              'names': [],
                              'next_stream_names': [],
                              'frame_sizes': [],
                              'traffic_shares': [],
                              'self_starts': [],
                              'runtime': [],
                              'stream_modes': [] } }
     streams['latency'] = copy.deepcopy(streams['default'])

     # packet overhead is (7 byte preamable + 1 byte SFD -- Start of Frame Delimiter -- + 12 byte IFG -- Inter Frame Gap)
     packet_overhead_bytes = 20
     ethernet_frame_overhead = 18
     bits_per_byte = 8

     protocols = [ t_global.args.packet_protocol ]
     if t_global.args.flow_mods['protocol']:
          if t_global.args.packet_protocol == "UDP":
               protocols.append("TCP")
          elif t_global.args.packet_protocol == "TCP":
               protocols.append("UDP")

     for protocols_index, protocols_value in enumerate(protocols):
          if t_global.args.frame_size == "imix" and t_global.args.stream_mode == "continuous":
               # imix is defined as the following packets (including IP header): 7 of size 40 bytes, 4 of size 576 bytes, and 1 of size 1500 bytes
               # from https://en.wikipedia.org/wiki/Internet_Mix

               small_packets = 7
               medium_packets = 4
               large_packets = 1
               total_packets = small_packets + medium_packets + large_packets

               small_traffic_share = float(small_packets) / float(total_packets)
               medium_traffic_share = float(medium_packets) / float(total_packets)
               large_traffic_share = float(large_packets) / float(total_packets)

               small_packet_bytes = 40 + ethernet_frame_overhead
               medium_packet_bytes = 576 + ethernet_frame_overhead
               large_packet_bytes = 1500 + ethernet_frame_overhead
               avg_packet_bytes = float(small_packet_bytes*small_packets + medium_packet_bytes*medium_packets + large_packet_bytes*large_packets) / float(total_packets)

               small_stream_pg_id = device_pair[direction]['pg_ids']['default']['start_index'] + protocols_index
               medium_stream_pg_id = device_pair[direction]['pg_ids']['default']['start_index'] + 2 + protocols_index
               large_stream_pg_id = device_pair[direction]['pg_ids']['default']['start_index'] + 4 + protocols_index

               small_stream_name = "small_stream_" + device_pair[direction]['id_string'] + "_" + protocols_value
               medium_stream_name = "medium_stream_" + device_pair[direction]['id_string'] + "_" + protocols_value
               large_stream_name = "large_stream_" + device_pair[direction]['id_string'] + "_" + protocols_value

               streams['default']['protocol'].extend([protocols_value, protocols_value, protocols_value])
               if t_global.args.rate_unit == "mpps":
                    my_packet_rate = rate_multiplier / len(protocols) * 1000000
               else:
                    my_packet_rate = ((rate_multiplier / 100) / len(protocols)) * (port_speed / bits_per_byte) / (avg_packet_bytes + packet_overhead_bytes)
               streams['default']['pps'].extend([small_traffic_share * my_packet_rate, medium_traffic_share * my_packet_rate, large_traffic_share * my_packet_rate])
               streams['default']['pg_ids'].extend([small_stream_pg_id, medium_stream_pg_id, large_stream_pg_id])
               streams['default']['names'].extend([small_stream_name, medium_stream_name, large_stream_name])
               streams['default']['next_stream_names'].extend([None, None, None])
               streams['default']['frame_sizes'].extend([small_packet_bytes, medium_packet_bytes, large_packet_bytes])
               streams['default']['traffic_shares'].extend([(small_traffic_share/len(protocols)), (medium_traffic_share/len(protocols)), (large_traffic_share/len(protocols))])
               streams['default']['self_starts'].extend([True, True, True])
               streams['default']['stream_modes'].extend(["burst", "burst", "burst"])
               streams['default']['runtime'].extend([float(t_global.args.runtime), float(t_global.args.runtime), float(t_global.args.runtime)])

               if t_global.args.measure_latency:
                    small_latency_stream_pg_id = device_pair[direction]['pg_ids']['latency']['start_index'] + protocols_index
                    medium_latency_stream_pg_id = device_pair[direction]['pg_ids']['latency']['start_index'] + 2 + protocols_index
                    large_latency_stream_pg_id = device_pair[direction]['pg_ids']['latency']['start_index'] + 4 + protocols_index

                    small_latency_stream_name = "small_latency_stream_" + device_pair[direction]['id_string'] + "_" + protocols_value
                    medium_latency_stream_name = "medium_latency_stream_" + device_pair[direction]['id_string'] + "_" + protocols_value
                    large_latency_stream_name = "large_latency_stream_" + device_pair[direction]['id_string'] + "_" + protocols_value

                    streams['latency']['protocol'].extend([protocols_value, protocols_value, protocols_value])
                    streams['latency']['pps'].extend([calculate_latency_pps(small_packets, total_packets, t_global.args.latency_rate, len(protocols)), calculate_latency_pps(medium_packets, total_packets, t_global.args.latency_rate, len(protocols)), calculate_latency_pps(large_packets, total_packets, t_global.args.latency_rate, len(protocols))])
                    streams['latency']['pg_ids'].extend([small_latency_stream_pg_id, medium_latency_stream_pg_id, large_latency_stream_pg_id])
                    streams['latency']['names'].extend([small_latency_stream_name, medium_latency_stream_name, large_latency_stream_name])
                    streams['latency']['next_stream_names'].extend([None, None, None])
                    streams['latency']['frame_sizes'].extend([small_packet_bytes, medium_packet_bytes, large_packet_bytes])
                    streams['latency']['traffic_shares'].extend([(small_traffic_share/len(protocols)), (medium_traffic_share/len(protocols)), (large_traffic_share/len(protocols))])
                    streams['latency']['self_starts'].extend([True, True, True])
                    streams['latency']['stream_modes'].extend(["continuous", "continuous", "continuous"])
                    streams['latency']['runtime'].extend([-1, -1, -1])

          elif t_global.args.frame_size == "imix" and t_global.args.stream_mode == "segmented":
               print("Support for segmented IMIX needs to be coded...")
          elif t_global.args.stream_mode == "continuous":
               default_stream_pg_id = device_pair[direction]['pg_ids']['default']['start_index'] + protocols_index

               default_stream_name = "default_stream_" + device_pair[direction]['id_string'] + "_" + protocols_value

               streams['default']['protocol'].extend([protocols_value])
               if t_global.args.rate_unit == "mpps":
                    streams['default']['pps'].extend([rate_multiplier/len(protocols)*1000000])
               else:
                    streams['default']['pps'].extend([((rate_multiplier/100)/len(protocols)) * (port_speed / bits_per_byte) / (int(t_global.args.frame_size) + packet_overhead_bytes)])
               streams['default']['pg_ids'].extend([default_stream_pg_id])
               streams['default']['names'].extend([default_stream_name])
               streams['default']['next_stream_names'].extend([None])
               streams['default']['frame_sizes'].extend([int(t_global.args.frame_size)])
               streams['default']['traffic_shares'].extend([1.0/len(protocols)])
               streams['default']['self_starts'].extend([True])
               streams['default']['stream_modes'].extend(["burst"])
               streams['default']['runtime'].extend([float(t_global.args.runtime)])

               if t_global.args.measure_latency:
                    latency_stream_pg_id = device_pair[direction]['pg_ids']['latency']['start_index'] + protocols_index

                    latency_stream_name = "latency_stream_" + device_pair[direction]['id_string'] + "_" + protocols_value

                    streams['latency']['protocol'].extend([protocols_value])
                    streams['latency']['pps'].extend([t_global.args.latency_rate/len(protocols)])
                    streams['latency']['pg_ids'].extend([latency_stream_pg_id])
                    streams['latency']['names'].extend([latency_stream_name])
                    streams['latency']['next_stream_names'].extend([None])
                    streams['latency']['frame_sizes'].extend([int(t_global.args.frame_size)])
                    streams['latency']['traffic_shares'].extend([1.0/len(protocols)])
                    streams['latency']['self_starts'].extend([True])
                    streams['latency']['stream_modes'].extend(["continuous"])
                    streams['latency']['runtime'].extend([-1])
          elif t_global.args.stream_mode == "segmented":
               stream_types = [ "default" ]
               if t_global.args.measure_latency:
                    stream_types.append("latency")

               for streams_type_index, streams_type_value in enumerate(stream_types):
                    if len(protocols) > 1 and (device_pair[direction]['pg_ids'][streams_type_value]['available'] % 2) != 0:
                         device_pair[direction]['pg_ids'][streams_type_value]['available'] -= 1

                    min_pg_id = device_pair[direction]['pg_ids'][streams_type_value]['start_index'] + protocols_index
                    max_pg_id = device_pair[direction]['pg_ids'][streams_type_value]['start_index'] + device_pair[direction]['pg_ids'][streams_type_value]['available']

                    counter=1
                    for current_pg_id in range(min_pg_id, max_pg_id, len(protocols)):
                         stream_name_prefix = streams_type_value + "_stream_" + device_pair[direction]['id_string'] + "_" + protocols_value + "_segment_"

                         stream_name = stream_name_prefix + str(counter)

                         next_stream_name = None
                         if (current_pg_id + len(protocols)) < max_pg_id:
                              next_stream_name = stream_name_prefix + str(counter+1)

                         self_start = False
                         if current_pg_id == min_pg_id:
                              self_start = True

                         streams[streams_type_value]['protocol'].extend([protocols_value])
                         if streams_type_value == "latency":
                              streams[streams_type_value]['pps'].extend([t_global.args.latency_rate/len(protocols)])
                         else:
                              if t_global.args.rate_unit == "mpps":
                                   streams[streams_type_value]['pps'].extend([rate_multiplier/len(protocols)*1000000])
                              else:
                                   streams[streams_type_value]['pps'].extend([((rate_multiplier/100)/len(protocols)) * (port_speed / bits_per_byte) / (int(t_global.args.frame_size) + packet_overhead_bytes)])
                         streams[streams_type_value]['pg_ids'].extend([current_pg_id])
                         streams[streams_type_value]['names'].extend([stream_name])
                         streams[streams_type_value]['next_stream_names'].extend([next_stream_name])
                         streams[streams_type_value]['frame_sizes'].extend([int(t_global.args.frame_size)])
                         streams[streams_type_value]['traffic_shares'].extend([1.0/device_pair[direction]['pg_ids'][streams_type_value]["available"]])
                         streams[streams_type_value]['self_starts'].extend([self_start])
                         streams[streams_type_value]['stream_modes'].extend(["burst"])
                         streams[streams_type_value]['runtime'].extend([float(t_global.args.runtime)/(device_pair[direction]['pg_ids'][streams_type_value]["available"]/len(protocols))])

                         counter += 1

     for streams_index, streams_packet_type in enumerate(streams):
          for stream_packet_protocol, stream_pps, stream_pg_id, stream_name, stream_frame_size, stream_traffic_share, stream_next_stream_name, stream_self_start, stream_mode, stream_runtime in zip(streams[streams_packet_type]['protocol'], streams[streams_packet_type]['pps'], streams[streams_packet_type]['pg_ids'], streams[streams_packet_type]['names'], streams[streams_packet_type]['frame_sizes'], streams[streams_packet_type]['traffic_shares'], streams[streams_packet_type]['next_stream_names'], streams[streams_packet_type]['self_starts'], streams[streams_packet_type]['stream_modes'], streams[streams_packet_type]['runtime']):
               myprint("Creating stream for device pair '%s' direction '%s' with packet_type=[%s], protocol=[%s], pps=[%f], pg_id=[%d], name=[%s], frame_size=[%d], next_stream_name=[%s], self_start=[%s], stream_mode=[%s], runtime=[%f], and traffic_share=[%f]." %
                       (device_pair['device_pair'],
                        direction,
                        streams_packet_type,
                        stream_packet_protocol,
                        stream_pps,
                        stream_pg_id,
                        stream_name,
                        stream_frame_size,
                        stream_next_stream_name,
                        stream_self_start,
                        stream_mode,
                        stream_runtime,
                        stream_traffic_share))

               stream_flow_stats = None
               if streams_packet_type == "default" and not t_global.args.skip_hw_flow_stats:
                    stream_flow_stats = STLFlowStats(pg_id = stream_pg_id)
               elif streams_packet_type == "latency":
                    stream_flow_stats = STLFlowLatencyStats(pg_id = stream_pg_id)
               device_pair[direction]['pg_ids'][streams_packet_type]['list'].append(stream_pg_id)

               stream_loop = False
               if stream_mode == "burst":
                    stream_total_pkts = int(stream_runtime * stream_pps)

                    # check if the total number of packets to TX is greater than can be held in an uint32 (API limit)
                    max_uint32 = int(4294967295)
                    if stream_total_pkts > max_uint32:
                         stream_loop = True
                         stream_loop_remainder = stream_total_pkts % max_uint32
                         stream_loops = int(((stream_total_pkts - stream_loop_remainder) / max_uint32))

                         if stream_loop_remainder == 0:
                              stream_loops -= 1
                              stream_loops_remainder = max_uinit32
                    else:
                         stream_mode_obj = STLTXSingleBurst(pps = stream_pps, total_pkts = stream_total_pkts)
               elif stream_mode == "continuous":
                    stream_mode_obj = STLTXCont(pps = stream_pps)

               stream_packet = create_generic_pkt(stream_frame_size,
                                                  device_pair[direction]['packet_values']['macs']['src'],
                                                  device_pair[direction]['packet_values']['macs']['dst'],
                                                  device_pair[direction]['packet_values']['ips']['src'],
                                                  device_pair[direction]['packet_values']['ips']['dst'],
                                                  device_pair[direction]['packet_values']['ports']['src'],
                                                  device_pair[direction]['packet_values']['ports']['dst'],
                                                  stream_packet_protocol,
                                                  device_pair[direction]['packet_values']['vlan'],
                                                  t_global.args.flow_mods,
                                                  t_global.args.num_flows,
                                                  t_global.args.enable_flow_cache)

               if stream_loop:
                    myprint("Stream is being split into multiple substreams due to high total packet count")

                    substream_self_start = stream_self_start
                    for loop_idx in range(1, stream_loops+1):
                         if loop_idx == 1:
                              substream_name = stream_name
                         else:
                              substream_name = "%s_sub_%d" % (stream_name, loop_idx)
                         substream_next_name = "%s_sub_%d" % (stream_name, loop_idx+1)
                         myprint("Creating substream %d with name %s" % (loop_idx, substream_name))

                         stream_mode_obj = STLTXSingleBurst(pps = stream_pps, total_pkts = max_uint32)
                         device_pair[direction]['traffic_profile'].append(STLStream(packet = stream_packet,
                                                                                    flow_stats = stream_flow_stats,
                                                                                    mode = stream_mode_obj,
                                                                                    name = substream_name,
                                                                                    next = substream_next_name,
                                                                                    self_start = substream_self_start))
                         substream_self_start = False

                    substream_name = "%s_sub_%d" % (stream_name, stream_loops+1)
                    myprint("Creating substream %d with name %s" % (stream_loops+1, substream_name))
                    stream_mode_obj = STLTXSingleBurst(pps = stream_pps, total_pkts = stream_loop_remainder)
                    device_pair[direction]['traffic_profile'].append(STLStream(packet = stream_packet,
                                                                               flow_stats = stream_flow_stats,
                                                                               mode = stream_mode_obj,
                                                                               name = substream_name,
                                                                               next = stream_next_stream_name,
                                                                               self_start = substream_self_start))
               else:
                    device_pair[direction]['traffic_profile'].append(STLStream(packet = stream_packet,
                                                                               flow_stats = stream_flow_stats,
                                                                               mode = stream_mode_obj,
                                                                               name = stream_name,
                                                                               next = stream_next_stream_name,
                                                                               self_start = stream_self_start))

     myprint("DEVICE PAIR %s | READABLE STREAMS FOR DIRECTION '%s':" % (device_pair['device_pair'], device_pair[direction]['id_string']), stderr_only = True)
     myprint(dump_json_readable(streams), stderr_only = True)
     myprint("DEVICE PAIR %s | PARSABLE STREAMS FOR DIRECTION '%s': %s" % (device_pair['device_pair'], device_pair[direction]['id_string'], dump_json_parsable(streams)), stderr_only = True)

def process_options ():
    parser = argparse.ArgumentParser(usage=""" 
    generate network traffic and report packet loss
    """);

    parser.add_argument('--trex-host',
                        dest='trex_host',
                        help='Hostname/IP address of the server where TRex is running',
                        default='localhost',
                        type = str
                        )
    parser.add_argument('--debug',
                        dest='debug',
                        help='Should debugging be enabled',
                        action = 'store_true'
                        )
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
    parser.add_argument('--active-device-pairs',
                        dest='active_device_pairs',
                        help='List of active device pairs in the for A:B[,C:D][,E:F][,...]',
                        default="--",
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
    parser.add_argument('--disable-flow-cache',
                        dest='enable_flow_cache',
                        help='Force disablement of the flow cache',
                        action = 'store_false',
                        )
    parser.add_argument('--send-teaching-warmup',
                        dest='send_teaching_warmup',
                        help='Send teaching packets from the receiving port during a warmup phase',
                        action = 'store_true',
                        )
    parser.add_argument('--send-teaching-measurement',
                        dest='send_teaching_measurement',
                        help='Send teaching packetsfrom the receiving port during the measurement phase',
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
                        default = 'garp',
                        choices = ['garp', 'icmp', 'generic']
                        )
    parser.add_argument('--teaching-measurement-packet-type',
                        dest='teaching_measurement_packet_type',
                        help='Type of packet to send for the teaching measurement from the receiving port',
                        default = 'garp',
                        choices = ['garp', 'icmp', 'generic']
                        )
    parser.add_argument('--no-promisc',
                        dest='no_promisc',
                        help='Do not use promiscuous mode for network interfaces (usually needed for virtual-functions)',
                        action = 'store_true'
                        )
    parser.add_argument('--binary-search-synchronize',
                        dest='binary_search_synchronize',
                        help='Enable synchronization through binary-search.py.  Used to coordinate with other traffic generators.',
                        action='store_true'
                        )

    t_global.args = parser.parse_args();
    if t_global.args.frame_size == "IMIX":
         t_global.args.frame_size = "imix"
    if t_global.args.active_device_pairs == '--':
         t_global.args.active_device_pairs = t_global.args.device_pairs
    if t_global.args.num_flows > 10000 and t_global.args.enable_flow_cache:
         t_global.args.enable_flow_cache = False
         myprint("NOTE: Flow caching disabled due to high flow count which will cause higher resource requirements.")
    else:
         if t_global.args.num_flows and not t_global.args.enable_flow_cache:
              myprint("NOTE: User disablement of flow caching will cause higher resource requirements.")
    t_global.args.flow_mods = create_flow_mod_object(use_src_mac_flows  = t_global.args.use_src_mac_flows,
                                                     use_dst_mac_flows  = t_global.args.use_dst_mac_flows,
                                                     use_src_ip_flows   = t_global.args.use_src_ip_flows,
                                                     use_dst_ip_flows   = t_global.args.use_dst_ip_flows,
                                                     use_src_port_flows = t_global.args.use_src_port_flows,
                                                     use_dst_port_flows = t_global.args.use_dst_port_flows,
                                                     use_protocol_flows = t_global.args.use_protocol_flows)
    myprint(t_global.args)

def segment_monitor(connection, device_pairs, run_ports, normal_exit_event, early_exit_event):
    try:
         myprint("Segment Monitor: Running")

         directions = [ '->', '<-' ]
         for device_pair in device_pairs:
              for direction in directions:
                   if device_pair[direction]['active']:
                        device_pair[direction]['pg_ids']['default']['current_index'] = 2

                        if t_global.args.measure_latency:
                             device_pair[direction]['pg_ids']['latency']['current_index'] = 2

         analyzed_pg_ids = dict()

         while not normal_exit_event.is_set():
              time.sleep(1)

              #myprint("")
              for device_pair in device_pairs:
                   #myprint("Analyzing device pair %s" % (device_pair['device_pair']))
                   pg_id_list = []
                   pg_id_details = dict()

                   for direction in directions:
                        if device_pair[direction]['active']:
                             if device_pair[direction]['pg_ids']['default']['current_index'] <= (len(device_pair[direction]['pg_ids']['default']['list']) - 1):
                                  #myprint("Found default candidate %d for '%s'" % (device_pair['a']['pg_ids']['default']['list'][device_pair['a']['pg_ids']['default']['current_index']], direction))
                                  pg_id_list.append(device_pair[direction]['pg_ids']['default']['list'][device_pair[direction]['pg_ids']['default']['current_index']])
                                  pg_id_details[str(device_pair[direction]['pg_ids']['default']['list'][device_pair[direction]['pg_ids']['default']['current_index']])] = dict()
                                  pg_id_details[str(device_pair[direction]['pg_ids']['default']['list'][device_pair[direction]['pg_ids']['default']['current_index']])]['direction'] = direction
                                  pg_id_details[str(device_pair[direction]['pg_ids']['default']['list'][device_pair[direction]['pg_ids']['default']['current_index']])]['type'] = 'default'

                             if t_global.args.measure_latency and device_pair[direction]['pg_ids']['latency']['current_index'] <= (len(device_pair[direction]['pg_ids']['latency']['list']) - 1):
                                  #myprint("Found latency candidate %d for '%s'" % (device_pair['a']['pg_ids']['latency']['list'][device_pair['a']['pg_ids']['latency']['current_index']], direction))
                                  pg_id_list.append(device_pair[direction]['pg_ids']['latency']['list'][device_pair[direction]['pg_ids']['latency']['current_index']])
                                  pg_id_details[str(device_pair[direction]['pg_ids']['latency']['list'][device_pair[direction]['pg_ids']['latency']['current_index']])] = dict()
                                  pg_id_details[str(device_pair[direction]['pg_ids']['latency']['list'][device_pair[direction]['pg_ids']['latency']['current_index']])]['direction'] = direction
                                  pg_id_details[str(device_pair[direction]['pg_ids']['latency']['list'][device_pair[direction]['pg_ids']['latency']['current_index']])]['type'] = 'latency'

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
                                  if loss_ratio > t_global.args.max_loss_pct:
                                       normal_exit_event.set()
                                       early_exit_event.set()
                                       myprint("Segment Monitor: device pair %s with pg_id=%d (direction=%s/type=%s) failed max loss percentage requirement: %f%% > %f%% (TX:%d/RX:%d)" %
                                               (
                                                    device_pair['device_pair'],
                                                    pg_id,
                                                    pg_id_to_analyze[str(pg_id)]["direction"],
                                                    pg_id_to_analyze[str(pg_id)]["type"],
                                                    loss_ratio,
                                                    t_global.args.max_loss_pct,
                                                    pg_id_stats['flow_stats'][pg_id]['tx_pkts']['total'],
                                                    pg_id_stats['flow_stats'][pg_id]['rx_pkts']['total']
                                               )
                                          )

    except TRexError as e:
         myprint("Segment Monitor: TREXERROR: %s" % e)

    except StandardError as e:
         myprint("Segment Monitor: STANDARDERROR: %s" % e)

    finally:
         if early_exit_event.is_set():
              myprint("Segment Monitor: Exiting early")

              connection.stop(ports = run_ports)
         else:
               myprint("Segment Monitor: Did not detect any segment failures")

         return(0)

def main():
    directions = [ '->', '<-' ]

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

    claimed_device_pairs = []
    for device_pair in t_global.args.device_pairs.split(','):
         ports = device_pair.split(':')
         port_a = int(ports[0])
         port_b = int(ports[1])
         claimed_device_pairs.extend([port_a, port_b])

    all_ports = []
    unidirec_ports = []
    revunidirec_ports = []
    unidirec_teaching_ports = []
    revunidirec_teaching_ports = []
    device_pairs = []
    for device_pair in t_global.args.active_device_pairs.split(','):
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
         if t_global.args.send_teaching_warmup or t_global.args.send_teaching_measurement:
              unidirec_teaching_ports.append(port_b)
              revunidirec_teaching_ports.append(port_a)
         device_pairs.append({ '->': { 'ports': { 'tx': port_a,
                                                  'rx': port_b },
                                       'id_string': "%s->%s" % (port_a, port_b),
                                       'packet_values': copy.deepcopy(packet_values),
                                       'pg_ids': copy.deepcopy(pg_id_values),
                                       'traffic_profile': [],
                                       'teaching_warmup_traffic_profile': [],
                                       'teaching_measurement_traffic_profile': [],
                                       'active': False },
                               '<-': { 'ports': { 'tx': port_b,
                                                  'rx': port_a },
                                       'id_string': "%s->%s" % (port_b, port_a),
                                       'packet_values': copy.deepcopy(packet_values),
                                       'pg_ids': copy.deepcopy(pg_id_values),
                                       'traffic_profile': [],
                                       'teaching_warmup_traffic_profile': [],
                                       'teaching_measurement_traffic_profile': [],
                                       'active': False },
                               'max_default_pg_ids': 0,
                               'max_latency_pg_ids': 0,
                               'device_pair': device_pair })

    c = STLClient(server = t_global.args.trex_host)
    passed = True

    stats = 0
    return_value = 1

    active_ports = 0
    if t_global.args.run_bidirec:
         active_ports = len(all_ports)

         for device_pair in device_pairs:
              device_pair['->']['active'] = True
              device_pair['<-']['active'] = True
    else:
         active_ports = len(unidirec_ports)
         if t_global.args.send_teaching_warmup or t_global.args.send_teaching_measurement:
              active_ports /= 2

         for device_pair in device_pairs:
              if t_global.args.run_revunidirec:
                   device_pair['<-']['active'] = True
              else:
                   device_pair['->']['active'] = True

    myprint("Active TX Ports: %d" % active_ports)

    try:
        if t_global.args.debug:
             # turn this on for some information
             c.set_verbose("debug")

        # connect to server
        myprint("Establishing connection to TRex server...")
        c.connect()
        myprint("Connection established")

        if t_global.args.run_bidirec and t_global.args.run_revunidirec:
             raise ValueError("It does not make sense for both --run-bidirec=1 and --run-revunidirec=1")

        # prepare our ports
        c.acquire(ports = claimed_device_pairs, force=True)
        c.reset(ports = claimed_device_pairs)
        if t_global.args.no_promisc:
             c.set_port_attr(ports = all_ports)
        else:
             c.set_port_attr(ports = all_ports, promiscuous = True)
        port_info = c.get_port_info(ports = claimed_device_pairs)
        myprint("READABLE PORT INFO:", stderr_only = True)
        myprint(dump_json_readable(port_info), stderr_only = True)
        myprint("PARSABLE PORT INFO: %s" % dump_json_parsable(port_info), stderr_only = True)

        port_speed_verification_fail = False

        for device_pair in device_pairs:
             if port_info[device_pair['->']['ports']['tx']]['speed'] == 0:
                  port_speed_verification_fail = True
                  myprint(error("Device with port index = %d failed speed verification test" % (device_pair['->']['ports']['tx'])))
             if port_info[device_pair['<-']['ports']['tx']]['speed'] == 0:
                  port_speed_verification_fail = True
                  myprint(error("Device with port index = %d failed speed verification test" % (device_pair['<-']['ports']['tx'])))

             device_pair['->']['packet_values']['macs']['src'] = port_info[device_pair['->']['ports']['tx']]['src_mac']
             device_pair['->']['packet_values']['macs']['dst'] = port_info[device_pair['->']['ports']['rx']]['src_mac']

             device_pair['<-']['packet_values']['macs']['src'] = port_info[device_pair['<-']['ports']['tx']]['src_mac']
             device_pair['<-']['packet_values']['macs']['dst'] = port_info[device_pair['<-']['ports']['rx']]['src_mac']

             if port_info[device_pair['->']['ports']['tx']]['src_ipv4'] != "-":
                  device_pair['->']['packet_values']['ips']['src'] = port_info[device_pair['->']['ports']['tx']]['src_ipv4']
                  device_pair['<-']['packet_values']['ips']['dst'] = port_info[device_pair['->']['ports']['tx']]['src_ipv4']
             else:
                  ip_address = "%d.%d.%d.%d" % (device_pair['->']['ports']['tx']+1, device_pair['->']['ports']['tx']+1, device_pair['->']['ports']['tx']+1, device_pair['->']['ports']['tx']+1)
                  device_pair['->']['packet_values']['ips']['src'] = ip_address
                  device_pair['<-']['packet_values']['ips']['dst'] = ip_address

             if port_info[device_pair['<-']['ports']['tx']]['src_ipv4'] != "-":
                  device_pair['->']['packet_values']['ips']['dst'] = port_info[device_pair['<-']['ports']['tx']]['src_ipv4']
                  device_pair['<-']['packet_values']['ips']['src'] = port_info[device_pair['<-']['ports']['tx']]['src_ipv4']
             else:
                  ip_address = "%d.%d.%d.%d" % (device_pair['<-']['ports']['tx']+1, device_pair['<-']['ports']['tx']+1, device_pair['<-']['ports']['tx']+1, device_pair['<-']['ports']['tx']+1)
                  device_pair['->']['packet_values']['ips']['dst'] = ip_address
                  device_pair['<-']['packet_values']['ips']['src'] = ip_address

        if port_speed_verification_fail:
             raise RuntimeError("Failed port speed verification")

        if t_global.args.flow_mods['port']['src'] or t_global.args.flow_mods['port']['dst']:
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
                  if port_info[device_pair['->']['ports']['tx']]["rx"]["counters"] <= port_info[device_pair['->']['ports']['rx']]["rx"]["counters"]:
                       device_pair['max_default_pg_ids'] = port_info[device_pair['->']['ports']['tx']]["rx"]["counters"]
                  else:
                       device_pair['max_default_pg_ids'] = port_info[device_pair['->']['ports']['rx']]["rx"]["counters"]
             else:
                  if t_global.args.run_revunidirec:
                       device_pair['max_default_pg_ids'] = port_info[device_pair['<-']['ports']['rx']]["rx"]["counters"]
                  else:
                       device_pair['max_default_pg_ids'] = port_info[device_pair['->']['ports']['rx']]["rx"]["counters"]

             if len(device_pairs) > 1:
                  # ensure that an even number of pg_ids are available per device_pair
                  remainder = device_pair['max_default_pg_ids'] % len(device_pairs)
                  device_pair['max_default_pg_ids'] -= remainder
                  # divide the pg_ids across the device_pairs
                  device_pair['max_default_pg_ids'] = int(device_pair['max_default_pg_ids'] / len(device_pairs))

             device_pair['max_latency_pg_ids'] = int(128 / len(device_pairs)) # 128 is the maximum number of software counters for latency in TRex

        pg_id_base = 1
        for device_pair in device_pairs:
             if not t_global.args.run_bidirec:
                  direction = '->'
                  if t_global.args.run_revunidirec:
                       direction = '<-'

                  device_pair[direction]['pg_ids']['default']['available']   = device_pair['max_default_pg_ids']
                  device_pair[direction]['pg_ids']['default']['start_index'] = pg_id_base
                  device_pair[direction]['pg_ids']['latency']['available']   = device_pair['max_latency_pg_ids']
                  device_pair[direction]['pg_ids']['latency']['start_index'] = device_pair[direction]['pg_ids']['default']['start_index'] + device_pair[direction]['pg_ids']['default']['available']
             else:
                  if (device_pair['max_default_pg_ids'] % 2) == 1:
                       device_pair['max_default_pg_ids'] -= 1

                  if (device_pair['max_latency_pg_ids'] % 2) == 1:
                       device_pair['max_latency_pg_ids'] -= 1

                  device_pair['->']['pg_ids']['default']['available']   = int(device_pair['max_default_pg_ids'] / 2)
                  device_pair['->']['pg_ids']['default']['start_index'] = pg_id_base
                  device_pair['->']['pg_ids']['latency']['available']   = int(device_pair['max_latency_pg_ids'] / 2)
                  device_pair['->']['pg_ids']['latency']['start_index'] = device_pair['->']['pg_ids']['default']['start_index'] + device_pair['->']['pg_ids']['default']['available']

                  device_pair['<-']['pg_ids']['default']['available']   = device_pair['->']['pg_ids']['default']['available']
                  device_pair['<-']['pg_ids']['default']['start_index'] = device_pair['->']['pg_ids']['default']['start_index'] + device_pair['->']['pg_ids']['default']['available'] + device_pair['->']['pg_ids']['latency']['available']
                  device_pair['<-']['pg_ids']['latency']['available']   = device_pair['->']['pg_ids']['latency']['available']
                  device_pair['<-']['pg_ids']['latency']['start_index'] = device_pair['<-']['pg_ids']['default']['start_index'] + device_pair['<-']['pg_ids']['default']['available']

             pg_id_base = pg_id_base + device_pair['max_default_pg_ids'] + device_pair['max_latency_pg_ids']

        # if latency is enabled the requested packet rate needs to be
        # adjusted to account for the latency streams
        rate_multiplier = t_global.args.rate
        if t_global.args.rate_unit == "mpps" and t_global.args.measure_latency:
             rate_multiplier -= (float(t_global.args.latency_rate) / 1000000)

        for device_pair in device_pairs:
             if t_global.args.run_revunidirec:
                  create_traffic_profile("<-", device_pair, rate_multiplier, (port_info[device_pair['<-']['ports']['tx']]['speed'] * 1000 * 1000 * 1000))

                  if t_global.args.send_teaching_warmup:
                       create_teaching_warmup_traffic_profile("<-", "->", device_pair)

                  if t_global.args.send_teaching_measurement:
                       create_teaching_measurement_traffic_profile("<-", "->", device_pair)
             else:
                  create_traffic_profile("->", device_pair, rate_multiplier, (port_info[device_pair['->']['ports']['tx']]['speed'] * 1000 * 1000 * 1000))

                  if t_global.args.send_teaching_warmup:
                       create_teaching_warmup_traffic_profile("->", "<-", device_pair)

                  if t_global.args.send_teaching_measurement:
                       create_teaching_measurement_traffic_profile("->", "<-", device_pair)

                  if t_global.args.run_bidirec:
                       create_traffic_profile("<-", device_pair, rate_multiplier, (port_info[device_pair['<-']['ports']['tx']]['speed'] * 1000 * 1000 * 1000))

                       if t_global.args.send_teaching_warmup:
                            create_teaching_warmup_traffic_profile("<-", "->", device_pair)

                       if t_global.args.send_teaching_measurement:
                            create_teaching_measurement_traffic_profile("<-", "->", device_pair)

        if t_global.args.send_teaching_warmup:
             for device_pair in device_pairs:
                  for direction in directions:
                       if len(device_pair[direction]['teaching_warmup_traffic_profile']):
                            myprint("Adding teaching warmup stream(s) for device pair '%s' to port %d" % (device_pair['device_pair'], device_pair[direction]['ports']['tx']))
                            c.add_streams(streams = device_pair[direction]['teaching_warmup_traffic_profile'], ports = device_pair[direction]['ports']['tx'])

             myprint("Transmitting teaching warmup packets...")
             start_time = datetime.datetime.now()

             warmup_timeout = int(max(30.0, (float(t_global.args.num_flows) / t_global.args.teaching_warmup_packet_rate) * 1.05))

             warmup_ports = []
             if t_global.args.run_revunidirec:
                  warmup_ports.extend(revunidirec_teaching_ports)
             else:
                  if t_global.args.run_bidirec:
                       warmup_ports.extend(all_ports)
                  else:
                       warmup_ports.extend(unidirec_teaching_ports)

             try:
                  c.start(ports = warmup_ports, force = True)
                  c.wait_on_traffic(ports = warmup_ports, timeout = warmup_timeout)

                  stop_time = datetime.datetime.now()
                  total_time = stop_time - start_time
                  myprint("...teaching warmup transmission complete -- %d total second(s) elapsed" % total_time.total_seconds())
             except TRexTimeoutError as e:
                  c.stop(ports = warmup_ports)
                  stop_time = datetime.datetime.now()
                  total_time = stop_time - start_time
                  myprint("...TIMEOUT ERROR: The teaching warmup did not end on it's own correctly within the allotted time (%d seconds) -- %d total second(s) elapsed" % (warmup_timeout, total_time.total_seconds()))
                  return return_value
             except TRexError as e:
                  c.stop(ports = warmup_ports)
                  myprint("...ERROR: wait_on_traffic: TRexError: %s" % e)
                  return return_value

             c.reset(ports = warmup_ports)
             if t_global.args.no_promisc:
                  c.set_port_attr(ports = warmup_ports)
             else:
                  c.set_port_attr(ports = warmup_ports, promiscuous = True)

        run_ports = []

        for device_pair in device_pairs:
             for direction in directions:
                  port_streams = 0

                  if len(device_pair[direction]['traffic_profile']):
                       myprint("Adding stream(s) for device pair '%s' to port %d" % (device_pair['device_pair'], device_pair[direction]['ports']['tx']))
                       port_streams += len(device_pair[direction]['traffic_profile'])
                       c.add_streams(streams = device_pair[direction]['traffic_profile'], ports = device_pair[direction]['ports']['tx'])

                  if t_global.args.send_teaching_measurement and len(device_pair[direction]['teaching_measurement_traffic_profile']):
                       myprint("Adding teaching stream(s) for device pair '%s' to port %d" % (device_pair['device_pair'], device_pair[direction]['ports']['tx']))
                       port_streams += len(device_pair[direction]['teaching_measurement_traffic_profile'])
                       c.add_streams(streams = device_pair[direction]['teaching_measurement_traffic_profile'], ports = device_pair[direction]['ports']['tx'])

                  if port_streams:
                       run_ports.append(device_pair[direction]['ports']['tx'])


        myprint("DEVICE PAIR INFORMATION:", stderr_only = True)
        myprint(dump_json_readable(device_pairs), stderr_only = True)
        myprint("DEVICE PAIR INFORMATION: %s" % dump_json_parsable(device_pairs), stderr_only = True)

        # clear the event log
        c.clear_events()

        # clear the stats
        c.clear_stats(ports = all_ports)

        if t_global.args.binary_search_synchronize:
             parent_launch_sem = posix_ipc.Semaphore("trafficgen_child_launch")
             parent_go_sem = posix_ipc.Semaphore("trafficgen_child_go")

             myprint("Signaling binary-search.py that I am ready")
             parent_launch_sem.release()

             myprint("Waiting for binary-search.py to tell me to go")
             parent_go_sem.acquire()
             myprint("Received go from binary-search.py")

             parent_launch_sem.close()
             parent_go_sem.close()

             myprint("Synchronization services complete")

        thread_normal_exit = threading.Event()
        thread_early_exit = threading.Event()
        segment_monitor_thread = threading.Thread(target = segment_monitor, args = (c, device_pairs, run_ports, thread_normal_exit, thread_early_exit))

        # log start of test
        timeout_seconds = math.ceil(float(t_global.args.runtime) * (1 + (float(t_global.args.runtime_tolerance) / 100)))
        stop_time = datetime.datetime.now()
        start_time = datetime.datetime.now()
        myprint("Starting test at %s" % start_time.strftime("%H:%M:%S on %Y-%m-%d"))
        expected_end_time = start_time + datetime.timedelta(seconds = t_global.args.runtime)
        expected_timeout_time = start_time + datetime.timedelta(seconds = timeout_seconds)
        myprint("The test should end at %s" % expected_end_time.strftime("%H:%M:%S on %Y-%m-%d"))
        myprint("The test will timeout with an error at %s" % expected_timeout_time.strftime("%H:%M:%S on %Y-%m-%d"))

        for device_pair in device_pairs:
             for direction in directions:
                  if device_pair[direction]['active']:
                       rate_unit = t_global.args.rate_unit
                       if rate_unit == '%':
                            rate_unit = '%%'

                       myprint("Transmitting at %s%s from port %d to port %d for %d seconds..." % (t_global.args.rate,
                                                                                                   rate_unit,
                                                                                                   device_pair[direction]['ports']['tx'],
                                                                                                   device_pair[direction]['ports']['rx'],
                                                                                                   t_global.args.runtime))

        # start the traffic
        c.start(ports = run_ports, force = True, duration = t_global.args.runtime, total = False, core_mask = STLClient.CORE_MASK_PIN)

        if t_global.args.stream_mode == "segmented" and t_global.args.enable_segment_monitor:
             segment_monitor_thread.start()

        timeout = False
        force_quit = False

        try:
             myprint("Waiting...")
             c.wait_on_traffic(ports = run_ports, timeout = timeout_seconds)
             stop_time = datetime.datetime.now()
        except TRexTimeoutError as e:
             c.stop(ports = run_ports)
             stop_time = datetime.datetime.now()
             myprint("TIMEOUT ERROR: The test did not end on it's own correctly within the allotted time.")
             timeout = True
        except TRexError as e:
             c.stop(ports = run_ports)
             stop_time = datetime.datetime.now()
             myprint(error("wait_on_traffic: TRexError: %s" % (e)))
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

                  if not int(flows_id) in device_pair['->']['pg_ids']['default']['list'] and not int(flows_id) in device_pair['<-']['pg_ids']['default']['list'] and not int(flows_id) in device_pair['->']['pg_ids']['latency']['list'] and not int(flows_id) in device_pair['<-']['pg_ids']['latency']['list']:
                       continue

                  flow_tx = 0
                  flow_rx = 0

                  if not "loss" in stats["flow_stats"][flows_id]:
                       stats["flow_stats"][flows_id]["loss"] = dict()
                       stats["flow_stats"][flows_id]["loss"]["pct"] = dict()
                       stats["flow_stats"][flows_id]["loss"]["cnt"] = dict()

                  for direction in directions:
                       if device_pair[direction]['ports']['tx'] in stats["flow_stats"][flows_id]["tx_pkts"] and device_pair[direction]['ports']['rx'] in stats["flow_stats"][flows_id]["rx_pkts"] and stats["flow_stats"][flows_id]["tx_pkts"][device_pair[direction]['ports']['tx']]:
                            stats["flow_stats"][flows_id]["loss"]["pct"][device_pair[direction]['id_string']] = (1 - (float(stats["flow_stats"][flows_id]["rx_pkts"][device_pair[direction]['ports']['rx']]) / float(stats["flow_stats"][flows_id]["tx_pkts"][device_pair[direction]['ports']['tx']]))) * 100
                            stats["flow_stats"][flows_id]["loss"]["cnt"][device_pair[direction]['id_string']] = float(stats["flow_stats"][flows_id]["tx_pkts"][device_pair[direction]['ports']['tx']]) - float(stats["flow_stats"][flows_id]["rx_pkts"][device_pair[direction]['ports']['rx']])
                            flow_tx += stats["flow_stats"][flows_id]["tx_pkts"][device_pair[direction]['ports']['tx']]
                            flow_rx += stats["flow_stats"][flows_id]["rx_pkts"][device_pair[direction]['ports']['rx']]
                       else:
                            stats["flow_stats"][flows_id]["loss"]["pct"][device_pair[direction]['id_string']] = "N/A"
                            stats["flow_stats"][flows_id]["loss"]["cnt"][device_pair[direction]['id_string']] = "N/A"

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

        myprint("TX Utilization: %f%%" % stats['global']['cpu_util'])
        myprint("RX Utilization: %f%%" % stats['global']['rx_cpu_util'])
        myprint("TX Queue Full:  %d"   % stats['global']['queue_full'])

        myprint("READABLE RESULT:", stderr_only = True)
        myprint(dump_json_readable(stats), stderr_only = True)
        myprint("PARSABLE RESULT: %s" % dump_json_parsable(stats), stderr_only = True)

        return_value = 0

    except TRexError as e:
        myprint("TRexERROR: %s" % e)

    except (ValueError, RuntimeError) as e:
        myprint(error("%s" % (e)))

    except:
        myprint("EXCEPTION: %s" % traceback.format_exc())

    finally:
        myprint("Disconnecting from TRex server...")
        c.disconnect()
        myprint("Connection severed")
        return return_value

if __name__ == "__main__":
    process_options()

    # only import the posix_ipc library if traffic generator
    # synchronization needs to be managed through binary-search.py.
    # imports must be done at the module level which is why this is
    # done here instead of in main()
    if t_global.args.binary_search_synchronize:
         myprint("Enabling synchronization through binary-search.py")
         import posix_ipc

    exit(main())
