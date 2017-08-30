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

def dump_json_readable(obj):
     return json.dumps(obj, indent = 4, separators=(',', ': '), sort_keys = True)

def dump_json_parsable(obj):
     return json.dumps(obj, separators=(',', ':'))

def ip_to_int (ip):
    ip_fields = ip.split(".")
    if len(ip_fields) != 4:
         raise ValueError("IP addresses should be in the form of W.X.Y.Z")
    ip_int = 256**3 * int(ip_fields[0]) + 256**2 * int(ip_fields[1]) + 256**1 * int(ip_fields[2]) + int(ip_fields[3])
    return ip_int

def calculate_latency_pps (dividend, divisor, total_rate, protocols):
     return int((float(dividend) / float(divisor) * total_rate / protocols))

def create_traffic_profile (direction, rate_multiplier, port_speed, rate_unit, run_time, stream_mode, measure_latency, pg_id, latency_rate, frame_size, num_flows, src_mac_flows, dst_mac_flows, src_ip_flows, dst_ip_flows, src_port_flows, dst_port_flows, protocol_flows, mac_src, mac_dst, ip_src, ip_dst, port_src, port_dst, packet_protocol, vlan, skip_hw_flow_stats):
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

               small_stream_pg_id = pg_id["default"]["start_index"] + protocols_index
               medium_stream_pg_id =  pg_id["default"]["start_index"] + 2 + protocols_index
               large_stream_pg_id = pg_id["default"]["start_index"] + 4 + protocols_index

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
                    small_latency_stream_pg_id = pg_id["latency"]["start_index"] + protocols_index
                    medium_latency_stream_pg_id = pg_id["latency"]["start_index"] + 2 + protocols_index
                    large_latency_stream_pg_id = pg_id["latency"]["start_index"] + 4 + protocols_index

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
               default_stream_pg_id = pg_id["default"]["start_index"] + protocols_index

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
                    latency_stream_pg_id = pg_id["latency"]["start_index"] + protocols_index

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
                    if len(protocols) > 1 and (pg_id[streams_type_value]["available"] % 2) != 0:
                         pg_id[streams_type_value]["available"] -= 1

                    min_pg_id = pg_id[streams_type_value]["start_index"] + protocols_index
                    max_pg_id = pg_id[streams_type_value]["start_index"] + pg_id["default"]["available"]

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
                         streams[streams_type_value]['traffic_shares'].extend([1.0/pg_id[streams_type_value]["available"]])
                         streams[streams_type_value]['self_starts'].extend([self_start])
                         streams[streams_type_value]['stream_modes'].extend(["burst"])
                         streams[streams_type_value]['run_time'].extend([float(run_time)/(pg_id[streams_type_value]["available"]/len(protocols))])

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

               if stream_mode == "burst":
                    stream_mode_obj = STLTXSingleBurst(pps = stream_pps, total_pkts = int(stream_run_time * stream_pps))
               elif stream_mode == "continuous":
                    stream_mode_obj = STLTXCont(pps = stream_pps)

               profile_streams.append(STLStream(packet = create_pkt(stream_frame_size, num_flows, src_mac_flows, dst_mac_flows, src_ip_flows, dst_ip_flows, src_port_flows, dst_port_flows, mac_src, mac_dst, ip_src, ip_dst, port_src, port_dst, stream_packet_protocol, vlan),
                                                flow_stats = stream_flow_stats,
                                                mode = stream_mode_obj,
                                                name = stream_name,
                                                next = stream_next_stream_name,
                                                self_start = stream_self_start))

     myprint("READABLE STREAMS FOR DIRECTION '%s':" % direction, stderr_only = True)
     myprint(dump_json_readable(streams), stderr_only = True)
     myprint("PARSABLE STREAMS FOR DIRECTION '%s': %s" % (direction, dump_json_parsable(streams)), stderr_only = True)

     return STLProfile(profile_streams)

# simple packet creation
def create_pkt (size, num_flows, src_mac_flows, dst_mac_flows, src_ip_flows, dst_ip_flows, src_port_flows, dst_port_flows, mac_src, mac_dst, ip_src, ip_dst, port_src, port_dst, packet_protocol, vlan_id):
    # adjust packet size
    size = int(size)
    size -= 4

    ip_src = { "start": ip_to_int(ip_src), "end": ip_to_int(ip_src) + num_flows }
    ip_dst = { "start": ip_to_int(ip_dst), "end": ip_to_int(ip_dst) + num_flows }

    port_range = { "start": 0, "end": 65535 }
    if src_port_flows or dst_port_flows:
         if num_flows < 1000:
              num_flows_divisor = num_flows
         elif (num_flows % 1000) == 0:
              num_flows_divisor = 1000
         elif (num_flows % 1024 == 0):
              num_flows_divisor = 1024

         if (port_src + num_flows_divisor) > port_range["end"]:
              port_start = port_range["end"] - num_flows_divisor
              port_end = port_range["end"]
         else:
              port_start = port_src
              port_end = port_src + num_flows_divisor

         port_src = { "start": port_start, "end": port_end, "init": port_src }

         if (port_dst + num_flows_divisor) > port_range["end"]:
              port_start = port_range["end"] - num_flows_divisor
              port_end = port_range["end"]
         else:
              port_start = port_dst
              port_end = port_dst + num_flows_divisor

         port_dst = { "start": port_start, "end": port_end, "init": port_dst }
    else:
         port_src = { "init": port_src }
         port_dst = { "init": port_dst }

    vm = []
    if src_ip_flows:
        vm = vm + [
            STLVmFlowVar(name="ip_src",min_value=ip_src['start'],max_value=ip_src['end'],size=4,op="inc"),
            STLVmWrFlowVar(fv_name="ip_src",pkt_offset= "IP.src")
        ]

    if dst_ip_flows:
        vm = vm + [
            STLVmFlowVar(name="ip_dst",min_value=ip_dst['start'],max_value=ip_dst['end'],size=4,op="inc"),
            STLVmWrFlowVar(fv_name="ip_dst",pkt_offset= "IP.dst")
        ]

    if src_mac_flows:
        vm = vm + [
            STLVmFlowVar(name="mac_src",min_value=0,max_value=num_flows,size=4,op="inc"),
            STLVmWrFlowVar(fv_name="mac_src",pkt_offset=7)
        ]

    if dst_mac_flows:
        vm = vm + [
            STLVmFlowVar(name="mac_dst",min_value=0,max_value=num_flows,size=4,op="inc"),
            STLVmWrFlowVar(fv_name="mac_dst",pkt_offset=1)
        ]

    if src_port_flows:
        vm = vm + [
            STLVmFlowVar(name = "port_src", init_value = port_src['init'], min_value = port_src['start'], max_value = port_src['end'], size = 2, op = "inc"),
            STLVmWrFlowVar(fv_name = "port_src", pkt_offset = packet_protocol + ".sport"),
        ]

    if dst_port_flows:
        vm = vm + [
            STLVmFlowVar(name = "port_dst", init_value = port_dst['init'], min_value = port_dst['start'], max_value = port_dst['end'], size = 2, op = "inc"),
            STLVmWrFlowVar(fv_name = "port_dst", pkt_offset = packet_protocol + ".dport"),
        ]

    if vlan_id > 1:
        base = Ether(src = mac_src, dst = mac_dst)/Dot1Q(vlan = vlan_id)/IP(src = str(ip_src['start']), dst = str(ip_dst['start']))
    else:
        base = Ether(src = mac_src, dst = mac_dst)/IP(src = str(ip_src['start']), dst = str(ip_dst['start']))

    if packet_protocol == "UDP":
         base = base/UDP(sport = port_src['init'], dport = port_dst['init'] )
    elif packet_protocol == "TCP":
         base = base/TCP(sport = port_src['init'], dport = port_dst['init'] )
    pad = max(0, size-len(base)) * 'x'

    the_packet = base/pad
    #the_packet.show2()

    if src_ip_flows or dst_ip_flows or src_mac_flows or dst_mac_flows or src_port_flows or dst_port_flows:
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

    t_global.args = parser.parse_args();
    if t_global.args.frame_size == "IMIX":
         t_global.args.frame_size = "imix"
    myprint(t_global.args)

def main():
    process_options()
    port_a = 0
    port_b = 1

    c = STLClient()
    passed = True

    stats = 0
    return_value = 1

    active_ports = 1
    if t_global.args.run_bidirec:
         active_ports += 1

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
        c.acquire(ports = [port_a, port_b], force=True)
        c.reset(ports = [port_a, port_b])
        c.set_port_attr(ports = [port_a, port_b], promiscuous = True)

        port_info = c.get_port_info(ports = [port_a, port_b])
        myprint("READABLE PORT INFO:", stderr_only = True)
        myprint(dump_json_readable(port_info), stderr_only = True)
        myprint("PARSABLE PORT INFO: %s" % dump_json_parsable(port_info), stderr_only = True)

        port_a_src = 32768
        port_a_dst = 53
        port_b_src = 32768
        port_b_dst = 53

        mac_a_src = port_info[port_a]["src_mac"]
        mac_a_dst = port_info[port_b]["src_mac"]
        mac_b_src = port_info[port_b]["src_mac"]
        mac_b_dst = port_info[port_a]["src_mac"]

        ip_a_src = "10.0.0.1"
        ip_a_dst = "8.0.0.1"
        ip_b_src = ip_a_dst
        ip_b_dst = ip_a_src

	vlan_a = 1
	vlan_b = 1

        if t_global.args.use_src_port_flows or t_global.args.use_dst_port_flows:
             if t_global.args.num_flows >= 1000:
                  if ((t_global.args.num_flows % 1000) != 0) and ((t_global.args.num_flows % 1024) != 0):
                       raise ValueError("when source of destination port flows are enabled the number of flows must be divisible by 1000 or 1024")

        if len(t_global.args.src_ports_list):
             src_ports = t_global.args.src_ports_list.split(",")
             if len(src_ports) < active_ports:
                  raise ValueError("--src-ports-list should be a comma separated list of at least %d source port(s)" % active_ports)
             port_a_src = int(src_ports[0])
             if t_global.args.run_revunidirec or t_global.args.run_bidirec:
                  port_b_src = int(src_ports[1])

        if len(t_global.args.dst_ports_list):
             dst_ports = t_global.args.dst_ports_list.split(",")
             if len(dst_ports) < active_ports:
                  raise ValueError("--dst-ports-list should be a comma separated list of at least %d destination port(s)" % active_ports)
             port_a_dst = int(dst_ports[0])
             if t_global.args.run_revunidirec or t_global.args.run_bidirec:
                  port_b_dst = int(dst_ports[1])

        if len(t_global.args.src_macs_list):
             src_macs = t_global.args.src_macs_list.split(",")
             if len(src_macs) < active_ports:
                  raise ValueError("--src-macs-list should be a comma separated list of at least %d MAC address(es)" % active_ports)
             mac_a_src = src_macs[0]
             if t_global.args.run_revunidirec or t_global.args.run_bidirec:
                  mac_b_src = src_macs[1]

        if len(t_global.args.dst_macs_list):
             dst_macs = t_global.args.dst_macs_list.split(",")
             if len(dst_macs) < active_ports:
                  raise ValueError("--dst-macs-list should be a comma separated list of at least %d MAC address(es)" % active_ports)
             mac_a_dst = dst_macs[0]
             if t_global.args.run_revunidirec or t_global.args.run_bidirec:
                  mac_b_dst = dst_macs[1]

        if len(t_global.args.src_ips_list):
             src_ips = t_global.args.src_ips_list.split(",")
             if len(src_ips) < active_ports:
                  raise ValueError("--src-ips-list should be a comma separated list of at least %d IP address(es)" % active_ports)
             ip_a_src = src_ips[0]
             if t_global.args.run_revunidirec or t_global.args.run_bidirec:
                  ip_b_src = src_ips[1]

        if len(t_global.args.dst_ips_list):
             dst_ips = t_global.args.dst_ips_list.split(",")
             if len(dst_ips) < active_ports:
                  raise ValueError("--dst-ips-list should be a comma separated list of at least %d IP address(es)" % active_ports)
             ip_a_dst = dst_ips[0]
             if t_global.args.run_revunidirec or t_global.args.run_bidirec:
                  ip_b_dst = dst_ips[1]

        if len(t_global.args.vlan_ids_list):
             vlan_ids = t_global.args.vlan_ids_list.split(",")
             if len(vlan_ids) < active_ports:
                  raise ValueError("--vlan-ids-list should be a comma separated list of at least %d VLAN ID(s)" % active_ports)
             vlan_a = int(vlan_ids[0])
             if t_global.args.run_revunidirec or t_global.args.run_bidirec:
                  vlan_b = int(vlan_ids[1])

        max_default_pg_ids = 0
        if t_global.args.run_bidirec:
             if port_info[port_a]["rx"]["counters"] <= port_info[port_b]["rx"]["counters"]:
                  max_default_pg_ids = port_info[port_a]["rx"]["counters"]
             else:
                  max_default_pg_ids = port_info[port_b]["rx"]["counters"]
        else:
             if t_global.args.run_revunidirec:
                  max_default_pg_ids = port_info[port_a]["rx"]["counters"]
             else:
                  max_default_pg_ids = port_info[port_b]["rx"]["counters"]

        max_latency_pg_ids = 128 # this is a software filtering limit
        pg_ids = { "a": { "default": { "available": -1, "start_index": -1 }, "latency": { "available": -1, "start_index": -1 } } }
        if not t_global.args.run_bidirec:
             pg_ids["a"]["default"]["available"] = max_default_pg_ids
             pg_ids["a"]["default"]["start_index"] = 1
             pg_ids["a"]["latency"]["available"] = max_latency_pg_ids
             pg_ids["a"]["latency"]["start_index"] = pg_ids["a"]["default"]["start_index"] + pg_ids["a"]["default"]["available"]
        else:
             pg_ids["b"] = copy.deepcopy(pg_ids["a"])

             pg_ids["a"]["default"]["available"] = max_default_pg_ids / 2
             pg_ids["a"]["default"]["start_index"] = 1
             pg_ids["a"]["latency"]["available"] = max_latency_pg_ids / 2
             pg_ids["a"]["latency"]["start_index"] = pg_ids["a"]["default"]["start_index"] + max_default_pg_ids

             pg_ids["b"]["default"]["available"] = pg_ids["a"]["default"]["available"]
             pg_ids["b"]["default"]["start_index"] = pg_ids["a"]["default"]["start_index"] + pg_ids["a"]["default"]["available"]
             pg_ids["b"]["latency"]["available"] = pg_ids["a"]["latency"]["available"]
             pg_ids["b"]["latency"]["start_index"] = pg_ids["a"]["latency"]["start_index"] + pg_ids["a"]["latency"]["available"]

        # if latency is enabled the requested packet rate needs to be
        # adjusted to account for the latency streams
        rate_multiplier = t_global.args.rate
        if t_global.args.rate_unit == "mpps" and t_global.args.measure_latency:
             rate_multiplier -= (float(t_global.args.latency_rate) / 1000000)

        if t_global.args.run_revunidirec:
             traffic_profile = create_traffic_profile("b", rate_multiplier, (port_info[port_b]['speed'] * 1000 * 1000 * 1000), t_global.args.rate_unit, t_global.args.runtime, t_global.args.stream_mode, t_global.args.measure_latency, pg_ids["a"], t_global.args.latency_rate, t_global.args.frame_size, t_global.args.num_flows, t_global.args.use_src_mac_flows, t_global.args.use_dst_mac_flows, t_global.args.use_src_ip_flows, t_global.args.use_dst_ip_flows, t_global.args.use_src_port_flows, t_global.args.use_dst_port_flows, t_global.args.use_protocol_flows, mac_b_src, mac_b_dst, ip_b_src, ip_b_dst, port_b_src, port_b_dst, t_global.args.packet_protocol, vlan_b, t_global.args.skip_hw_flow_stats)
             c.add_streams(streams = traffic_profile, ports = [port_b])
        else:
             traffic_profile = create_traffic_profile("a", rate_multiplier, (port_info[port_b]['speed'] * 1000 * 1000 * 1000), t_global.args.rate_unit, t_global.args.runtime, t_global.args.stream_mode, t_global.args.measure_latency, pg_ids["a"], t_global.args.latency_rate, t_global.args.frame_size, t_global.args.num_flows, t_global.args.use_src_mac_flows, t_global.args.use_dst_mac_flows, t_global.args.use_src_ip_flows, t_global.args.use_dst_ip_flows, t_global.args.use_src_port_flows, t_global.args.use_dst_port_flows, t_global.args.use_protocol_flows, mac_a_src, mac_a_dst, ip_a_src, ip_a_dst, port_a_src, port_a_dst, t_global.args.packet_protocol, vlan_a, t_global.args.skip_hw_flow_stats)
             c.add_streams(streams = traffic_profile, ports = [port_a])

             if t_global.args.run_bidirec:
                  traffic_profile = create_traffic_profile("b", rate_multiplier, (port_info[port_b]['speed'] * 1000 * 1000 * 1000), t_global.args.rate_unit, t_global.args.runtime, t_global.args.stream_mode, t_global.args.measure_latency, pg_ids["b"], t_global.args.latency_rate, t_global.args.frame_size, t_global.args.num_flows, t_global.args.use_src_mac_flows, t_global.args.use_dst_mac_flows, t_global.args.use_src_ip_flows, t_global.args.use_dst_ip_flows, t_global.args.use_src_port_flows, t_global.args.use_dst_port_flows, t_global.args.use_protocol_flows, mac_b_src, mac_b_dst, ip_b_src, ip_b_dst, port_b_src, port_b_dst, t_global.args.packet_protocol, vlan_b, t_global.args.skip_hw_flow_stats)
                  c.add_streams(streams = traffic_profile, ports = [port_b])

        # clear the stats before injecting
        c.clear_stats()

        # clear the event log
        c.clear_events()

        if t_global.args.stream_mode == "continuous":
             rate_multiplier = str(rate_multiplier) + t_global.args.rate_unit
        elif t_global.args.stream_mode == "segmented":
             rate_multiplier = str(1)

        # clear the stats
        if t_global.args.run_revunidirec:
             c.clear_stats(ports = [port_b])
        else:
             if t_global.args.run_bidirec:
                  c.clear_stats(ports = [port_a, port_b])
             else:
                  c.clear_stats(ports = [port_a])

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
             myprint("Transmitting at {:}{:} from port {:} -> {:} for {:} seconds...".format(t_global.args.rate, t_global.args.rate_unit, port_b, port_a, t_global.args.runtime))
             c.start(ports = [port_b], force = True, mult = rate_multiplier, duration = t_global.args.runtime, total = False)
        else:
             myprint("Transmitting at {:}{:} from port {:} -> {:} for {:} seconds...".format(t_global.args.rate, t_global.args.rate_unit, port_a, port_b, t_global.args.runtime))
             if t_global.args.run_bidirec:
                  myprint("Transmitting at {:}{:} from port {:} -> {:} for {:} seconds...".format(t_global.args.rate, t_global.args.rate_unit, port_b, port_a, t_global.args.runtime))
                  c.start(ports = [port_a, port_b], force = True, mult = rate_multiplier, duration = t_global.args.runtime, total = False)
             else:
                  c.start(ports = [port_a], force = True, mult = rate_multiplier, duration = t_global.args.runtime, total = False)

        timeout = False

        try:
             if t_global.args.run_bidirec:
                  c.wait_on_traffic(ports = [port_a, port_b], timeout = timeout_seconds)
             else:
                  if t_global.args.run_revunidirec:
                       c.wait_on_traffic(ports = [port_b], timeout = timeout_seconds)
                  else:
                       c.wait_on_traffic(ports = [port_a], timeout = timeout_seconds)
             stop_time = datetime.datetime.now()
        except STLTimeoutError as e:
             if t_global.args.run_bidirec:
                  c.stop(ports = [port_a, port_b])
             else:
                  if t_global.args.run_revunidirec:
                       c.stop(ports = [port_b])
                  else:
                       c.stop(ports = [port_a])
             stop_time = datetime.datetime.now()
             myprint("TIMEOUT ERROR: The test did not end on it's own correctly within the allotted time.")
             timeout = True

        # log end of test
        myprint("Finished test at %s" % stop_time.strftime("%H:%M:%S on %Y-%m-%d"))
        total_time = stop_time - start_time
        myprint("Test ran for %d seconds (%s)" % (total_time.total_seconds(), total_time))

        stats = c.get_stats(sync_now = True)
        stats["global"]["runtime"] = total_time.total_seconds()
        stats["global"]["timeout"] = timeout

        for flows_index, flows_id in enumerate(stats["flow_stats"]):
             if flows_id == "global":
                  continue

             flow_tx = 0
             flow_rx = 0

             stats["flow_stats"][flows_id]["loss"] = dict()
             stats["flow_stats"][flows_id]["loss"]["pct"] = dict()
             stats["flow_stats"][flows_id]["loss"]["cnt"] = dict()

             if 0 in stats["flow_stats"][flows_id]["tx_pkts"] and 1 in stats["flow_stats"][flows_id]["rx_pkts"] and stats["flow_stats"][flows_id]["tx_pkts"][0]:
                  stats["flow_stats"][flows_id]["loss"]["pct"]["0->1"] = (1 - (float(stats["flow_stats"][flows_id]["rx_pkts"][1]) / float(stats["flow_stats"][flows_id]["tx_pkts"][0]))) * 100
                  stats["flow_stats"][flows_id]["loss"]["cnt"]["0->1"] = float(stats["flow_stats"][flows_id]["tx_pkts"][0]) - float(stats["flow_stats"][flows_id]["rx_pkts"][1])
                  flow_tx += stats["flow_stats"][flows_id]["tx_pkts"][0]
                  flow_rx += stats["flow_stats"][flows_id]["rx_pkts"][1]
             else:
                  stats["flow_stats"][flows_id]["loss"]["pct"]["0->1"] = "N/A"
                  stats["flow_stats"][flows_id]["loss"]["cnt"]["0->1"] = "N/A"

             if 1 in stats["flow_stats"][flows_id]["tx_pkts"] and 0 in stats["flow_stats"][flows_id]["rx_pkts"] and stats["flow_stats"][flows_id]["tx_pkts"][1]:
                  stats["flow_stats"][flows_id]["loss"]["pct"]["1->0"] = (1 - (float(stats["flow_stats"][flows_id]["rx_pkts"][0]) / float(stats["flow_stats"][flows_id]["tx_pkts"][1]))) * 100
                  stats["flow_stats"][flows_id]["loss"]["cnt"]["1->0"] = float(stats["flow_stats"][flows_id]["tx_pkts"][1]) - float(stats["flow_stats"][flows_id]["rx_pkts"][0])
                  flow_tx += stats["flow_stats"][flows_id]["tx_pkts"][1]
                  flow_rx += stats["flow_stats"][flows_id]["rx_pkts"][0]
             else:
                  stats["flow_stats"][flows_id]["loss"]["pct"]["1->0"] = "N/A"
                  stats["flow_stats"][flows_id]["loss"]["cnt"]["1->0"] = "N/A"

             if flow_tx:
                  stats["flow_stats"][flows_id]["loss"]["pct"]["total"] = (1 - (float(flow_rx) / float(flow_tx))) * 100
                  stats["flow_stats"][flows_id]["loss"]["cnt"]["total"] = float(flow_tx) - float(flow_rx)
             else:
                  stats["flow_stats"][flows_id]["loss"]["pct"]["total"] = "N/A"
                  stats["flow_stats"][flows_id]["loss"]["cnt"]["total"] = "N/A"

        warning_events = c.get_warnings()
        if len(warning_events):
             myprint("TRex Events:")
             for warning in warning_events:
                  myprint("    WARNING: %s" % warning)

        myprint("READABLE RESULT:", stderr_only = True)
        myprint(dump_json_readable(stats), stderr_only = True)
        myprint("PARSABLE RESULT: %s" % dump_json_parsable(stats), stderr_only = True)

        return_value = 0

    except STLError as e:
        myprint(e)

    except ValueError as e:
        myprint("ERROR: %s" % e)

    finally:
        myprint("Disconnecting from TRex server...")
        c.disconnect()
        myprint("Connection severed")
        return return_value

if __name__ == "__main__":
    exit(main())
