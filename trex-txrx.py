import sys, getopt
sys.path.append('/opt/trex/current/automation/trex_control_plane/stl/examples')
sys.path.append('/opt/trex/current/automation/trex_control_plane/stl')
import argparse
import stl_path
import time
import json
import string
import datetime
from decimal import *
from trex_stl_lib.api import *

class t_global(object):
     args=None;

def ip_to_int (ip):
    ip_fields = ip.split(".")
    if len(ip_fields) != 4:
         raise ValueError("IP addresses should be in the form of W.X.Y.Z")
    ip_int = 256**3 * int(ip_fields[0]) + 256**2 * int(ip_fields[1]) + 256**1 * int(ip_fields[2]) + int(ip_fields[3])
    return ip_int

def calculate_latency_pps (dividend, divisor, total_rate):
     return int((float(dividend) / float(divisor) * total_rate))

def create_traffic_profile (direction, measure_latency, default_stream_pg_id_base, latency_stream_pg_id_base, latency_rate, frame_size, num_flows, src_mac_flows, dst_mac_flows, src_ip_flows, dst_ip_flows, mac_src, mac_dst, ip_src, ip_dst):
     streams = { 'default': { 'pg_ids': [], 'names': [], 'frame_sizes': [], 'traffic_shares': [] }, 'latency': { 'pg_ids': [], 'names': [], 'frame_sizes': [], 'traffic_shares': [] } }

     ethernet_frame_overhead = 18

     if frame_size == "imix":
          # imix is defined as the following packets (including IP header): 7 of size 40 bytes, 4 of size 576 bytes, and 1 of size 1500 bytes
          # from https://en.wikipedia.org/wiki/Internet_Mix

          small_packets = 7
          medium_packets = 4
          large_packets = 1
          total_packets = small_packets + medium_packets + large_packets

          small_packet_bytes = 40 + ethernet_frame_overhead
          medium_packet_bytes = 576 + ethernet_frame_overhead
          large_packet_bytes = 1500 + ethernet_frame_overhead

          small_stream_pg_id = default_stream_pg_id_base
          medium_stream_pg_id = default_stream_pg_id_base + 1
          large_stream_pg_id = default_stream_pg_id_base + 2

          small_stream_name = "small_stream_" + direction
          medium_stream_name = "medium_stream_" + direction
          large_stream_name = "large_stream_" + direction

          streams['default']['pg_ids'].extend([small_stream_pg_id, medium_stream_pg_id, large_stream_pg_id])
          streams['default']['names'].extend([small_stream_name, medium_stream_name, large_stream_name])
          streams['default']['frame_sizes'].extend([small_packet_bytes, medium_packet_bytes, large_packet_bytes])
          streams['default']['traffic_shares'].extend([(float(small_packets)/float(total_packets)), (float(medium_packets)/float(total_packets)), (float(large_packets)/float(total_packets))])

          small_stream = STLStream(packet = create_pkt(small_packet_bytes, num_flows, src_mac_flows, dst_mac_flows, src_ip_flows, dst_ip_flows, mac_src, mac_dst, ip_src, ip_dst),
                                   flow_stats = STLFlowStats(pg_id = small_stream_pg_id),
                                   mode = STLTXCont(pps = small_packets),
                                   name = small_stream_name)

          medium_stream = STLStream(packet = create_pkt(medium_packet_bytes, num_flows, src_mac_flows, dst_mac_flows, src_ip_flows, dst_ip_flows, mac_src, mac_dst, ip_src, ip_dst),
                                    flow_stats = STLFlowStats(pg_id = medium_stream_pg_id),
                                    mode = STLTXCont(pps = medium_packets),
                                    name = medium_stream_name)

          large_stream = STLStream(packet = create_pkt(large_packet_bytes, num_flows, src_mac_flows, dst_mac_flows, src_ip_flows, dst_ip_flows, mac_src, mac_dst, ip_src, ip_dst),
                                   flow_stats = STLFlowStats(pg_id = large_stream_pg_id),
                                   mode = STLTXCont(pps = large_packets),
                                   name = large_stream_name)

          if measure_latency:
               small_latency_stream_pg_id = latency_stream_pg_id_base
               medium_latency_stream_pg_id = latency_stream_pg_id_base + 1
               large_latency_stream_pg_id = latency_stream_pg_id_base + 2

               small_latency_stream_name = "small_latency_stream_" + direction
               medium_latency_stream_name = "medium_latency_stream_" + direction
               large_latency_stream_name = "large_latency_stream_" + direction

               streams['latency']['pg_ids'].extend([small_latency_stream_pg_id, medium_latency_stream_pg_id, large_latency_stream_pg_id])
               streams['latency']['names'].extend([small_latency_stream_name, medium_latency_stream_name, large_latency_stream_name])
               streams['latency']['frame_sizes'].extend([small_packet_bytes, medium_packet_bytes, large_packet_bytes])
               streams['latency']['traffic_shares'].extend([(float(small_packets)/float(total_packets)), (float(medium_packets)/float(total_packets)), (float(large_packets)/float(total_packets))])

               small_latency_stream = STLStream(packet = create_pkt(small_packet_bytes, num_flows, src_mac_flows, dst_mac_flows, src_ip_flows, dst_ip_flows, mac_src, mac_dst, ip_src, ip_dst),
                                                flow_stats = STLFlowLatencyStats(pg_id = small_latency_stream_pg_id),
                                                mode = STLTXCont(pps = calculate_latency_pps(small_packets, total_packets, latency_rate)),
                                                name = small_latency_stream_name)

               medium_latency_stream = STLStream(packet = create_pkt(medium_packet_bytes, num_flows, src_mac_flows, dst_mac_flows, src_ip_flows, dst_ip_flows, mac_src, mac_dst, ip_src, ip_dst),
                                                 flow_stats = STLFlowLatencyStats(pg_id = medium_latency_stream_pg_id),
                                                 mode = STLTXCont(pps = calculate_latency_pps(medium_packets, total_packets, latency_rate)),
                                                 name = medium_latency_stream_name)

               large_latency_stream = STLStream(packet = create_pkt(large_packet_bytes, num_flows, src_mac_flows, dst_mac_flows, src_ip_flows, dst_ip_flows, mac_src, mac_dst, ip_src, ip_dst),
                                                flow_stats = STLFlowLatencyStats(pg_id = large_latency_stream_pg_id),
                                                mode = STLTXCont(pps = calculate_latency_pps(large_packets, total_packets, latency_rate)),
                                                name = large_latency_stream_name)

               profile = STLProfile([ small_stream, medium_stream, large_stream, small_latency_stream, medium_latency_stream, large_latency_stream ])
          else:
               profile = STLProfile([ small_stream, medium_stream, large_stream ])
     else:
          default_stream_pg_id = default_stream_pg_id_base

          default_stream_name = "default_stream_" + direction

          streams['default']['pg_ids'].extend([default_stream_pg_id])
          streams['default']['names'].extend([default_stream_name])
          streams['default']['frame_sizes'].extend([int(frame_size)])
          streams['default']['traffic_shares'].extend([1])

          default_stream = STLStream(packet = create_pkt(frame_size, num_flows, src_mac_flows, dst_mac_flows, src_ip_flows, dst_ip_flows, mac_src, mac_dst, ip_src, ip_dst),
                                     flow_stats = STLFlowStats(pg_id = default_stream_pg_id),
                                     mode = STLTXCont(pps = 100),
                                     name = default_stream_name)

          if measure_latency:
               latency_stream_pg_id = latency_stream_pg_id_base

               latency_stream_name = "latency_stream_" + direction

               streams['latency']['pg_ids'].extend([latency_stream_pg_id])
               streams['latency']['names'].extend([latency_stream_name])
               streams['latency']['frame_sizes'].extend([int(frame_size)])
               streams['latency']['traffic_shares'].extend([1])

               latency_stream = STLStream(packet = create_pkt(frame_size, num_flows, src_mac_flows, dst_mac_flows, src_ip_flows, dst_ip_flows, mac_src, mac_dst, ip_src, ip_dst),
                                          flow_stats = STLFlowLatencyStats(pg_id = latency_stream_pg_id),
                                          mode = STLTXCont(pps = latency_rate),
                                          name = latency_stream_name)

               profile = STLProfile([ default_stream, latency_stream ])
          else:
               profile = STLProfile([ default_stream ])

     print("READABLE STREAMS FOR DIRECTION '%s':" % direction)
     print(json.dumps(streams, indent = 4, separators=(',', ': '), sort_keys = True))
     print("PARSABLE STREAMS FOR DIRECTION '%s': %s" % (direction, json.dumps(streams, separators=(',', ': '))))

     return profile

# simple packet creation
def create_pkt (size, num_flows, src_mac_flows, dst_mac_flows, src_ip_flows, dst_ip_flows, mac_src, mac_dst, ip_src, ip_dst):
    # adjust packet size
    size = int(size)
    size -= 4

    ip_src = { "start": ip_to_int(ip_src), "end": ip_to_int(ip_src) + num_flows }
    ip_dst = { "start": ip_to_int(ip_dst), "end": ip_to_int(ip_dst) + num_flows }

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

    base = Ether(src = mac_src, dst = mac_dst)/IP(src = str(ip_src['start']), dst = str(ip_dst['start']))/UDP()
    pad = max(0, size-len(base)) * 'x'

    the_packet = base/pad
    #the_packet.show2()

    if src_ip_flows or dst_ip_flows or src_mac_flows or dst_mac_flows:
         vm = vm + [STLVmFixIpv4(offset = "IP")]
         return STLPktBuilder(pkt = the_packet,
                              vm  = vm)
    else:
         return STLPktBuilder(pkt = the_packet)


def process_options ():
    parser = argparse.ArgumentParser(usage=""" 
    generate network traffic and report packet loss
    """);

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
    parser.add_argument('--runtime', 
                        dest='runtime',
                        help='tiral period in seconds',
                        default=30,
                        type = int,
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
    t_global.args = parser.parse_args();
    if t_global.args.frame_size == "IMIX":
         t_global.args.frame_size = "imix"
    print(t_global.args)

def main():
    process_options()
    port_a = 0
    port_b = 1

    c = STLClient()
    passed = True

    stats = 0

    active_ports = 1
    if t_global.args.run_bidirec:
         active_ports += 1

    try:
        # turn this on for some information
        #c.set_verbose("high")

        # connect to server
        c.connect()

        # prepare our ports
        c.acquire(ports = [port_a, port_b], force=True)
        c.reset(ports = [port_a, port_b])
        c.set_port_attr(ports = [port_a, port_b], promiscuous = True)

        port_info = c.get_port_info(ports = [port_a, port_b])
        print("READABLE PORT INFO:")
        print(json.dumps(port_info, indent = 4, separators=(',', ': '), sort_keys = True))
        print("PARSABLE PORT INFO: %s" % json.dumps(port_info, separators=(',', ':')))

        mac_a_src = port_info[port_a]["src_mac"]
        mac_a_dst = port_info[port_b]["src_mac"]
        mac_b_src = port_info[port_b]["src_mac"]
        mac_b_dst = port_info[port_a]["src_mac"]

        ip_a_src = "10.0.0.1"
        ip_a_dst = "8.0.0.1"
        ip_b_src = ip_a_dst
        ip_b_dst = ip_a_src

        if len(t_global.args.src_macs_list):
             src_macs = t_global.args.src_macs_list.split(",")
             if len(src_macs) < active_ports:
                  raise ValueError("--src-macs-list should be a comma separated list of at least %d MAC address(es)" % active_ports)
             mac_a_src = src_macs[0]
             if t_global.args.run_bidirec:
                  mac_b_src = src_macs[1]

        if len(t_global.args.dst_macs_list):
             dst_macs = t_global.args.dst_macs_list.split(",")
             if len(dst_macs) < active_ports:
                  raise ValueError("--dst-macs-list should be a comma separated list of at least %d MAC address(es)" % active_ports)
             mac_a_dst = dst_macs[0]
             if t_global.args.run_bidirec:
                  mac_b_dst = dst_macs[1]

        if len(t_global.args.src_ips_list):
             src_ips = t_global.args.src_ips_list.split(",")
             if len(src_ips) < active_ports:
                  raise ValueError("--src-ips-list should be a comma separated list of at least %d IP address(es)" % active_ports)
             ip_a_src = src_ips[0]
             if t_global.args.run_bidirec:
                  ip_b_src = src_ips[1]

        if len(t_global.args.dst_ips_list):
             dst_ips = t_global.args.dst_ips_list.split(",")
             if len(dst_ips) < active_ports:
                  raise ValueError("--dst-ips-list should be a comma separated list of at least %d IP address(es)" % active_ports)
             ip_a_dst = dst_ips[0]
             if t_global.args.run_bidirec:
                  ip_b_dst = dst_ips[1]

        # dedicate 128 (this is somewhat arbitrary; it is a 32bit id) packet group ids (pg_ids) to each direction: base_a=128 and base_b=256
        # there are a maximum of 128 concurrent latency streams (with unique pg_ids) so dedicate 64 to each direction: latency_base_a=0 and latency_base_b=64

        traffic_profile = create_traffic_profile("a", t_global.args.measure_latency, 128, 0, t_global.args.latency_rate, t_global.args.frame_size, t_global.args.num_flows, t_global.args.use_src_mac_flows, t_global.args.use_dst_mac_flows, t_global.args.use_src_ip_flows, t_global.args.use_dst_ip_flows, mac_a_src, mac_a_dst, ip_a_src, ip_a_dst)
        c.add_streams(streams = traffic_profile, ports = [port_a])

        if t_global.args.run_bidirec:
             traffic_profile = create_traffic_profile("b", t_global.args.measure_latency, 256, 64, t_global.args.latency_rate, t_global.args.frame_size, t_global.args.num_flows, t_global.args.use_src_mac_flows, t_global.args.use_dst_mac_flows, t_global.args.use_src_ip_flows, t_global.args.use_dst_ip_flows, mac_b_src, mac_b_dst, ip_b_src, ip_b_dst)
             c.add_streams(streams = traffic_profile, ports = [port_b])

        # clear the stats before injecting
        c.clear_stats()

        # clear the event log
        c.clear_events()

        # if latency is enabled the requested packet rate needs to be
        # adjusted to account for the latency streams
        rate_multiplier = t_global.args.rate
        if t_global.args.rate_unit == "mpps" and t_global.args.measure_latency:
             rate_multiplier -= (float(t_global.args.latency_rate) / 1000000)

        # log start of test
        start_time = datetime.datetime.now()
        print("Starting test at %s" % start_time.strftime("%H:%M:%S on %Y-%m-%d"))

        # here we multiply the traffic lineaer to whatever given in rate
        print("Transmitting at {:}{:} from port {:} -> {:} for {:} seconds...".format(t_global.args.rate, t_global.args.rate_unit, port_a, port_b, t_global.args.runtime))
        if t_global.args.run_bidirec:
            print("Transmitting at {:}{:} from port {:} -> {:} for {:} seconds...".format(t_global.args.rate, t_global.args.rate_unit, port_b, port_a, t_global.args.runtime))
            c.start(ports = [port_a, port_b], force = True, mult = (str(rate_multiplier) + t_global.args.rate_unit), duration = -1, total = False)
        else:
            c.start(ports = [port_a], force = True, mult = (str(rate_multiplier) + t_global.args.rate_unit), duration = -1, total = False)

        time.sleep(t_global.args.runtime)

        if t_global.args.run_bidirec:
             c.stop(ports = [port_a, port_b])
        else:
             c.stop(ports = [port_a])

        # log end of test
        stop_time = datetime.datetime.now()
        print("Finished test at %s" % stop_time.strftime("%H:%M:%S on %Y-%m-%d"))
        total_time = stop_time - start_time
        print("Test ran for %d seconds (%s)" % (total_time.total_seconds(), total_time))

        stats = c.get_stats(sync_now = True)

        warning_events = c.get_warnings()
        if len(warning_events):
             print("TRex Events:")
             for warning in warning_events:
                  print("    WARNING: %s" % warning)

        c.disconnect()

        print("READABLE RESULT:")
        print(json.dumps(stats, indent = 4, separators=(',', ': '), sort_keys = True))
        print("PARSABLE RESULT: %s" % json.dumps(stats, separators=(',', ':')))

    except STLError as e:
        print(e)

    except ValueError as e:
        print("ERROR: %s" % e)

    finally:
            c.disconnect()

if __name__ == "__main__":
    main()

