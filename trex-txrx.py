import sys, getopt
sys.path.append('/opt/trex-core/scripts/automation/trex_control_plane/stl/examples')
sys.path.append('/opt/trex-core/scripts/automation/trex_control_plane/stl')
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

# simple packet creation
def create_pkt (size, direction, num_flows, src_mac_flows, dst_mac_flows, src_ip_flows, dst_ip_flows):

    ip_range = {'src': {'start': (256**3 *10 +1), 'end': (256**3 *10 +num_flows)}, # 10.x.y.z
                'dst': {'start': (256**3 *8 +1),  'end': (256**3 *8 +num_flows)}}  #  8.x.y.z

    if (direction == 0):
        ip_src = ip_range['src']
        ip_dst = ip_range['dst']
    else:
        ip_src = ip_range['dst']
        ip_dst = ip_range['src']

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

    base = Ether()/IP(src = str(ip_src['start']), dst = str(ip_dst['start']))/UDP()
    pad = max(0, size-len(base)) * 'x'

    if src_ip_flows or dst_ip_flows or src_mac_flows or dst_mac_flows:
         vm = vm + [STLVmFixIpv4(offset = "IP")]
         return STLPktBuilder(pkt = base/pad,
                              vm  = vm)
    else:
         return STLPktBuilder(pkt = base/pad)


def process_options ():
    parser = argparse.ArgumentParser(usage=""" 
    generate network traffic and report packet loss
    """);

    parser.add_argument('--size', 
                        dest='frame_size',
                        help='L2 frame size in bytes',
                        default=64,
                        type = int,
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
                        help='rate in millions of packets per second per device',
                        default = 0.0,
                        type = float
                        )
    #parser.add_argument('--dst-macs-list',
    #                    dest='dst_macs_list',
    #                    help='comma separated list of destination MACs, 1 per device',
    #                    default=""
    #                    )
    #parser.add_argument('--src-macs-list',
    #                    dest='src_macs_list',
    #                    help='comma separated list of src MACs, 1 per device',
    #                    default=""
    #                    )
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
    #parser.add_argument('--dst-ips-list',
    #                    dest='dst_macs_list',
    #                    help='comma separated list of destination IPs 1 per device',
    #                    default=""
    #                    )
    #parser.add_argument('--src-ips-list',
    #                    dest='src_macs_list',
    #                    help='comma separated list of src IPs, 1 per device',
    #                    default=""
    #                    )
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
    t_global.args = parser.parse_args();
    print(t_global.args)

def main():
    process_options()
    port_a = 0
    port_b = 1

    c = STLClient()
    passed = True

    stats = 0

    try:
        # turn this on for some information
        #c.set_verbose("high")

        s1 = STLStream(packet = create_pkt(t_global.args.frame_size - 4, 0, t_global.args.num_flows, t_global.args.use_src_mac_flows, t_global.args.use_dst_mac_flows, t_global.args.use_src_ip_flows, t_global.args.use_dst_ip_flows),
                       flow_stats = STLFlowStats(pg_id = 1),
                       mode = STLTXCont(pps = 100))

	if t_global.args.run_bidirec:
            s2 = STLStream(packet = create_pkt(t_global.args.frame_size - 4, 1, t_global.args.num_flows, t_global.args.use_src_mac_flows, t_global.args.use_dst_mac_flows, t_global.args.use_src_ip_flows, t_global.args.use_dst_ip_flows),
                           flow_stats = STLFlowStats(pg_id = 2),
                           isg = 1000,
                           mode = STLTXCont(pps = 100))

        if t_global.args.measure_latency:
            ls1 = STLStream(packet = create_pkt(t_global.args.frame_size - 4, 0, t_global.args.num_flows, t_global.args.use_src_mac_flows, t_global.args.use_dst_mac_flows, t_global.args.use_src_ip_flows, t_global.args.use_dst_ip_flows),
                            flow_stats = STLFlowLatencyStats(pg_id = 3),
                            mode = STLTXCont(pps = 1000))
            if t_global.args.run_bidirec:
                ls2 = STLStream(packet = create_pkt(t_global.args.frame_size - 4, 1, t_global.args.num_flows, t_global.args.use_src_mac_flows, t_global.args.use_dst_mac_flows, t_global.args.use_src_ip_flows, t_global.args.use_dst_ip_flows),
                                flow_stats = STLFlowLatencyStats(pg_id = 4),
                                isg = 1000,
                                mode = STLTXCont(pps = 1000))

        # connect to server
        c.connect()
        # prepare our ports
        c.reset(ports = [port_a, port_b])
        c.set_port_attr(ports = [port_a, port_b], promiscuous = True)

        # add both streams to ports
        c.add_streams(s1, ports = [port_a])
	if t_global.args.run_bidirec:
            c.add_streams(s2, ports = [port_b])

        if t_global.args.measure_latency:
            c.add_streams(ls1, ports = [port_a])
            if t_global.args.run_bidirec:
                c.add_streams(ls2, ports = [port_b])

        # clear the stats before injecting
        c.clear_stats()

        # log start of test
        print("Starting test at %s" % datetime.datetime.now().strftime("%H:%M:%S on %Y-%m-%d"))

        # here we multiply the traffic lineaer to whatever given in rate
        print("Transmitting {:} Mpps from port {:} -> {:} for {:} seconds...".format(t_global.args.rate, port_a, port_b, t_global.args.runtime))
        if t_global.args.run_bidirec:
            print("Transmitting {:} Mpps from port {:} -> {:} for {:} seconds...".format(t_global.args.rate, port_b, port_a, t_global.args.runtime))
            c.start(ports = [port_a, port_b], mult = (str(t_global.args.rate) + 'mpps'), duration = t_global.args.runtime, total = False)
        else:
            c.start(ports = [port_a], mult = (str(t_global.args.rate) + 'mpps'), duration = t_global.args.runtime, total = False)

        # block until done
        if t_global.args.run_bidirec:
            c.wait_on_traffic(ports = [port_a, port_b])
        else:
            c.wait_on_traffic(ports = [port_a])

        # log end of test
        print("Finished test at %s" % datetime.datetime.now().strftime("%H:%M:%S on %Y-%m-%d"))

        stats = c.get_stats()
        c.disconnect()

    except STLError as e:
        print(e)

    finally:
            c.disconnect()
            print("READABLE RESULT:")
            print(json.dumps(stats, indent = 4, separators=(',', ': '), sort_keys = True))
            print("PARSABLE RESULT: %s" % json.dumps(stats, separators=(',', ':')))

if __name__ == "__main__":
    main()

