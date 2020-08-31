#!/bin/python

from __future__ import print_function

import argparse
from trex_tg_lib import *

class t_global(object):
    args = None

def process_options ():
    parser = argparse.ArgumentParser(usage="postprocess a TRex profile")

    parser.add_argument('--frame-size', 
                        dest='frame_size',
                        help='L2 frame size in bytes',
                        default="64",
                        type = int
                        )
    parser.add_argument('--num-flows', 
                        dest='num_flows',
                        help='Number of unique network flows',
                        default=1024,
                        type = int,
                        )
    parser.add_argument('--use-src-ip-flows', 
                        dest='use_src_ip_flows',
                        help='Implement flows by source IP',
                        action = 'store_true',
                        )
    parser.add_argument('--use-dst-ip-flows', 
                        dest='use_dst_ip_flows',
                        help='Implement flows by destination IP',
                        action = 'store_true',
                        )
    parser.add_argument('--use-src-mac-flows', 
                        dest='use_src_mac_flows',
                        help='Implement flows by source MAC',
                        action = 'store_true',
                        )
    parser.add_argument('--use-dst-mac-flows', 
                        dest='use_dst_mac_flows',
                        help='Implement flows by destination MAC',
                        action = 'store_true',
                        )
    parser.add_argument('--use-src-port-flows',
                        dest='use_src_port_flows',
                        help='Implement flows by source port',
                        action = 'store_true',
                        )
    parser.add_argument('--use-dst-port-flows',
                        dest='use_dst_port_flows',
                        help='Implement flows by destination port',
                        action = 'store_true',
                        )
    parser.add_argument('--use-protocol-flows',
                        dest='use_protocol_flows',
                        help='Implement flows by IP protocol',
                        action = 'store_true',
                        )
    parser.add_argument('--rate', 
                        dest='rate',
                        help='Packet rate per device per stream (mpps)',
                        default = 1.0,
                        type = float
                        )
    parser.add_argument('--measure-latency',
                        dest='measure_latency',
                        help='Collect latency statistics or not',
                        action = 'store_true',
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
    parser.add_argument('--teaching-warmup-packet-type',
                        dest='teaching_warmup_packet_type',
                        help='Type of packet to send for the teaching warmup from the receiving port',
                        default = 'generic',
                        choices = ['garp', 'icmp', 'generic']
                        )
    parser.add_argument('--teaching-measurement-packet-type',
                        dest='teaching_measurement_packet_type',
                        help='Type of packet to send for the teaching measurement from the receiving port',
                        default = 'generic',
                        choices = ['garp', 'icmp', 'generic']
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
    parser.add_argument('--traffic-direction',
                        dest='traffic_direction',
                        help='What direction is the traffic flow?',
                        default = 'bidirectional',
                        choices = ['bidirectional', 'unidirectional', 'revunidirectional']
                        )
    parser.add_argument('--packet-protocol',
                        dest='packet_protocol',
                        help='IP protocol to use when constructing packets',
                        default = "UDP",
                        choices = [ 'UDP', 'TCP' ]
                        )

    t_global.args = parser.parse_args()

    return(0)

def main ():
    ret_val = process_options()
    if ret_val:
        print(error("Input Error"))
        return(ret_val)

    profile = { 'streams': [] }

    flow_mods = create_flow_mod_object(use_src_mac_flows = t_global.args.use_src_mac_flows,
                                       use_dst_mac_flows = t_global.args.use_dst_mac_flows,
                                       use_src_ip_flows = t_global.args.use_src_ip_flows,
                                       use_dst_ip_flows = t_global.args.use_dst_ip_flows,
                                       use_src_port_flows = t_global.args.use_src_port_flows,
                                       use_dst_port_flows = t_global.args.use_dst_port_flows,
                                       use_protocol_flows = t_global.args.use_protocol_flows)

    stream_id = "built-by-profile-builder"

    integrated_teaching_warmup = t_global.args.send_teaching_warmup
    dedicated_teaching_warmup = False
    if t_global.args.send_teaching_warmup and t_global.args.teaching_warmup_packet_type != 'generic':
        dedicated_teaching_warmup = True
        integrated_teaching_warmup = False

    integrated_teaching_measurement = t_global.args.send_teaching_measurement
    dedicated_teaching_measurement = False
    if t_global.args.send_teaching_measurement and t_global.args.teaching_measurement_packet_type != 'generic':
        dedicated_teaching_measurement = True
        integrated_teaching_measurement = False

    stream = create_profile_stream(flows = t_global.args.num_flows,
                                   frame_size = t_global.args.frame_size,
                                   flow_mods = flow_mods,
                                   rate = t_global.args.rate * 1000000.0,
                                   frame_type = 'generic',
                                   measurement = True,
                                   teaching_warmup = integrated_teaching_warmup,
                                   teaching_measurement = integrated_teaching_measurement,
                                   latency = t_global.args.measure_latency,
                                   protocol = t_global.args.packet_protocol,
                                   traffic_direction = t_global.args.traffic_direction,
                                   stream_id = stream_id)

    profile['streams'].append(stream)

    if dedicated_teaching_warmup or dedicated_teaching_measurement:
        if dedicated_teaching_warmup and dedicated_teaching_measurement and t_global.args.teaching_warmup_packet_type == t_global.args.teaching_measurement_packet_type and t_global.args.teaching_warmup_packet_rate == t_global.args.teaching_measurement_packet_rate:
            stream = create_profile_stream(flows = t_global.args.num_flows,
                                           frame_size = t_global.args.frame_size,
                                           flow_mods = flow_mods,
                                           rate = t_global.args.teaching_warmup_packet_rate,
                                           frame_type = t_global.args.teaching_warmup_packet_type,
                                           measurement = False,
                                           teaching_warmup = True,
                                           teaching_measurement = True,
                                           latency = False,
                                           protocol = t_global.args.packet_protocol,
                                           traffic_direction = t_global.args.traffic_direction,
                                           stream_id = stream_id)

            profile['streams'].append(stream)
        else:
            if dedicated_teaching_warmup:
                stream = create_profile_stream(flows = t_global.args.num_flows,
                                               frame_size = t_global.args.frame_size,
                                               flow_mods = flow_mods,
                                               rate = t_global.args.teaching_warmup_packet_rate,
                                               frame_type = t_global.args.teaching_warmup_packet_type,
                                               measurement = False,
                                               teaching_warmup = True,
                                               teaching_measurement = False,
                                               latency = False,
                                               protocol = t_global.args.packet_protocol,
                                               traffic_direction = t_global.args.traffic_direction,
                                               stream_id = stream_id)

                profile['streams'].append(stream)

            if dedicated_teaching_measurement:
                stream = create_profile_stream(flows = t_global.args.num_flows,
                                               frame_size = t_global.args.frame_size,
                                               flow_mods = flow_mods,
                                               rate = t_global.args.teaching_measurement_packet_rate,
                                               frame_type = t_global.args.teaching_measurement_packet_type,
                                               measurement = False,
                                               teaching_warmup = False,
                                               teaching_measurement = True,
                                               latency = False,
                                               protocol = t_global.args.packet_protocol,
                                               traffic_direction = t_global.args.traffic_direction,
                                               stream_id = stream_id)

                profile['streams'].append(stream)

    print(dump_json_readable(profile))

    return(0)

if __name__ == "__main__":
    exit(main())
