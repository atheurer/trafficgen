from __future__ import print_function

import sys, getopt
sys.path.append('/opt/trex/current/automation/trex_control_plane/stl/examples')
sys.path.append('/opt/trex/current/automation/trex_control_plane/stl')
import argparse
import stl_path
import string
import datetime
import math
import threading
import thread
from decimal import *
from trex_stl_lib.api import *
from trex_tg_lib import *

class t_global(object):
     args=None
     constants=None
     variables=None

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

def setup_global_constants ():
     forward_direction = '->'
     reverse_direction = '<-'

     t_global.constants = { 'forward_direction': forward_direction,
                            'reverse_direction': reverse_direction,
                            'both_directions': "%s%s" % (reverse_direction, forward_direction),
                            'directions': [ forward_direction,
                                            reverse_direction ],
                       }

def setup_global_variables ():
     t_global.variables = { 'packet_resources': { 'ips': { 'dynamic_streams': { 'octet_1': 10,
                                                                                'octet_2': { 'start': 2,
                                                                                             'stop': 255,
                                                                                             'current': 2 },
                                                                                'octet_3': 0,
                                                                                'octet_4': 0 },
                                                           'static_streams': { 'octet_1': 10,
                                                                               'octet_2': { 'A': 0,
                                                                                            'B': 1 },
                                                                               'octet_3': { 'A': { 'start': 0,
                                                                                                   'stop': 255,
                                                                                                   'current': 0 },
                                                                                            'B': { 'start': 0,
                                                                                                   'stop': 255,
                                                                                                   'current': 0 } },
                                                                               'octet_4': { 'A': { 'start': 0,
                                                                                                   'stop': 255,
                                                                                                   'current': 0 },
                                                                                            'B': { 'start': 0,
                                                                                                   'stop': 255,
                                                                                                   'current': 0 } } } },
                                                  'ports': { 'src': 32768,
                                                             'dst': 49152 },
                                                  'mac_prefixes': [],
                                                  'stream_ids': {},
                                                  'vlan': None } }


def process_options ():
    parser = argparse.ArgumentParser(usage="generate network traffic and report packet loss")

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
    parser.add_argument('--rate-modifier',
                        dest='rate_modifier',
                        help='Percentage to modifiy the traffic profile\'s specified rates by',
                        default = 100.0,
                        type = float
                        )
    parser.add_argument('--measure-latency',
                        dest='measure_latency',
                        help='Collect latency statistics or not',
                        action = 'store_true'
                        )
    parser.add_argument('--latency-rate',
                        dest='latency_rate',
                        help='Rate to send latency packets per second',
                        default = 1000,
                        type = int
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
    parser.add_argument('--traffic-profile',
                        dest='traffic_profile',
                        help='Name of the file containing traffic profiles to load',
                        default = '',
                        type = str
                        )
    parser.add_argument('--random-seed',
                        dest='random_seed',
                        help='Specify a fixed random seed for repeatable results (defaults to not repeatable)',
                        default = None,
                        type = float
                        )

    t_global.args = parser.parse_args()

    if t_global.args.active_device_pairs == '--':
         t_global.args.active_device_pairs = t_global.args.device_pairs

    random.seed(t_global.args.random_seed)

    myprint(t_global.args)

def get_stream_ip (stream, port_id):
     ip = ""

     if stream['flow_mods']['ip']['dst'] or stream['flow_mods']['ip']['src']:
          if t_global.variables['packet_resources']['ips']['dynamic_streams']['octet_2']['current'] > t_global.variables['packet_resources']['ips']['dynamic_streams']['octet_2']['stop']:
               raise ValueError("Exhausted dynamic stream IP address pool")

          ip = "%d.%d.%d.%d" % (t_global.variables['packet_resources']['ips']['dynamic_streams']['octet_1'],
                                t_global.variables['packet_resources']['ips']['dynamic_streams']['octet_2']['current'],
                                t_global.variables['packet_resources']['ips']['dynamic_streams']['octet_3'],
                                t_global.variables['packet_resources']['ips']['dynamic_streams']['octet_4'])

          t_global.variables['packet_resources']['ips']['dynamic_streams']['octet_2']['current'] += 1
     else:
          if t_global.variables['packet_resources']['ips']['static_streams']['octet_4'][port_id]['current'] > t_global.variables['packet_resources']['ips']['static_streams']['octet_4'][port_id]['stop'] and t_global.variables['packet_resources']['ips']['static_streams']['octet_3'][port_id]['current'] > t_global.variables['packet_resources']['ips']['static_streams']['octet_3'][port_id]['stop']:
               raise ValueError("Exhausted static stream IP address pool")

          ip = "%d.%d.%d.%d" % (t_global.variables['packet_resources']['ips']['static_streams']['octet_1'],
                                t_global.variables['packet_resources']['ips']['static_streams']['octet_2'][port_id],
                                t_global.variables['packet_resources']['ips']['static_streams']['octet_3'][port_id]['current'],
                                t_global.variables['packet_resources']['ips']['static_streams']['octet_4'][port_id]['current'])

          t_global.variables['packet_resources']['ips']['static_streams']['octet_4'][port_id]['current'] += 1
          if t_global.variables['packet_resources']['ips']['static_streams']['octet_4'][port_id]['current'] > t_global.variables['packet_resources']['ips']['static_streams']['octet_4'][port_id]['stop']:
               t_global.variables['packet_resources']['ips']['static_streams']['octet_4'][port_id]['current'] = t_global.variables['packet_resources']['ips']['static_streams']['octet_4'][port_id]['start']
               t_global.variables['packet_resources']['ips']['static_streams']['octet_3'][port_id]['current'] += 1

     return ip

def generate_random_mac ():
     # ensure that we generate a unique prefix (first 4 octets) so
     # that no two streams ever generate the same mac address
     while True:
          mac_prefix = "%02x:%02x:%02x:%02x" % (0x0,
                                                0x16,
                                                0x3e,
                                                random.randint(0, 255))
          if not mac_prefix in t_global.variables['packet_resources']['mac_prefixes']:
               t_global.variables['packet_resources']['mac_prefixes'].append(mac_prefix)
               break

     return "%s:%02x:%02x" % (mac_prefix,
                            random.randint(0, 255),
                            random.randint(0, 255))

def setup_stream_packet_values (stream):
     if stream['stream_id'] and stream['stream_id'] in t_global.variables['packet_resources']['stream_ids']:
          stream['packet_values'] = t_global.variables['packet_resources']['stream_ids'][stream['stream_id']]
     else:
          if not 'packet_values' in stream:
               stream['packet_values'] = { 'ports': { 'A': { 'src': t_global.variables['packet_resources']['ports']['src'],
                                                             'dst': t_global.variables['packet_resources']['ports']['dst'] },
                                                      'B': { 'src': t_global.variables['packet_resources']['ports']['src'],
                                                             'dst': t_global.variables['packet_resources']['ports']['dst'] } },
                                           'ips': { 'A': get_stream_ip(stream, 'A'),
                                                    'B': get_stream_ip(stream, 'B') },
                                           'macs': { 'A': generate_random_mac(),
                                                     'B': generate_random_mac() },
                                           'vlan': { 'A': t_global.variables['packet_resources']['vlan'],
                                                     'B': t_global.variables['packet_resources']['vlan'] } }

          if stream['stream_id']:
               t_global.variables['packet_resources']['stream_ids'][stream['stream_id']] = stream['packet_values']

     return

def create_stream (stream, device_pair, direction, other_direction, flow_scaler):
    # assume direction == t_global.constants['forward_direction']
    src_port = 'A'
    dst_port = 'B'
    if direction == t_global.constants['reverse_direction']:
         src_port = 'B'
         dst_port = 'A'

    protocols = [ stream['protocol'] ]

    latency = stream['latency']
    if not t_global.args.measure_latency:
        latency = False

    if stream['flow_mods']['protocol']:
         if protocols[0] == 'UDP':
              protocols.append('TCP')
         elif protocols[0] == 'TCP':
              protocols.append('UDP')

    stream_modes = [ 'default' ]
    if stream['latency_only']:
        if latency:
            stream_modes = [ 'latency' ]
        else:
            stream_modes = []
    elif latency:
        stream_modes.append('latency')

    stream_flows = int(stream['flows'] * flow_scaler)

    stream_packets = { 'measurement': [],
                       'teaching': [] }
    flow_stats = None
    stream_pg_id = None

    if stream['frame_type'] == 'generic':
         # teaching packets don't need to cover all the protocols; they just need to cover all the MAC addresses
         stream_packets['teaching'].append({ 'protocol': "%s-%s" % (stream['frame_type'], protocols[0]),
                                             'packet':   create_generic_pkt(stream['frame_size'],
                                                                            stream['packet_values']['macs'][dst_port],
                                                                            stream['packet_values']['macs'][src_port],
                                                                            stream['packet_values']['ips'][dst_port],
                                                                            stream['packet_values']['ips'][src_port],
                                                                            stream['packet_values']['ports'][dst_port]['src'],
                                                                            stream['packet_values']['ports'][src_port]['dst'],
                                                                            protocols[0],
                                                                            stream['packet_values']['vlan'][dst_port],
                                                                            stream['flow_mods'],
                                                                            stream_flows,
                                                                            t_global.args.enable_flow_cache,
                                                                            flow_offset = stream['flow_offset'],
                                                                            old_mac_flow = False) })
         for protocol in protocols:
              stream_packets['measurement'].append({ 'protocol': "%s-%s" % (stream['frame_type'], protocol),
                                                     'packet':   create_generic_pkt(stream['frame_size'],
                                                                                    stream['packet_values']['macs'][src_port],
                                                                                    stream['packet_values']['macs'][dst_port],
                                                                                    stream['packet_values']['ips'][src_port],
                                                                                    stream['packet_values']['ips'][dst_port],
                                                                                    stream['packet_values']['ports'][src_port]['src'],
                                                                                    stream['packet_values']['ports'][dst_port]['dst'],
                                                                                    protocol,
                                                                                    stream['packet_values']['vlan'][src_port],
                                                                                    stream['flow_mods'],
                                                                                    stream_flows,
                                                                                    t_global.args.enable_flow_cache,
                                                                                    flow_offset = stream['flow_offset'],
                                                                                    old_mac_flow = False) })
    elif stream['frame_type'] == 'garp':
         # GARP packet types: 0x1=request, 0x2=reply
         garp_packets = [ { 'name': 'request',
                            'opcode': 0x1 },
                          { 'name': 'response',
                            'opcode': 0x2 } ]
         for garp_packet in garp_packets:
              stream_packets['measurement'].append({ 'protocol': "%s-%s" % (stream['frame_type'], garp_packet['name']),
                                                     'packet':   create_garp_pkt(stream['packet_values']['macs'][src_port],
                                                                                 stream['packet_values']['ips'][src_port],
                                                                                 stream['packet_values']['vlan'][src_port],
                                                                                 garp_packet['opcode'],
                                                                                 stream['flow_mods'],
                                                                                 stream_flows,
                                                                                 t_global.args.enable_flow_cache,
                                                                                 flow_offset = stream['flow_offset'],
                                                                                 old_mac_flow = False) })
              stream_packets['teaching'].append({ 'protocol': "%s-%s" % (stream['frame_type'], garp_packet['name']),
                                                  'packet':   create_garp_pkt(stream['packet_values']['macs'][dst_port],
                                                                              stream['packet_values']['ips'][dst_port],
                                                                              stream['packet_values']['vlan'][dst_port],
                                                                              garp_packet['opcode'],
                                                                              stream['flow_mods'],
                                                                              stream_flows,
                                                                              t_global.args.enable_flow_cache,
                                                                              flow_offset = stream['flow_offset'],
                                                                              old_mac_flow = False) })
    elif stream['frame_type'] == 'icmp':
         stream_packets['measurement'].append({ 'protocol': stream['frame_type'],
                                                'packet':   create_icmp_pkt(stream['frame_size'],
                                                                            stream['packet_values']['macs'][src_port],
                                                                            stream['packet_values']['macs'][dst_port],
                                                                            stream['packet_values']['ips'][src_port],
                                                                            stream['packet_values']['ips'][dst_port],
                                                                            stream['packet_values']['vlan'][src_port],
                                                                            stream['flow_mods'],
                                                                            stream_flows,
                                                                            t_global.args.enable_flow_cache,
                                                                            flow_offset = stream['flow_offset'],
                                                                            old_mac_flow = False) })
         stream_packets['teaching'].append({ 'protocol': stream['frame_type'],
                                             'packet':   create_icmp_pkt(stream['frame_size'],
                                                                         stream['packet_values']['macs'][dst_port],
                                                                         stream['packet_values']['macs'][src_port],
                                                                         stream['packet_values']['ips'][dst_port],
                                                                         stream['packet_values']['ips'][src_port],
                                                                         stream['packet_values']['vlan'][dst_port],
                                                                         stream['flow_mods'],
                                                                         stream_flows,
                                                                         t_global.args.enable_flow_cache,
                                                                         flow_offset = stream['flow_offset'],
                                                                         old_mac_flow = False) })
    else:
         raise ValueError("Invalid frame_type: %s" % (stream['frame_type']))

    stream_rate = stream['rate']

    for stream_type in stream['stream_types']:
         if stream_type != 'measurement' and stream_type != 'teaching_warmup' and stream_type != 'teaching_measurement':
              raise ValueError("Invalid stream_type: %s" % (stream_type))

         if stream_type == 'measurement':
              for stream_mode in stream_modes:
                   stream_rate = stream['rate']
                   if len(stream_packets['measurement']) > 1:
                        stream_rate /= len(protocols)

                   if 'latency' in stream_modes and stream_mode == 'default':
                        stream_rate -= t_global.args.latency_rate
                        if stream_rate <= 0:
                             continue
                   elif stream_mode == 'latency' and stream_rate > t_global.args.latency_rate:
                        stream_rate = t_global.args.latency_rate

                   for stream_packet in stream_packets['measurement']:
                        if device_pair[direction]['pg_ids'][stream_mode]['available']:
                             stream_pg_id = device_pair[direction]['pg_ids'][stream_mode]['start_index'] + (device_pair[direction]['pg_ids'][stream_mode]['total'] - device_pair[direction]['pg_ids'][stream_mode]['available'])
                             device_pair[direction]['pg_ids'][stream_mode]['available'] -= 1
                        else:
                             raise RuntimeError("Not enough available pg_ids for the requested stream configuration")
                        stream_name = "%s-stream-%s-%d" % (stream_type, stream_packet['protocol'], stream_pg_id)
                        if stream['stream_id']:
                             stream_name = "%s-%s" % (stream_name, stream['stream_id'])
                        if stream_mode == 'default':
                             flow_stats = STLFlowStats(pg_id = stream_pg_id)
                        elif stream_mode == 'latency':
                             flow_stats = STLFlowLatencyStats(pg_id = stream_pg_id)

                        stream_total_pkts = int(stream_rate * t_global.args.runtime)

                        myprint("\tMeasurement stream for '%s' with flows=%s, frame size=%s, rate=%s, pg_id=%d, mode=%s, and name=%s" % (device_pair[direction]['id_string'],
                                                                                                                                         commify(stream_flows),
                                                                                                                                         commify(stream['frame_size']),
                                                                                                                                         commify(stream_rate),
                                                                                                                                         stream_pg_id,
                                                                                                                                         stream_mode,
                                                                                                                                         stream_name))

                        # check if the total number of packets to TX is greater than can be held in an uint32 (API limit)
                        max_uint32 = int(4294967295)
                        if stream_total_pkts > max_uint32:
                             stream_loops = stream_total_pkts / max_uint32
                             stream_loop_remainder = stream_total_pkts % max_uint32

                             if stream_loop_remainder == 0:
                                  stream_loops -= 1
                                  stream_loops_remainder = max_uint32

                             substream_self_start = True
                             for loop_idx in range(1, stream_loops+1):
                                  substream_name = "%s_sub_%d" % (stream_name, loop_idx)
                                  substream_next_name = "%s_sub_%d" % (stream_name, loop_idx+1)
                                  myprint("\t\tCreating substream %d with name=%s" % (loop_idx, substream_name))
                                  stream_control = STLTXSingleBurst(pps = stream_rate, total_pkts = max_uint32)
                                  device_pair[direction]['traffic_streams'].append(STLStream(packet = stream_packet['packet'],
                                                                                             flow_stats = flow_stats,
                                                                                             mode = stream_control,
                                                                                             name = substream_name,
                                                                                             next = substream_next_name,
                                                                                             self_start = substream_self_start))
                                  substream_self_start = False

                             substream_name = "%s_sub_%d" % (stream_name, stream_loops+1)
                             myprint("\t\tCreating substream %d with name=%s" % (stream_loops+1, substream_name))
                             stream_control = STLTXSingleBurst(pps = stream_rate, total_pkts = stream_loop_remainder)
                             device_pair[direction]['traffic_streams'].append(STLStream(packet = stream_packet['packet'],
                                                                                        flow_stats = flow_stats,
                                                                                        mode = stream_control,
                                                                                        name = substream_name,
                                                                                        next = None,
                                                                                        self_start = substream_self_start))
                        else:
                             stream_control = STLTXSingleBurst(pps = stream_rate, total_pkts = stream_total_pkts)

                             device_pair[direction]['traffic_streams'].append(STLStream(packet = stream_packet['packet'],
                                                                                        flow_stats = flow_stats,
                                                                                        mode = stream_control,
                                                                                        name = stream_name,
                                                                                        next = None,
                                                                                        self_start = True))

                        device_pair[direction]['traffic_profile'][stream_mode]['protocol'].append(stream_packet['protocol'])
                        device_pair[direction]['traffic_profile'][stream_mode]['pps'].append(stream_rate)
                        device_pair[direction]['traffic_profile'][stream_mode]['pg_ids'].append(stream_pg_id)
                        device_pair[direction]['traffic_profile'][stream_mode]['names'].append(stream_name)
                        device_pair[direction]['traffic_profile'][stream_mode]['next_stream_names'].append(None)
                        device_pair[direction]['traffic_profile'][stream_mode]['frame_sizes'].append(stream['frame_size'])
                        device_pair[direction]['traffic_profile'][stream_mode]['traffic_shares'].append(None)
                        device_pair[direction]['traffic_profile'][stream_mode]['self_starts'].append(True)
                        device_pair[direction]['traffic_profile'][stream_mode]['run_time'].append(t_global.args.runtime)
                        device_pair[direction]['traffic_profile'][stream_mode]['stream_modes'].append('burst')
                        device_pair[direction]['traffic_profile'][stream_mode]['flows'].append(stream_flows)
         elif stream_type == 'teaching_warmup' and t_global.args.send_teaching_warmup:
              # if teaching_warmup is the only type for this stream, use the stream's configured rate
              # otherwise use the global default for teaching warmup rate
              if len(stream['stream_types']) != 1:
                   stream_rate = t_global.args.teaching_warmup_packet_rate

              stream_control = STLTXSingleBurst(total_pkts = stream_flows, pps = stream_rate)

              device_pair[direction]['teaching_warmup_max_run_time'] = max(device_pair[direction]['teaching_warmup_max_run_time'],
                                                                           (stream_flows / stream_rate))

              for stream_packet in stream_packets['teaching']:
                   myprint("\tTeaching warmup stream for '%s' with flows=%s, frame size=%s, rate=%s, and protocol=%s" % (device_pair[direction]['id_string'],
                                                                                                                         commify(stream_flows),
                                                                                                                         commify(stream['frame_size']),
                                                                                                                         commify(stream_rate),
                                                                                                                         stream_packet['protocol']))
                   device_pair[other_direction]['teaching_warmup_traffic_streams'].append(STLStream(packet = stream_packet['packet'],
                                                                                                    mode = stream_control,
                                                                                                    next = None,
                                                                                                    self_start = True))
         elif stream_type == 'teaching_measurement' and t_global.args.send_teaching_measurement:
              # if teaching_measurement is the only type for this stream, use the stream's configured rate
              # otherwise use the global default for teaching measurement rate
              if len(stream['stream_types']) != 1:
                   stream_rate = t_global.args.teaching_warmup_packet_rate

              burst_length = stream_flows / stream_rate

              # IBG is in usec, so we multiply by 1,000,000 to convert to seconds
              measurement_mode = STLTXMultiBurst(pkts_per_burst = stream_flows,
                                                 ibg = (t_global.args.teaching_measurement_interval * 1000000),
                                                 count = int(t_global.args.runtime / (t_global.args.teaching_measurement_interval + burst_length)),
                                                 pps = stream_rate)

              for stream_packet in stream_packets['teaching']:
                   myprint("\tTeaching measurement stream for '%s' with flows=%s, frame size=%s, rate=%s, interval=%s, and protocol=%s" % (device_pair[direction]['id_string'],
                                                                                                                                           commify(stream_flows),
                                                                                                                                           commify(stream['frame_size']),
                                                                                                                                           commify(stream_rate),
                                                                                                                                           commify(t_global.args.teaching_measurement_interval),
                                                                                                                                           stream_packet['protocol']))
                   device_pair[other_direction]['teaching_measurement_traffic_streams'].append(STLStream(packet = stream_packet['packet'],
                                                                                                   mode = stream_control,
                                                                                                   next = None,
                                                                                                   self_start = True))
    return

def main():
    setup_global_constants()
    setup_global_variables()
    process_options()

    traffic_profile = {}

    pg_id_values = { "default": { 'available':   None,
                                  'total':       None,
                                  'start_index': None },
                     "latency": { 'available':   None,
                                  'total':       None,
                                  'start_index': None } }

    stream_profile_object = { 'protocol': [],
                              'pps': [],
                              'pg_ids': [],
                              'names': [],
                              'next_stream_names': [],
                              'frame_sizes': [],
                              'traffic_shares': [],
                              'self_starts': [],
                              'run_time': [],
                              'stream_modes': [],
                              'flows': [] }

    claimed_device_pairs = []
    for device_pair in t_global.args.device_pairs.split(','):
         ports = device_pair.split(':')
         port_a = int(ports[0])
         port_b = int(ports[1])
         claimed_device_pairs.extend([port_a, port_b])

    all_ports = []
    measurement_ports = []
    teaching_ports = []

    device_pairs = []
    for device_pair in t_global.args.active_device_pairs.split(','):
         ports = device_pair.split(':')
         port_a = int(ports[0])
         port_b = int(ports[1])

         myprint("Configuring device pair: %s" % (device_pair))
         all_ports.extend([port_a, port_b])

         device_pairs.append({ t_global.constants['forward_direction']: { 'ports': { 'tx': port_a,
                                                                                     'rx': port_b },
                                                                          'id_string': "%s%s%s" % (port_a, t_global.constants['forward_direction'], port_b),
                                                                          'pg_ids': copy.deepcopy(pg_id_values),
                                                                          'traffic_profile': { 'default': copy.deepcopy(stream_profile_object),
                                                                                               'latency': copy.deepcopy(stream_profile_object) },
                                                                          'traffic_streams': [],
                                                                          'teaching_warmup_traffic_streams': [],
                                                                          'teaching_warmup_max_run_time': 0,
                                                                          'teaching_measurement_traffic_streams': [] },
                               t_global.constants['reverse_direction']: { 'ports': { 'tx': port_b,
                                                                                     'rx': port_a },
                                                                          'id_string': "%s%s%s" % (port_a, t_global.constants['reverse_direction'], port_b),
                                                                          'pg_ids': copy.deepcopy(pg_id_values),
                                                                          'traffic_profile': { 'default': copy.deepcopy(stream_profile_object),
                                                                                               'latency': copy.deepcopy(stream_profile_object) },
                                                                          'traffic_streams': [],
                                                                          'teaching_warmup_traffic_streams': [],
                                                                          'teaching_warmup_max_run_time': 0,
                                                                          'teaching_measurement_traffic_streams': [] },
                               'max_default_pg_ids': 0,
                               'max_latency_pg_ids': 0,
                               'device_pair': device_pair })

    stats = 0
    return_value = 1

    traffic_profile = load_traffic_profile(traffic_profile = t_global.args.traffic_profile,
                                           rate_modifier = t_global.args.rate_modifier)
    if not 'streams' in traffic_profile:
         return return_value

    for stream in traffic_profile['streams']:
         setup_stream_packet_values(stream)

    myprint("READABLE TRAFFIC PROFILE:", stderr_only = True)
    myprint(dump_json_readable(traffic_profile), stderr_only = True)
    myprint("PARSABLE TRAFFIC PROFILE: %s" % dump_json_parsable(traffic_profile), stderr_only = True)

    c = STLClient()

    try:
        if t_global.args.debug:
             # turn this on for some information
             c.set_verbose("high")

        # connect to server
        myprint("Establishing connection to TRex server...")
        c.connect()
        myprint("Connection established")

        # prepare our ports
        c.acquire(ports = claimed_device_pairs, force=True)
        c.reset(ports = claimed_device_pairs)
        c.set_port_attr(ports = all_ports, promiscuous = True)

        port_info = c.get_port_info(ports = claimed_device_pairs)
        myprint("READABLE PORT INFO:", stderr_only = True)
        myprint(dump_json_readable(port_info), stderr_only = True)
        myprint("PARSABLE PORT INFO: %s" % dump_json_parsable(port_info), stderr_only = True)

        port_speed_verification_fail = False
        for device_pair in device_pairs:
            for direction in t_global.constants['directions']:
                if port_info[device_pair[direction]['ports']['tx']]['speed'] == 0:
                    port_speed_verification_fail = True
                    myprint("ERROR: Device with port index = %d failed speed verification test" % device_pair[direction]['ports']['tx'])

        if port_speed_verification_fail:
             raise RuntimeError("Failed port speed verification")

        for device_pair in device_pairs:
             if port_info[device_pair[t_global.constants['forward_direction']]['ports']['tx']]["rx"]["counters"] <= port_info[device_pair[t_global.constants['forward_direction']]['ports']['rx']]["rx"]["counters"]:
                  device_pair['max_default_pg_ids'] = port_info[device_pair[t_global.constants['forward_direction']]['ports']['tx']]["rx"]["counters"] / len(device_pairs)
             else:
                  device_pair['max_default_pg_ids'] = port_info[device_pair[t_global.constants['forward_direction']]['ports']['rx']]["rx"]["counters"] / len(device_pairs)

             device_pair['max_latency_pg_ids'] = 128 / len(device_pairs) # 128 is the maximum number of software counters for latency in TRex

        pg_id_base = 1000
        for device_pair in device_pairs:
             device_pair[t_global.constants['forward_direction']]['pg_ids']['default']['total']       = device_pair['max_default_pg_ids'] / 2
             device_pair[t_global.constants['forward_direction']]['pg_ids']['default']['available']   = device_pair[t_global.constants['forward_direction']]['pg_ids']['default']['total']
             device_pair[t_global.constants['forward_direction']]['pg_ids']['default']['start_index'] = pg_id_base
             device_pair[t_global.constants['forward_direction']]['pg_ids']['latency']['total']       = device_pair['max_latency_pg_ids'] / 2
             device_pair[t_global.constants['forward_direction']]['pg_ids']['latency']['available']   = device_pair[t_global.constants['forward_direction']]['pg_ids']['latency']['total']
             device_pair[t_global.constants['forward_direction']]['pg_ids']['latency']['start_index'] = device_pair[t_global.constants['forward_direction']]['pg_ids']['default']['start_index'] + device_pair[t_global.constants['forward_direction']]['pg_ids']['default']['total']

             device_pair[t_global.constants['reverse_direction']]['pg_ids']['default']['total']       = device_pair[t_global.constants['forward_direction']]['pg_ids']['default']['total']
             device_pair[t_global.constants['reverse_direction']]['pg_ids']['default']['available']   = device_pair[t_global.constants['reverse_direction']]['pg_ids']['default']['total']
             device_pair[t_global.constants['reverse_direction']]['pg_ids']['default']['start_index'] = device_pair[t_global.constants['forward_direction']]['pg_ids']['default']['start_index'] + device_pair[t_global.constants['forward_direction']]['pg_ids']['default']['total'] + device_pair[t_global.constants['forward_direction']]['pg_ids']['latency']['total']
             device_pair[t_global.constants['reverse_direction']]['pg_ids']['latency']['total']       = device_pair[t_global.constants['forward_direction']]['pg_ids']['latency']['total']
             device_pair[t_global.constants['reverse_direction']]['pg_ids']['latency']['available']   = device_pair[t_global.constants['reverse_direction']]['pg_ids']['latency']['total']
             device_pair[t_global.constants['reverse_direction']]['pg_ids']['latency']['start_index'] = device_pair[t_global.constants['reverse_direction']]['pg_ids']['default']['start_index'] + device_pair[t_global.constants['reverse_direction']]['pg_ids']['default']['total']

             pg_id_base = pg_id_base + device_pair['max_default_pg_ids'] + device_pair['max_latency_pg_ids']

        myprint("Creating Streams from loaded traffic profile [%s]" % (t_global.args.traffic_profile))
        flow_port_divider = 1.0 / len(device_pairs)
        for device_pair in device_pairs:
            for stream in traffic_profile['streams']:
                 if stream['direction'] == t_global.constants['forward_direction'] or stream['direction'] == t_global.constants['both_directions']:
                      create_stream(stream, device_pair, t_global.constants['forward_direction'], t_global.constants['reverse_direction'], flow_port_divider)

                 if stream['direction'] == t_global.constants['reverse_direction'] or stream['direction'] == t_global.constants['both_directions']:
                      create_stream(stream, device_pair, t_global.constants['reverse_direction'], t_global.constants['forward_direction'], flow_port_divider)

                 # update the flow offset so that each port gets unique flows for the same stream
                 stream['flow_offset'] += int(stream['flows'] * flow_port_divider)

            for direction in t_global.constants['directions']:
                if len(device_pair[direction]['traffic_streams']):
                    myprint("DEVICE PAIR %s | READABLE STREAMS FOR DIRECTION '%s':" % (device_pair['device_pair'], device_pair[direction]['id_string']), stderr_only = True)
                    myprint(dump_json_readable(device_pair[direction]['traffic_profile']), stderr_only = True)
                    myprint("DEVICE PAIR %s | PARSABLE STREAMS FOR DIRECTION '%s': %s" % (device_pair['device_pair'], device_pair[direction]['id_string'], dump_json_parsable(device_pair[direction]['traffic_profile'])), stderr_only = True)

        if t_global.args.send_teaching_warmup:
             warmup_ports = []

             myprint("Teaching Warmup")
             for device_pair in device_pairs:
                  for direction in t_global.constants['directions']:
                       if len(device_pair[direction]['teaching_warmup_traffic_streams']):
                            myprint("\tAdding stream(s) for '%s'" % (device_pair[direction]['id_string']))
                            c.add_streams(streams = device_pair[direction]['teaching_warmup_traffic_streams'], ports = device_pair[direction]['ports']['tx'])
                            warmup_ports.append(device_pair[direction]['ports']['tx'])

             if len(warmup_ports):
                  warmup_timeout = 30.0
                  for device_pair in device_pairs:
                       for direction in t_global.constants['directions']:
                            warmup_timeout = int(max(warmup_timeout, device_pair[direction]['teaching_warmup_max_run_time'] * 1.05))

                  start_time = datetime.datetime.now()
                  myprint("\tStarting transmission at %s" % (start_time.strftime("%H:%M:%S on %Y-%m-%d")))

                  timeout_time = start_time + datetime.timedelta(seconds = warmup_timeout)
                  myprint("\tThe transmission will timeout with an error at %s" % (timeout_time.strftime("%H:%M:%S on %Y-%m-%d")))

                  try:
                       c.start(ports = warmup_ports, force = True)
                       c.wait_on_traffic(ports = warmup_ports, timeout = warmup_timeout)

                       stop_time = datetime.datetime.now()
                       total_time = stop_time - start_time
                       myprint("\tFinished transmission at %s" % (stop_time.strftime("%H:%M:%S on %Y-%m-%d")))
                       myprint("\tWarmup ran for %s second(s) (%s)" % (commify(total_time.total_seconds()), total_time))
                  except STLTimeoutError as e:
                       c.stop(ports = warmup_ports)
                       stop_time = datetime.datetime.now()
                       total_time = stop_time - start_time
                       myprint("TIMEOUT ERROR: The teaching warmup did not end on it's own correctly within the allotted time (%s seconds) -- %s total second(s) elapsed" % (commify(warmup_timeout), commify(total_time.total_seconds())))
                       return return_value
                  except STLError as e:
                       c.stop(ports = warmup_ports)
                       myprint("ERROR: wait_on_traffic: STLError: %s" % e)
                       return return_value

                  c.reset(ports = warmup_ports)
                  c.set_port_attr(ports = warmup_ports, promiscuous = True)
             else:
                  myprint("\tNo streams configured")

        run_ports = []

        myprint("Measurement")
        for device_pair in device_pairs:
             for direction in t_global.constants['directions']:
                  port_streams = 0

                  if len(device_pair[direction]['traffic_streams']):
                       myprint("\tAdding measurement stream(s) for '%s'" % (device_pair[direction]['id_string']))
                       port_streams += len(device_pair[direction]['traffic_streams'])
                       c.add_streams(streams = device_pair[direction]['traffic_streams'], ports = device_pair[direction]['ports']['tx'])

                  if t_global.args.send_teaching_measurement and len(device_pair[direction]['teaching_measurement_traffic_streams']):
                       myprint("\tAdding teaching stream(s) for '%s'" % (device_pair[direction]['id_string']))
                       port_streams += len(device_pair[direction]['teaching_measurement_traffic_streams'])
                       c.add_streams(streams = device_pair[direction]['teaching_measurement_traffic_streams'], ports = device_pair[direction]['ports']['tx'])

                  if port_streams:
                       run_ports.append(device_pair[direction]['ports']['tx'])

        myprint("DEVICE PAIR INFORMATION:", stderr_only = True)
        myprint(dump_json_readable(device_pairs), stderr_only = True)
        myprint("DEVICE PAIR INFORMATION: %s" % dump_json_parsable(device_pairs), stderr_only = True)

        # clear the event log
        c.clear_events()

        # clear the stats
        c.clear_stats(ports = all_ports)

        # log start of test
        timeout_seconds = math.ceil(float(t_global.args.runtime) * (1 + (float(t_global.args.runtime_tolerance) / 100)))
        stop_time = datetime.datetime.now()
        start_time = datetime.datetime.now()
        myprint("\tStarting test at %s" % start_time.strftime("%H:%M:%S on %Y-%m-%d"))
        expected_end_time = start_time + datetime.timedelta(seconds = t_global.args.runtime)
        expected_timeout_time = start_time + datetime.timedelta(seconds = timeout_seconds)
        myprint("\tThe test should end at %s" % expected_end_time.strftime("%H:%M:%S on %Y-%m-%d"))
        myprint("\tThe test will timeout with an error at %s" % expected_timeout_time.strftime("%H:%M:%S on %Y-%m-%d"))

        # start the traffic
        c.start(ports = run_ports, force = True, duration = t_global.args.runtime, total = False, core_mask = STLClient.CORE_MASK_PIN)

        timeout = False
        force_quit = False

        try:
             c.wait_on_traffic(ports = run_ports, timeout = timeout_seconds)
             stop_time = datetime.datetime.now()
        except STLTimeoutError as e:
             c.stop(ports = run_ports)
             stop_time = datetime.datetime.now()
             myprint("TIMEOUT ERROR: The test did not end on it's own correctly within the allotted time.")
             timeout = True
        except STLError as e:
             c.stop(ports = run_ports)
             stop_time = datetime.datetime.now()
             myprint("ERROR: wait_on_traffic: STLError: %s" % e)
             force_quit = True

        # log end of test
        myprint("\tFinished test at %s" % stop_time.strftime("%H:%M:%S on %Y-%m-%d"))
        total_time = stop_time - start_time
        myprint("\tTrial ran for %s second(s) (%s)" % (commify(total_time.total_seconds()), total_time))

        stats = c.get_stats(sync_now = True)
        stats["global"]["runtime"] = total_time.total_seconds()
        stats["global"]["timeout"] = timeout
        stats["global"]["force_quit"] = force_quit
        stats["global"]["early_exit"] = False

        for device_pair in device_pairs:
             for flows_index, flows_id in enumerate(stats["flow_stats"]):
                  if flows_id == "global":
                       continue

                  if not int(flows_id) in device_pair[t_global.constants['forward_direction']]['traffic_profile']['default']['pg_ids'] and not int(flows_id) in device_pair[t_global.constants['reverse_direction']]['traffic_profile']['default']['pg_ids'] and not int(flows_id) in device_pair[t_global.constants['forward_direction']]['traffic_profile']['latency']['pg_ids'] and not int(flows_id) in device_pair[t_global.constants['reverse_direction']]['traffic_profile']['latency']['pg_ids']:
                       continue

                  flow_tx = 0
                  flow_rx = 0

                  if not "loss" in stats["flow_stats"][flows_id]:
                       stats["flow_stats"][flows_id]["loss"] = dict()
                       stats["flow_stats"][flows_id]["loss"]["pct"] = dict()
                       stats["flow_stats"][flows_id]["loss"]["cnt"] = dict()

                  for direction in t_global.constants['directions']:
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
             myprint("\tTRex Warning Events:")
             for warning in warning_events:
                  myprint("\t\t%s" % warning)

        events = c.get_events()
        if len(events):
             myprint("\tTRex Events:")
             for event in events:
                  myprint("\t\t%s" % event)

        myprint("\tStatistics")
        myprint("\t\tTX Utilization: %s%%" % (commify(stats['global']['cpu_util'])))
        myprint("\t\tRX Utilization: %s%%" % (commify(stats['global']['rx_cpu_util'])))
        myprint("\t\tTX Queue Full:  %s"   % (commify(stats['global']['queue_full'])))

        myprint("READABLE RESULT:", stderr_only = True)
        myprint(dump_json_readable(stats), stderr_only = True)
        myprint("PARSABLE RESULT: %s" % dump_json_parsable(stats), stderr_only = True)

        return_value = 0

    except STLError as e:
        myprint("STLERROR: %s" % e)

    except (ValueError, RuntimeError) as e:
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
