from __future__ import print_function

import sys, getopt
sys.path.append('/opt/trex/current/automation/trex_control_plane/interactive')
import argparse
import string
import datetime
import math
import threading
import uuid
from decimal import *
from trex.stl.api import *
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
                                                  'vlan': None },
                            'uuids': [] }

def process_options ():
    parser = argparse.ArgumentParser(usage="generate network traffic and report packet loss")

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
    parser.add_argument('--enable-profiler',
                        dest='enable_profiler',
                        help='Should the TRex profiler be enabled',
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
    parser.add_argument('--profiler-interval',
                        dest='profiler_interval',
                        help='What interval (in seconds) should the TRex profiler collect data',
                        default = 3.0,
                        type = float
                        )
    parser.add_argument('--profiler-logfile',
                        dest='profiler_logfile',
                        help='Name of the file to log the profiler to',
                        default = 'trex-profiler.log',
                        type = str
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
     if not stream['the_packet'] is None:
          if not 'packet_values' in stream:
               stream['packet_values'] = { 'vlan': { 'A': t_global.variables['packet_resources']['vlan'],
                                                     'B': t_global.variables['packet_resources']['vlan'] },
                                           'ports': { 'A': { 'src': t_global.variables['packet_resources']['ports']['src'],
                                                             'dst': t_global.variables['packet_resources']['ports']['dst'] },
                                                      'B': { 'src': t_global.variables['packet_resources']['ports']['src'],
                                                             'dst': t_global.variables['packet_resources']['ports']['dst'] } } }

               layer_counter=0
               while True:
                    layer = stream['the_packet'].getlayer(layer_counter)
                    if not layer is None:
                         #myprint("Layer %d is '%s'" % (layer_counter, layer.name))

                         if layer.name == 'Ethernet':
                              stream['packet_values']['macs'] = { 'A': layer.src,
                                                                  'B': layer.dst }
                         elif layer.name == 'Dot1Q':
                              stream['packet_values']['vlan'] = { 'A': layer.vlan,
                                                                  'B': layer.vlan }
                         elif layer.name == 'IP':
                              stream['packet_values']['ips'] = { 'A': layer.src,
                                                                 'B': layer.dst }
                         elif layer.name == 'TCP' or layer.name == 'UDP':
                              stream['packet_values']['ports'] = { 'A': { 'src': layer.sport,
                                                                          'dst': layer.dport },
                                                                   'B': { 'src': layer.sport,
                                                                          'dst': layer.dport } }
                    else:
                         break
                    layer_counter += 1

          if stream['stream_id']:
               t_global.variables['packet_resources']['stream_ids'][stream['stream_id']] = stream['packet_values']
     else:
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

def get_uuid ():
     while True:
          my_uuid = str(uuid.uuid4())
          if not my_uuid in t_global.variables['uuids']:
               t_global.variables['uuids'].append(my_uuid)
               return(my_uuid)

class stl_stream:
     def __init__(self,
                  direction = '',
                  uuid = None,
                  mode_uuid = None,
                  segment_id = -1,
                  segment_part = -1,
                  packet = None,
                  flow_stats_type = None,
                  flow_stats_pg_id = 0,
                  mode = None,
                  name = '',
                  next_name = '',
                  dummy = True,
                  isg = 0.0,
                  self_start = True,
                  packet_protocol = 'UDP',
                  pps = 0.0,
                  duration = 0,
                  flow_count = 0,
                  packet_count = 0,
                  frame_size = 64,
                  offset = 0,
                  substream = False,
                  packets_per_burst = 0,
                  ibg = 0.0,
                  intervals = 0,
                  standard = False,
                  teaching = False,
                  stream_type = ''):
          self.direction = direction
          self.uuid = uuid
          self.mode_uuid = mode_uuid
          self.segment_id = segment_id
          self.segment_part = segment_part
          self.packet = packet
          self.flow_stats_type = flow_stats_type
          self.flow_stats_pg_id = flow_stats_pg_id
          self.mode = mode
          self.name = name
          self.next_name = next_name
          self.dummy = dummy
          self.isg = isg
          self.self_start = self_start
          self.packet_protocol = packet_protocol
          self.pps = pps
          self.duration = duration
          self.flow_count = flow_count
          self.packet_count = packet_count
          self.frame_size = frame_size
          self.offset = offset
          self.substream = substream
          self.packets_per_burst = packets_per_burst
          self.ibg = ibg
          self.intervals = intervals
          self.standard = standard
          self.teaching = teaching
          self.stream_type = stream_type

     def to_dictionary(self):
          return({ 'direction': self.direction,
                   'uuid': self.uuid,
                   'mode_uuid': self.mode_uuid,
                   'segment_id': self.segment_id,
                   'segment_part': self.segment_part,
                   'packet': self.packet,
                   'flow_stats_type': self.flow_stats_type,
                   'flow_stats_pg_id': self.flow_stats_pg_id,
                   'mode': self.mode,
                   'name': self.name,
                   'next_name': self.next_name,
                   'dummy': self.dummy,
                   'isg': self.isg,
                   'self_start': self.self_start,
                   'packet_protocol': self.packet_protocol,
                   'pps': self.pps,
                   'duration': self.duration,
                   'flow_count': self.flow_count,
                   'packet_count': self.packet_count,
                   'frame_size': self.frame_size,
                   'offset': self.offset,
                   'substream': self.substream,
                   'packets_per_burst': self.packets_per_burst,
                   'ibg': self.ibg,
                   'intervals': self.intervals,
                   'standard': self.standard,
                   'teaching': self.teaching,
                   'stream_type': self.stream_type })

     def create_stream(self):
          stream_control = None
          if self.mode == 'burst':
               if self.dummy:
                    # there is no reason to fake traffic at a high
                    # rate because that just adds overhead, so fake it
                    # slowly while adjusting accordingly
                    dummy_pps = 1.0
                    dummy_pps_ratio = dummy_pps/self.pps
                    self.packet_count = int(math.ceil(self.packet_count * dummy_pps_ratio))
                    self.pps = dummy_pps

               stream_control = STLTXSingleBurst(pps = self.pps, total_pkts = self.packet_count)
          elif self.mode == 'multiburst':
               stream_control = STLTXMultiBurst(pkts_per_burst = self.packets_per_burst, ibg = sec_to_usec(self.ibg), count = int(self.intervals), pps = self.pps)

          flow_stats = None
          my_pg_id = self.flow_stats_pg_id
          if self.dummy:
               my_pg_id = 0
          if self.flow_stats_type == 'default':
               flow_stats = STLFlowStats(pg_id = int(my_pg_id))
          elif self.flow_stats_type == 'latency':
               flow_stats = STLFlowLatencyStats(pg_id = int(my_pg_id))

          return(STLStream(packet = self.packet,
                           flow_stats = flow_stats,
                           mode = stream_control,
                           name = self.name,
                           next = self.next_name,
                           dummy_stream = self.dummy,
                           isg = sec_to_usec(self.isg),
                           self_start = self.self_start))

     def append_config(self, device_pair):
          if not self.dummy and not self.teaching:
               device_pair[self.direction]['traffic_profile'][self.flow_stats_type]['protocol'].append(self.packet_protocol)
               device_pair[self.direction]['traffic_profile'][self.flow_stats_type]['pps'].append(self.pps)
               device_pair[self.direction]['traffic_profile'][self.flow_stats_type]['pg_ids'].append(self.flow_stats_pg_id)
               device_pair[self.direction]['traffic_profile'][self.flow_stats_type]['names'].append(self.name)
               device_pair[self.direction]['traffic_profile'][self.flow_stats_type]['next_stream_names'].append(self.next_name)
               device_pair[self.direction]['traffic_profile'][self.flow_stats_type]['frame_sizes'].append(self.frame_size)
               device_pair[self.direction]['traffic_profile'][self.flow_stats_type]['traffic_shares'].append(None)
               device_pair[self.direction]['traffic_profile'][self.flow_stats_type]['self_starts'].append(self.self_start)
               device_pair[self.direction]['traffic_profile'][self.flow_stats_type]['runtime'].append(self.duration)
               device_pair[self.direction]['traffic_profile'][self.flow_stats_type]['stream_modes'].append(self.mode)
               device_pair[self.direction]['traffic_profile'][self.flow_stats_type]['flows'].append(self.flow_count)
               device_pair[self.direction]['traffic_profile'][self.flow_stats_type]['offset'].append(self.offset)
               device_pair[self.direction]['traffic_profile'][self.flow_stats_type]['isg'].append(self.isg)
               device_pair[self.direction]['traffic_profile'][self.flow_stats_type]['traffic_type'].append(self.stream_type)

          return

class segment_object:
     def __init__(self,
                  stage,
                  segment_type,
                  duration,
                  offset,
                  isg = 0.0,
                  skip = False,
                  standard = False):
          self.stage = stage
          self.type = segment_type
          self.duration = duration
          self.offset = offset
          self.isg = isg
          self.skip = skip
          self.standard = standard

     def to_dictionary(self):
          return({ 'stage': self.stage,
                   'type': self.type,
                   'duration': self.duration,
                   'offset': self.offset,
                   'isg': self.isg,
                   'skip': self.skip,
                   'standard': self.standard })

def build_stream_segments(stream):
     segments = []
     segments_total_time = 0
     stream_runtime = stream['duration']
     if stream_runtime is None:
          stream_runtime = t_global.args.runtime
     else:
          if stream_runtime > t_global.args.runtime:
               stream_runtime = t_global.args.runtime

     # build the initial list of segments, this is a very verbose list
     if stream['offset']:
          segments.append(segment_object(0, 'null', stream['offset'], segments_total_time))
          segments_total_time += stream['offset']
          if (stream_runtime + stream['offset']) > t_global.args.runtime:
               stream_runtime = t_global.args.runtime - stream['offset']
     if stream['repeat']:
          remaining_time = t_global.args.runtime - segments_total_time
          while segments_total_time < t_global.args.runtime:
               if remaining_time >= stream_runtime:
                    segments.append(segment_object(1, 'tx', stream_runtime, segments_total_time))
                    segments_total_time += stream_runtime
                    remaining_time -= stream_runtime

                    if remaining_time >= stream['repeat_delay']:
                         segments.append(segment_object(2, 'null', stream['repeat_delay'], segments_total_time))
                         segments_total_time += stream['repeat_delay']
                         remaining_time -= stream['repeat_delay']
                    else:
                         if remaining_time:
                              segments.append(segment_object(3, 'null', remaining_time, segments_total_time))
                              segments_total_time += remaining_time
               else:
                    if remaining_time:
                         segments.append(segment_object(4, 'tx', remaining_time, segments_total_time))
                         segments_total_time += remaining_time
     else:
          segments.append(segment_object(5, 'tx', stream_runtime, segments_total_time))
          segments_total_time += stream_runtime

          if segments_total_time < t_global.args.runtime:
               remaining_time = t_global.args.runtime - segments_total_time
               segments.append(segment_object(6, 'null', remaining_time, segments_total_time))

     #myprint("stream segments")
     #myprint(dump_json_readable(segments))

     return(segments)

def build_measurement_segments(segments):
     measurement_segments = copy.deepcopy(segments)

     if len(measurement_segments) > 1:
          # since there are multiple segments try and reduce them
          trim_segments = False

          for segment_idx in range(0, len(measurement_segments)-1):
               # we can eliminate a dummy stream by replacing it with ISG on the following real stream
               # this should produce fewer streams and use fewer pg_id resources
               if measurement_segments[segment_idx].type == 'null' and measurement_segments[segment_idx+1].type == 'tx':
                    measurement_segments[segment_idx+1].isg += (measurement_segments[segment_idx].isg + measurement_segments[segment_idx].duration)
                    measurement_segments[segment_idx+1].offset -= (measurement_segments[segment_idx].isg + measurement_segments[segment_idx].duration)
                    measurement_segments[segment_idx].stage = 7
                    measurement_segments[segment_idx+1].stage = 7
                    measurement_segments[segment_idx].skip = True
                    trim_segments = True

          if trim_segments:
               # get rid of all segments marked to be skipped
               tmp_segments = []
               for segment in measurement_segments:
                    if not segment.skip:
                         # merge the isg and duration if the segment is null
                         if segment.type == 'null' and segment.isg:
                              segment.duration += segment.isg
                              segment.isg = 0

                         tmp_segments.append(segment)
               measurement_segments = tmp_segments

     # determine if this is a 'standard' stream -- meaning it is the
     # first segment and has no ISG and no offset
     if len(measurement_segments) == 1:
          for segment in measurement_segments:
               if segment.isg == segment.offset == 0:
                    segment.standard = True

     #myprint("measurement segments")
     #myprint(dump_json_readable(measurement_segments))

     return(measurement_segments)

def build_warmup_segments(segments, rate, flows):
     warmup_segments = copy.deepcopy(segments)

     warmup_duration = float(flows) / float(rate)
     warmup_gap = 1.0

     if len(warmup_segments) > 1:
          # since there are multiple segments try and reduce them
          trim_segments = False

          for segment_idx in range(0, len(warmup_segments)-1):
               if segment_idx == 0 and warmup_segments[segment_idx].type == 'tx' and warmup_segments[segment_idx].isg == 0 and warmup_segments[segment_idx].offset == 0:
                    warmup_segments[segment_idx].standard = True
               elif warmup_segments[segment_idx].type == 'null' and warmup_segments[segment_idx+1].type == 'tx':
                    warmup_segments[segment_idx].type = 'tx'
                    warmup_segments[segment_idx+1].type = 'null'

                    warmup_segments[segment_idx].isg = warmup_segments[segment_idx].duration - warmup_duration - warmup_gap
                    warmup_segments[segment_idx].duration = warmup_duration

                    warmup_segments[segment_idx+1].duration += warmup_gap
                    warmup_segments[segment_idx+1].isg = 0
                    warmup_segments[segment_idx+1].offset -= (warmup_duration + warmup_gap)

     # determine if this is a 'standard' stream -- meaning it is the
     # first segment and has no ISG and no offset
     if len(warmup_segments) == 1:
          for segment in warmup_segments:
               if segment.isg == segment.offset == 0:
                    segment.standard = True

     #myprint("warmup segments")
     #myprint(dump_json_readable(warmup_segments))

     return(warmup_segments)

def create_stream (stream, device_pair, direction, other_direction, flow_scaler):
    if not stream['enabled']:
         myprint("")
         myprint("\tSkipping stream %d for '%s' due to explicit disablement in the profile" % (stream['profile_id'], device_pair[direction]['id_string']))
         return

    if stream['offset'] >= t_global.args.runtime:
         myprint("")
         myprint("\tSkipping stream %d for '%s' due to offset >= runtime" % (stream['profile_id'], device_pair[direction]['id_string']))
         return

    segments = build_stream_segments(stream)
    if not stream['repeat_flows'] and stream['repeat']:
         for segment in segments:
              if segment.type == 'tx':
                   new_stream = copy.deepcopy(stream)
                   new_stream['repeat'] = False
                   new_stream['duration'] = segment.duration
                   new_stream['offset'] = segment.offset + segment.isg
                   new_stream['isg'] = 0
                   new_stream['repeat_delay'] = None
                   new_stream['repeat_flows'] = True
                   create_stream(new_stream, device_pair, direction, other_direction, flow_scaler)
         return

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

    if not stream['the_packet'] is None:
         stream_packets['teaching'].append({ 'protocol': "user-pkt",
                                             'packet': load_user_pkt(stream['the_packet'],
                                                                     stream['frame_size'],
                                                                     stream['packet_values']['macs'][dst_port],
                                                                     stream['packet_values']['macs'][src_port],
                                                                     stream['packet_values']['ips'][dst_port],
                                                                     stream['packet_values']['ips'][src_port],
                                                                     stream['packet_values']['ports'][dst_port]['src'],
                                                                     stream['packet_values']['ports'][src_port]['dst'],
                                                                     stream['flow_mods'],
                                                                     stream_flows,
                                                                     t_global.args.enable_flow_cache,
                                                                     flow_offset = stream['flow_offset'],
                                                                     old_mac_flow = False) })
         stream_packets['measurement'].append({ 'protocol': "user-pkt",
                                                'packet': load_user_pkt(stream['the_packet'],
                                                                        stream['frame_size'],
                                                                        stream['packet_values']['macs'][src_port],
                                                                        stream['packet_values']['macs'][dst_port],
                                                                        stream['packet_values']['ips'][src_port],
                                                                        stream['packet_values']['ips'][dst_port],
                                                                        stream['packet_values']['ports'][src_port]['src'],
                                                                        stream['packet_values']['ports'][dst_port]['dst'],
                                                                        stream['flow_mods'],
                                                                        stream_flows,
                                                                        t_global.args.enable_flow_cache,
                                                                        flow_offset = stream['flow_offset'],
                                                                        old_mac_flow = False) })
    else:
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

    measurement_segments = build_measurement_segments(segments)
    if not len(measurement_segments):
         raise ValueError("Hmm, for some reason there are no measurement segments.")

    stl_stream_types = [ 'traffic_streams', 'teaching_measurement_traffic_streams', 'teaching_warmup_traffic_streams', 'teaching_warmup_standard_traffic_streams' ]
    stl_streams = { }
    for stl_stream_type in stl_stream_types:
         stl_streams[stl_stream_type] = []

    # generate a uuid to represent this measurement stream
    stream_uuid = get_uuid()

    for stream_type in stream['stream_types']:
         if stream_type != 'measurement' and stream_type != 'teaching_warmup' and stream_type != 'teaching_measurement' and stream_type != 'ddos':
              raise ValueError("Invalid stream_type: %s" % (stream_type))

         # 'measurement' and 'ddos' (Distributed Denial-of-Service)
         # packets are exactly the same -- except we don't expect to
         # get any 'ddos' packets back because they should be filtered
         # by the DUT
         if stream_type == 'measurement' or stream_type == 'ddos':
              for stream_mode in stream_modes:
                   # generate a uuid to represent this measurement stream's mode
                   stream_mode_uuid = get_uuid()

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
                        stream_pg_id = None

                        myprint("")
                        myprint("\t'%s' stream for '%s' with uuid=%s, mode_uuid=%s, flows=%s, frame size=%s, rate=%s, and mode=%s" % (stream_type,
                                                                                                                                      device_pair[direction]['id_string'],
                                                                                                                                      stream_uuid,
                                                                                                                                      stream_mode_uuid,
                                                                                                                                      commify(stream_flows),
                                                                                                                                      commify(stream['frame_size']),
                                                                                                                                      commify(stream_rate),
                        stream_mode))
                        myprint("\t\tSegments:")

                        segment_auto_start = True
                        base_stream_name = ""
                        segment_part_counter = 1
                        for segment_idx in range(0, len(measurement_segments)):
                             if measurement_segments[segment_idx].type == 'tx' and (stream_pg_id is None or stream_mode == 'latency'):
                                  if device_pair[direction]['pg_ids'][stream_mode]['available']:
                                       stream_pg_id = device_pair[direction]['pg_ids'][stream_mode]['start_index'] + (device_pair[direction]['pg_ids'][stream_mode]['total'] - device_pair[direction]['pg_ids'][stream_mode]['available'])
                                       device_pair[direction]['pg_ids'][stream_mode]['available'] -= 1
                                  else:
                                       raise RuntimeError("Not enough available pg_ids for the requested stream configuration")

                             base_stream_name = "stream-%s_mode-%s_%s_%s" % (stream_uuid, stream_mode_uuid, stream_mode, stream_packet['protocol'])
                             if stream['stream_id']:
                                  base_stream_name = "%s_%s" % (base_stream_name, stream['stream_id'])

                             stream_name =      "%s_part-%d" % (base_stream_name, segment_part_counter)
                             next_stream_name = "%s_part-%d" % (base_stream_name, segment_part_counter+1)

                             dummy = True
                             flow_stats = None
                             tmp_stream_pg_id = None
                             if measurement_segments[segment_idx].type == 'tx':
                                  dummy = False
                                  tmp_stream_pg_id = stream_pg_id
                             else:
                                  tmp_stream_pg_id = 'null'

                             myprint("\t\t\t%d: name=%s, pg_id=%s, type=%s, duration=%s, offset=%s, and isg=%s" % (segment_idx+1,
                                                                                                                   stream_name,
                                                                                                                   tmp_stream_pg_id,
                                                                                                                   measurement_segments[segment_idx].type,
                                                                                                                   commify(measurement_segments[segment_idx].duration),
                                                                                                                   commify(measurement_segments[segment_idx].offset),
                                                                                                                   commify(measurement_segments[segment_idx].isg)))

                             if (len(measurement_segments) == 1) or (segment_idx == (len(measurement_segments) - 1)):
                                  next_stream_name = None

                             if segment_idx > 0:
                                  segment_auto_start = False

                             stream_total_pkts = int(stream_rate * measurement_segments[segment_idx].duration)

                             # check if the total number of packets to TX is greater than can be held in an uint32 (API limit)
                             max_uint32 = int(4294967295)
                             if stream_total_pkts > max_uint32:
                                  stream_loop_remainder = stream_total_pkts % max_uint32
                                  stream_loops = int(((stream_total_pkts - stream_loop_remainder) / max_uint32))

                                  if stream_loop_remainder == 0:
                                       stream_loops -= 1
                                       stream_loops_remainder = max_uint32

                                  substream_self_start = segment_auto_start
                                  substream_isg = measurement_segments[segment_idx].isg
                                  for loop_idx in range(1, stream_loops+1):
                                       substream_name = "%s_part-%d" % (base_stream_name, segment_part_counter)
                                       substream_next_name = "%s_part-%d" % (base_stream_name, segment_part_counter+1)
                                       myprint("\t\t\t\tSubstream %d with name=%s" % (loop_idx, substream_name))
                                       stl_streams['traffic_streams'].append(stl_stream(direction = direction,
                                                                                        uuid = stream_uuid,
                                                                                        mode_uuid = stream_mode_uuid,
                                                                                        segment_id = segment_idx,
                                                                                        segment_part = segment_part_counter,
                                                                                        packet = stream_packet['packet'],
                                                                                        flow_stats_type = stream_mode,
                                                                                        flow_stats_pg_id = stream_pg_id,
                                                                                        mode = 'burst',
                                                                                        name = substream_name,
                                                                                        next_name = substream_next_name,
                                                                                        dummy = dummy,
                                                                                        isg = substream_isg,
                                                                                        self_start = substream_self_start,
                                                                                        packet_protocol = stream_packet['protocol'],
                                                                                        pps = stream_rate,
                                                                                        duration = (max_uint32 / stream_rate),
                                                                                        offset = 0, # fix me
                                                                                        flow_count = stream_flows,
                                                                                        frame_size = stream['frame_size'],
                                                                                        packet_count = max_uint32,
                                                                                        substream = True,
                                                                                        standard = False,
                                                                                        stream_type = stream_type))

                                       substream_self_start = False
                                       substream_isg = 0.0
                                       segment_part_counter += 1

                                  substream_name = "%s_part-%d" % (base_stream_name, segment_part_counter)
                                  if not next_stream_name is None:
                                       next_stream_name = "%s_part-%d" % (base_stream_name, segment_part_counter+1)
                                  myprint("\t\t\t\tSubstream %d with name=%s" % (stream_loops+1, substream_name))
                                  stl_streams['traffic_streams'].append(stl_stream(direction = direction,
                                                                                   uuid = stream_uuid,
                                                                                   mode_uuid = stream_mode_uuid,
                                                                                   segment_id = segment_idx,
                                                                                   segment_part = segment_part_counter,
                                                                                   packet = stream_packet['packet'],
                                                                                   flow_stats_type = stream_mode,
                                                                                   flow_stats_pg_id = stream_pg_id,
                                                                                   mode = 'burst',
                                                                                   name = substream_name,
                                                                                   next_name = next_stream_name,
                                                                                   dummy = dummy,
                                                                                   isg = substream_isg,
                                                                                   self_start = substream_self_start,
                                                                                   packet_protocol = stream_packet['protocol'],
                                                                                   pps = stream_rate,
                                                                                   duration = (stream_loop_remainder / stream_rate),
                                                                                   offset = 0, # fix me
                                                                                   flow_count = stream_flows,
                                                                                   frame_size = stream['frame_size'],
                                                                                   packet_count = stream_loop_remainder,
                                                                                   substream = True,
                                                                                   standard = False,
                                                                                   stream_type = stream_type))
                             else:
                                  stl_streams['traffic_streams'].append(stl_stream(direction = direction,
                                                                                   uuid = stream_uuid,
                                                                                   mode_uuid = stream_mode_uuid,
                                                                                   segment_id = segment_idx,
                                                                                   segment_part = segment_part_counter,
                                                                                   packet = stream_packet['packet'],
                                                                                   flow_stats_type = stream_mode,
                                                                                   flow_stats_pg_id = stream_pg_id,
                                                                                   mode = 'burst',
                                                                                   name = stream_name,
                                                                                   next_name = next_stream_name,
                                                                                   dummy = dummy,
                                                                                   isg = measurement_segments[segment_idx].isg,
                                                                                   self_start = segment_auto_start,
                                                                                   packet_protocol = stream_packet['protocol'],
                                                                                   pps = stream_rate,
                                                                                   duration = measurement_segments[segment_idx].duration,
                                                                                   offset = measurement_segments[segment_idx].offset,
                                                                                   flow_count = stream_flows,
                                                                                   frame_size = stream['frame_size'],
                                                                                   packet_count = stream_total_pkts,
                                                                                   standard = measurement_segments[segment_idx].standard,
                                                                                   stream_type = stream_type))

                             segment_part_counter += 1
         elif stream_type == 'teaching_warmup':
              # if teaching_warmup is the only type for this stream, use the stream's configured rate
              # otherwise use the global default for teaching warmup rate
              if len(stream['stream_types']) != 1:
                   stream_rate = t_global.args.teaching_warmup_packet_rate

              warmup_segments = build_warmup_segments(segments, stream_rate, stream_flows)
              if not len(warmup_segments):
                   raise ValueError("Hmm, for some reason there are no warmup segments.")

              device_pair[direction]['teaching_warmup_max_runtime'] = max(device_pair[direction]['teaching_warmup_max_runtime'],
                                                                           (stream_flows / stream_rate))

              for stream_packet in stream_packets['teaching']:
                   myprint("")
                   myprint("\tTeaching warmup stream for '%s' with uuid=%s, flows=%s, frame size=%s, rate=%s, and protocol=%s" % (device_pair[direction]['id_string'],
                                                                                                                                  stream_uuid,
                                                                                                                                  commify(stream_flows),
                                                                                                                                  commify(stream['frame_size']),
                                                                                                                                  commify(stream_rate),
                                                                                                                                  stream_packet['protocol']))
                   myprint("\t\tSegments:")

                   segment_auto_start = True
                   segment_part_counter = 1
                   for segment_idx in range(0, len(warmup_segments)):

                        if warmup_segments[segment_idx].standard:
                             base_stream_name = "stream-%s_mode-NA_teaching-warmup_%s_standard" % (stream_uuid, stream_packet['protocol'])

                             if stream['stream_id']:
                                  base_stream_name = "%s_%s" % (base_stream_name, stream['stream_id'])

                             stream_name =      base_stream_name

                             myprint("\t\t\t%d: name=%s, type=%s, duration=%s, offset=%s, isg=%s, and standard=%s" % (segment_idx+1,
                                                                                                                      stream_name,
                                                                                                                      warmup_segments[segment_idx].type,
                                                                                                                      commify(warmup_segments[segment_idx].duration),
                                                                                                                      commify(warmup_segments[segment_idx].offset),
                                                                                                                      commify(warmup_segments[segment_idx].isg),
                                                                                                                      True))

                             stl_streams['teaching_warmup_standard_traffic_streams'].append(stl_stream(direction = other_direction,
                                                                                                       uuid = stream_uuid,
                                                                                                       segment_id = segment_idx,
                                                                                                       packet = stream_packet['packet'],
                                                                                                       mode = 'burst',
                                                                                                       name = stream_name,
                                                                                                       next_name = None,
                                                                                                       dummy = False,
                                                                                                       isg = warmup_segments[segment_idx].isg,
                                                                                                       self_start = True,
                                                                                                       packet_protocol = stream_packet['protocol'],
                                                                                                       pps = stream_rate,
                                                                                                       duration = warmup_segments[segment_idx].duration,
                                                                                                       offset = warmup_segments[segment_idx].offset,
                                                                                                       flow_count = stream_flows,
                                                                                                       frame_size = stream['frame_size'],
                                                                                                       packet_count = stream_flows,
                                                                                                       standard = True,
                                                                                                       teaching = True,
                                                                                                       stream_type = stream_type))

                             # since this segment is 'standard', it
                             # also needs to be treated as 'null' to
                             # properly fill the timeline
                             warmup_segments[segment_idx].type = 'null'

                        if len(warmup_segments) == 1 and warmup_segments[segment_idx].type == 'null':
                             continue

                        base_stream_name = "stream-%s_mode-NA_teaching-warmup" % (stream_uuid)

                        if stream['stream_id']:
                             base_stream_name = "%s_%s" % (base_stream_name, stream['stream_id'])

                        stream_name =      "%s_part-%d" % (base_stream_name, segment_part_counter)
                        next_stream_name = "%s_part-%d" % (base_stream_name, segment_part_counter+1)

                        if (len(warmup_segments) == 1) or (segment_idx == (len(warmup_segments) - 1)):
                             next_stream_name = None

                        dummy = False
                        total_packets = stream_flows
                        if warmup_segments[segment_idx].type == 'null':
                             dummy = True
                             total_packets = int(math.ceil(stream_flows * warmup_segments[segment_idx].duration))
                             if stream_flows < stream_rate:
                                  total_packets = int(float(total_packets) / (float(stream_flows) / float(stream_rate)))

                        segment_auto_start = True
                        if segment_idx > 0:
                             segment_auto_start = False


                        myprint("\t\t\t%d: name=%s, type=%s, duration=%s, offset=%s, isg=%s, and standard=%s" % (segment_idx+1,
                                                                                                                 stream_name,
                                                                                                                 warmup_segments[segment_idx].type,
                                                                                                                 commify(warmup_segments[segment_idx].duration),
                                                                                                                 commify(warmup_segments[segment_idx].offset),
                                                                                                                 commify(warmup_segments[segment_idx].isg),
                                                                                                                 False))

                        stl_streams['teaching_warmup_traffic_streams'].append(stl_stream(direction = other_direction,
                                                                                         uuid = stream_uuid,
                                                                                         segment_id = segment_idx,
                                                                                         packet = stream_packet['packet'],
                                                                                         mode = 'burst',
                                                                                         name = stream_name,
                                                                                         next_name = next_stream_name,
                                                                                         dummy = dummy,
                                                                                         isg = warmup_segments[segment_idx].isg,
                                                                                         self_start = segment_auto_start,
                                                                                         packet_protocol = stream_packet['protocol'],
                                                                                         pps = stream_rate,
                                                                                         duration = warmup_segments[segment_idx].duration,
                                                                                         offset = warmup_segments[segment_idx].offset,
                                                                                         flow_count = stream_flows,
                                                                                         frame_size = stream['frame_size'],
                                                                                         packet_count = total_packets,
                                                                                         standard = False,
                                                                                         teaching = True,
                                                                                         stream_type = stream_type))

                        segment_part_counter += 1
         elif stream_type == 'teaching_measurement':
              # if teaching_measurement is the only type for this stream, use the stream's configured rate
              # otherwise use the global default for teaching measurement rate
              if len(stream['stream_types']) != 1:
                   stream_rate = t_global.args.teaching_warmup_packet_rate

              burst_length = stream_flows / stream_rate

              for stream_packet in stream_packets['teaching']:
                   myprint("")
                   myprint("\tTeaching measurement stream for '%s' with uuid=%s, flows=%s, frame size=%s, rate=%s, interval=%s, and protocol=%s" % (device_pair[direction]['id_string'],
                                                                                                                                                    stream_uuid,
                                                                                                                                                    commify(stream_flows),
                                                                                                                                                    commify(stream['frame_size']),
                                                                                                                                                    commify(stream_rate),
                                                                                                                                                    commify(t_global.args.teaching_measurement_interval),
                                                                                                                                                    stream_packet['protocol']))
                   myprint("\t\tSegments:")

                   segment_auto_start = True
                   base_stream_name = ""
                   segment_part_counter = 1
                   for segment_idx in range(0, len(measurement_segments)):
                        base_stream_name = "stream-%s_mode-NA_teaching-measurement_%s" % (stream_uuid, stream_packet['protocol'])
                        if stream['stream_id']:
                             base_stream_name = "%s_%s" % (base_stream_name, stream['stream_id'])

                        stream_name =      "%s_part-%d" % (base_stream_name, segment_part_counter)
                        next_stream_name = "%s_part-%d" % (base_stream_name, segment_part_counter+1)

                        dummy = True
                        if measurement_segments[segment_idx].type == 'tx':
                             dummy = False

                        myprint("\t\t\t%d: name=%s, type=%s, duration=%s, offset=%s, and isg=%s" % (segment_idx+1,
                                                                                                    stream_name,
                                                                                                    measurement_segments[segment_idx].type,
                                                                                                    commify(measurement_segments[segment_idx].duration),
                                                                                                    commify(measurement_segments[segment_idx].offset),
                                                                                                    commify(measurement_segments[segment_idx].isg)))

                        if (len(measurement_segments) == 1) or (segment_idx == (len(measurement_segments) - 1)):
                             next_stream_name = None

                        if segment_idx > 0:
                             segment_auto_start = False

                        stream_total_pkts = int(stream_rate * measurement_segments[segment_idx].duration)

                        stl_streams['teaching_measurement_traffic_streams'].append(stl_stream(direction = other_direction,
                                                                                              uuid = stream_uuid,
                                                                                              segment_id = segment_idx,
                                                                                              segment_part = segment_part_counter,
                                                                                              packet = stream_packet['packet'],
                                                                                              mode = 'multiburst',
                                                                                              name = stream_name,
                                                                                              next_name = next_stream_name,
                                                                                              dummy = dummy,
                                                                                              isg = measurement_segments[segment_idx].isg,
                                                                                              self_start = segment_auto_start,
                                                                                              packet_protocol = stream_packet['protocol'],
                                                                                              pps = stream_rate,
                                                                                              duration = measurement_segments[segment_idx].duration,
                                                                                              offset = measurement_segments[segment_idx].offset,
                                                                                              flow_count = stream_flows,
                                                                                              frame_size = stream['frame_size'],
                                                                                              packet_count = stream_total_pkts,
                                                                                              packets_per_burst = stream_flows,
                                                                                              ibg = t_global.args.teaching_measurement_interval,
                                                                                              intervals = (measurement_segments[segment_idx].duration / (t_global.args.teaching_measurement_interval + burst_length)),
                                                                                              standard = measurement_segments[segment_idx].standard,
                                                                                              teaching = True,
                                                                                              stream_type = stream_type))

                        segment_part_counter += 1

    #myprint(dump_json_readable(stl_streams))

    for stl_stream_type in stl_stream_types:
         for stream in stl_streams[stl_stream_type]:
              device_pair[stream.direction][stl_stream_type].append(stream.create_stream())
              stream.append_config(device_pair)

    return

def main():
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
                              'runtime': [],
                              'stream_modes': [],
                              'flows': [],
                              'offset': [],
                              'isg': [],
                              'traffic_type': [] }

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
                                                                          'teaching_warmup_standard_traffic_streams': [],
                                                                          'teaching_warmup_max_runtime': 0,
                                                                          'teaching_measurement_traffic_streams': [] },
                               t_global.constants['reverse_direction']: { 'ports': { 'tx': port_b,
                                                                                     'rx': port_a },
                                                                          'id_string': "%s%s%s" % (port_a, t_global.constants['reverse_direction'], port_b),
                                                                          'pg_ids': copy.deepcopy(pg_id_values),
                                                                          'traffic_profile': { 'default': copy.deepcopy(stream_profile_object),
                                                                                               'latency': copy.deepcopy(stream_profile_object) },
                                                                          'traffic_streams': [],
                                                                          'teaching_warmup_traffic_streams': [],
                                                                          'teaching_warmup_standard_traffic_streams': [],
                                                                          'teaching_warmup_max_runtime': 0,
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

    c = STLClient(server = t_global.args.trex_host)

    try:
        thread_exit = threading.Event()
        profiler_threads_started = False

        if t_global.args.debug:
             # turn this on for some information
             c.set_verbose("debug")

        # connect to server
        myprint("Establishing connection to TRex server...")
        c.connect()
        myprint("Connection established")

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
            for direction in t_global.constants['directions']:
                if port_info[device_pair[direction]['ports']['tx']]['speed'] == 0:
                    port_speed_verification_fail = True
                    myprint(error("Device with port index = %d failed speed verification test" % (device_pair[direction]['ports']['tx'])))

        if port_speed_verification_fail:
             raise RuntimeError("Failed port speed verification")

        for device_pair in device_pairs:
             if port_info[device_pair[t_global.constants['forward_direction']]['ports']['tx']]["rx"]["counters"] <= port_info[device_pair[t_global.constants['forward_direction']]['ports']['rx']]["rx"]["counters"]:
                  device_pair['max_default_pg_ids'] = port_info[device_pair[t_global.constants['forward_direction']]['ports']['tx']]["rx"]["counters"]
             else:
                  device_pair['max_default_pg_ids'] = port_info[device_pair[t_global.constants['forward_direction']]['ports']['rx']]["rx"]["counters"]

             if len(device_pairs) > 1:
                  # ensure that an even number of pg_ids are available per device_pair
                  remainder = device_pair['max_default_pg_ids'] % len(device_pairs)
                  device_pair['max_default_pg_ids'] -= remainder
                  # divide the pg_ids across the device_pairs
                  device_pair['max_default_pg_ids'] = int(device_pair['max_default_pg_ids'] / len(device_pairs))

             device_pair['max_latency_pg_ids'] = int(128 / len(device_pairs)) # 128 is the maximum number of software counters for latency in TRex

        pg_id_base = 1000
        for device_pair in device_pairs:
             if (device_pair['max_default_pg_ids'] % 2) == 1:
                  device_pair['max_default_pg_ids'] -= 1

             if (device_pair['max_latency_pg_ids'] % 2) == 1:
                  device_pair['max_latency_pg_ids'] -= 1

             device_pair[t_global.constants['forward_direction']]['pg_ids']['default']['total']       = int(device_pair['max_default_pg_ids'] / 2)
             device_pair[t_global.constants['forward_direction']]['pg_ids']['default']['available']   = device_pair[t_global.constants['forward_direction']]['pg_ids']['default']['total']
             device_pair[t_global.constants['forward_direction']]['pg_ids']['default']['start_index'] = pg_id_base
             device_pair[t_global.constants['forward_direction']]['pg_ids']['latency']['total']       = int(device_pair['max_latency_pg_ids'] / 2)
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
        total_streams = 0
        pgids = {}
        flow_port_divider = 1.0 / len(device_pairs)
        enable_standard_warmup = False
        for device_pair in device_pairs:
            for stream in traffic_profile['streams']:
                 if stream['direction'] == t_global.constants['forward_direction'] or stream['direction'] == t_global.constants['both_directions']:
                      create_stream(stream, device_pair, t_global.constants['forward_direction'], t_global.constants['reverse_direction'], flow_port_divider)

                 if stream['direction'] == t_global.constants['reverse_direction'] or stream['direction'] == t_global.constants['both_directions']:
                      create_stream(stream, device_pair, t_global.constants['reverse_direction'], t_global.constants['forward_direction'], flow_port_divider)

                 # update the flow offset so that each port gets unique flows for the same stream
                 stream['flow_offset'] += int(stream['flows'] * flow_port_divider)

            for direction in t_global.constants['directions']:
                total_streams += len(device_pair[direction]['traffic_streams'])
                total_streams += len(device_pair[direction]['teaching_warmup_traffic_streams'])
                tmp_streams = len(device_pair[direction]['teaching_warmup_standard_traffic_streams'])
                if tmp_streams:
                     total_streams += tmp_streams
                     enable_standard_warmup = True
                total_streams += len(device_pair[direction]['teaching_measurement_traffic_streams'])

                if len(device_pair[direction]['traffic_streams']):
                    for stream_mode in [ 'default', 'latency' ]:
                         for pgid in device_pair[direction]['traffic_profile'][stream_mode]['pg_ids']:
                              if pgid in pgids:
                                   pgids[pgid] += 1
                              else:
                                   pgids[pgid] = 1

                    myprint("DEVICE PAIR %s | READABLE STREAMS FOR DIRECTION '%s':" % (device_pair['device_pair'], device_pair[direction]['id_string']), stderr_only = True)
                    myprint(dump_json_readable(device_pair[direction]['traffic_profile']), stderr_only = True)
                    myprint("DEVICE PAIR %s | PARSABLE STREAMS FOR DIRECTION '%s': %s" % (device_pair['device_pair'], device_pair[direction]['id_string'], dump_json_parsable(device_pair[direction]['traffic_profile'])), stderr_only = True)
        myprint("\n\tStream summary: %d total streams and %d pgids\n" % (total_streams, len(pgids)))

        profiler_pgids = []
        for pgid in pgids:
             profiler_pgids.append(pgid)

        profiler_queue = deque()
        profiler_worker_thread = threading.Thread(target = trex_profiler, args = (c, claimed_device_pairs, t_global.args.profiler_interval, profiler_pgids, profiler_queue, thread_exit))
        profiler_logger_thread = threading.Thread(target = trex_profiler_logger, args = (t_global.args.profiler_logfile, profiler_queue, thread_exit))
        if t_global.args.enable_profiler:
             profiler_worker_thread.start()
             profiler_logger_thread.start()
             profiler_threads_started = True

        if enable_standard_warmup:
             warmup_ports = []

             myprint("Standard Teaching Warmup")
             for device_pair in device_pairs:
                  for direction in t_global.constants['directions']:
                       if len(device_pair[direction]['teaching_warmup_standard_traffic_streams']):
                            myprint("\tAdding stream(s) for '%s'" % (device_pair[direction]['id_string']))
                            c.add_streams(streams = device_pair[direction]['teaching_warmup_standard_traffic_streams'], ports = device_pair[direction]['ports']['tx'])
                            warmup_ports.append(device_pair[direction]['ports']['tx'])

             if len(warmup_ports):
                  warmup_timeout = 30.0
                  for device_pair in device_pairs:
                       for direction in t_global.constants['directions']:
                            warmup_timeout = int(max(warmup_timeout, device_pair[direction]['teaching_warmup_max_runtime'] * 1.05))

                  start_time = datetime.datetime.now()
                  myprint("\tStarting transmission at %s" % (start_time.strftime("%H:%M:%S on %Y-%m-%d")))

                  timeout_time = start_time + datetime.timedelta(seconds = warmup_timeout)
                  myprint("\tThe transmission will timeout with an error at %s (after %d seconds)" % (timeout_time.strftime("%H:%M:%S on %Y-%m-%d"), warmup_timeout))

                  try:
                       c.start(ports = warmup_ports, force = True, core_mask = STLClient.CORE_MASK_PIN)
                       c.wait_on_traffic(ports = warmup_ports, timeout = warmup_timeout)

                       stop_time = datetime.datetime.now()
                       total_time = stop_time - start_time
                       myprint("\tFinished transmission at %s" % (stop_time.strftime("%H:%M:%S on %Y-%m-%d")))
                       myprint("\tWarmup ran for %s second(s) (%s)" % (commify(total_time.total_seconds()), total_time))
                  except TRexTimeoutError as e:
                       c.stop(ports = warmup_ports)
                       stop_time = datetime.datetime.now()
                       total_time = stop_time - start_time
                       myprint("TIMEOUT ERROR: The teaching warmup did not end on it's own correctly within the allotted time (%s seconds) -- %s total second(s) elapsed" % (commify(warmup_timeout), commify(total_time.total_seconds())))
                       return return_value
                  except TRexError as e:
                       c.stop(ports = warmup_ports)
                       myprint(error("wait_on_traffic: TRexError: %s" % (e)))
                       return return_value

                  c.reset(ports = warmup_ports)
                  if t_global.args.no_promisc:
                       c.set_port_attr(ports = warmup_ports)
                  else:
                       c.set_port_attr(ports = warmup_ports, promiscuous = True)
             else:
                  myprint("\tNo streams configured")

        run_ports = []

        myprint("Measurement")
        for device_pair in device_pairs:
             for direction in t_global.constants['directions']:
                  port_streams = []

                  myprint("\tAdding streams for '%s'" % (device_pair[direction]['id_string']))

                  if len(device_pair[direction]['teaching_warmup_traffic_streams']):
                       myprint("\t\t- teaching warmup")
                       port_streams.extend(device_pair[direction]['teaching_warmup_traffic_streams'])

                  if len(device_pair[direction]['traffic_streams']):
                       myprint("\t\t- measurement")
                       port_streams.extend(device_pair[direction]['traffic_streams'])

                  if len(device_pair[direction]['teaching_measurement_traffic_streams']):
                       myprint("\t\t- teaching measurement")
                       port_streams.extend(device_pair[direction]['teaching_measurement_traffic_streams'])

                  if len(port_streams):
                       profile = STLProfile(port_streams)

                       c.add_streams(streams = profile.get_streams(), ports = device_pair[direction]['ports']['tx'])
                       run_ports.append(device_pair[direction]['ports']['tx'])

                       myprint("DEVICE PAIR %s | PARSABLE JSON STREAM PROFILE FOR DIRECTION '%s': %s" % (device_pair['device_pair'], device_pair[direction]['id_string'], dump_json_parsable(profile.to_json())), stderr_only = True)
                  else:
                       myprint("\t\t - none")
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

        # log start of test
        timeout_seconds = math.ceil(float(t_global.args.runtime) * (1 + (float(t_global.args.runtime_tolerance) / 100)))
        stop_time = datetime.datetime.now()
        start_time = datetime.datetime.now()
        myprint("\tStarting test at %s for %s seconds" % (start_time.strftime("%H:%M:%S on %Y-%m-%d"), commify(t_global.args.runtime)))
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

        if t_global.args.enable_profiler:
             thread_exit.set()
             profiler_worker_thread.join()
             profiler_logger_thread.join()

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

    except TRexError as e:
        myprint("TRexERROR: %s" % e)

    except (ValueError, RuntimeError) as e:
        myprint(error("%s" % (e)))

    except:
        myprint("EXCEPTION: %s" % traceback.format_exc())

    finally:
        if t_global.args.enable_profiler and profiler_threads_started:
             thread_exit.set()
             profiler_worker_thread.join()
             profiler_logger_thread.join()

        myprint("Disconnecting from TRex server...")
        c.disconnect()
        myprint("Connection severed")
        return return_value

if __name__ == "__main__":
    setup_global_constants()
    setup_global_variables()
    process_options()

    # only import the posix_ipc library if traffic generator
    # synchronization needs to be managed through binary-search.py.
    # imports must be done at the module level which is why this is
    # done here instead of in main()
    if t_global.args.binary_search_synchronize:
         myprint("Enabling synchronization through binary-search.py")
         import posix_ipc

    exit(main())
