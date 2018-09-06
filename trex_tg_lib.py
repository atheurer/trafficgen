from __future__ import print_function

import sys
sys.path.append('/opt/trex/current/automation/trex_control_plane/stl/examples')
sys.path.append('/opt/trex/current/automation/trex_control_plane/stl')
import json
from trex_stl_lib.api import *
from collections import deque

def error (string):
    return("ERROR: %s" % (string))

def not_json_serializable(obj):
     return "not JSON serializable"

def dump_json_readable(obj):
     return json.dumps(obj, indent = 4, separators=(',', ': '), sort_keys = True, default = not_json_serializable)

def dump_json_parsable(obj):
     return json.dumps(obj, separators=(',', ':'), default = not_json_serializable)

def commify(string):
     return str.format("{:,}", string)

def ip_to_int (ip):
    ip_fields = ip.split(".")
    if len(ip_fields) != 4:
         raise ValueError("IP addresses should be in the form of W.X.Y.Z")
    ip_int = 256**3 * int(ip_fields[0]) + 256**2 * int(ip_fields[1]) + 256**1 * int(ip_fields[2]) + int(ip_fields[3])
    return ip_int

def calculate_latency_pps (dividend, divisor, total_rate, protocols):
     return int((float(dividend) / float(divisor) * total_rate / protocols))

# Flow Mod Documentation
#
# When old_mac_flow = True, the generated MAC addresses are of the
# form xx:YY:YY:YY:YY:xx where x is static and Y is being modified by
# the TRex field engine.  This allows for a total of 4,294,967,295
# flows.
#
# When old_mac_flow = False, the generated MAC addresses are of the
# form xx:xx:xx:xx:YY:YY where x is static and Y is being modified by
# the TRex field engine.  This allows for a total of 65,536 flows.

def create_icmp_bcast_pkt (mac_src, ip_src, vlan_id, flow_mods, num_flows, enable_flow_cache, flow_offset = 0, old_mac_flow = True):
    mac_dst = 'ff:ff:ff:ff:ff:ff'
    ip_dst  = '255.255.255.255'

    local_flow_mods = copy.deepcopy(flow_mods)

    local_flow_mods['mac']['dst'] = False
    local_flow_mods['ip']['dst'] = False

    return create_icmp_pkt(64, mac_src, mac_dst, ip_src, ip_dst, vlan_id, local_flow_mods, num_flows, enable_flow_cache, flow_offset = flow_offset, old_mac_flow = old_mac_flow)

def create_icmp_pkt (size, mac_src, mac_dst, ip_src, ip_dst, vlan_id, flow_mods, num_flows, enable_flow_cache, flow_offset = 0, old_mac_flow = True):
    tmp_num_flows = num_flows - 1

    ip_src = { "start": ip_to_int(ip_src) + flow_offset, "end": ip_to_int(ip_src) + tmp_num_flows + flow_offset}
    ip_dst = { "start": ip_to_int(ip_dst) + flow_offset, "end": ip_to_int(ip_dst) + tmp_num_flows + flow_offset}

    vm = []
    if flow_mods['ip']['src'] and tmp_num_flows:
         vm = vm + [
              STLVmFlowVar(name = "ip_src", min_value = ip_src['start'], max_value = ip_src['end'], size = 4, op = "inc"),
              STLVmWrFlowVar(fv_name = "ip_src", pkt_offset = "IP.src")
         ]

    if flow_mods['ip']['dst'] and tmp_num_flows:
         vm = vm + [
              STLVmFlowVar(name = "ip_dst", min_value = ip_dst['start'], max_value = ip_dst['end'], size = 4, op = "inc"),
              STLVmWrFlowVar(fv_name = "ip_dst", pkt_offset = "IP.dst")
         ]

    if flow_mods['mac']['src'] and tmp_num_flows:
         if old_mac_flow:
              vm = vm + [
                   STLVmFlowVar(name = "mac_src", min_value = 0 + flow_offset, max_value = tmp_num_flows + flow_offset, size = 4, op = "inc"),
                   STLVmWrFlowVar(fv_name = "mac_src", pkt_offset = 7)
                   #STLVmWrFlowVar(fv_name = "mac_src", pkt_offset = "Ether.src", offset_fixup = 1)
              ]
         else:
              vm = vm + [
                   STLVmFlowVar(name = "mac_src", min_value = 0 + flow_offset, max_value = tmp_num_flows + flow_offset, size = 2, op="inc"),
                   STLVmWrMaskFlowVar(fv_name = "mac_src", pkt_offset = "Ether.src", offset_fixup = 4, mask = 0xFFFF, pkt_cast_size = 2)
              ]

    if flow_mods['mac']['dst'] and tmp_num_flows:
         if old_mac_flow:
              vm = vm + [
                   STLVmFlowVar(name = "mac_dst", min_value = 0 + flow_offset, max_value = tmp_num_flows + flow_offset, size = 4, op = "inc"),
                   STLVmWrFlowVar(fv_name = "mac_dst", pkt_offset = 1)
                   #STLVmWrFlowVar(fv_name = "ether_mac_dst", pkt_offset = "Ether.dst", offset_fixup = 1)
              ]
         else:
              vm = vm + [
                   STLVmFlowVar(name = "mac_dst", min_value = 0 + flow_offset, max_value = tmp_num_flows + flow_offset, size = 2, op = "inc"),
                   STLVmWrMaskFlowVar(fv_name = "mac_dst", pkt_offset = "Ether.dst", offset_fixup = 4, mask = 0xFFFF, pkt_cast_size = 2)
              ]

    the_packet = Ether(src = mac_src, dst = mac_dst)

    if vlan_id is not None:
         the_packet = the_packet/Dot1Q(vlan = vlan_id)

    the_packet = the_packet/IP(src = str(ip_src['start']), dst = str(ip_dst['start']))/ICMP(type = 8, code = 0, id = 0, seq = 0)

    pad = max(0, size - len(the_packet)) * 'x'
    the_packet = the_packet/pad

    #the_packet.show2()

    if tmp_num_flows and (flow_mods['ip']['src'] or flow_mods['ip']['dst'] or flow_mods['mac']['src'] or flow_mods['mac']['dst']):
         vm = vm + [STLVmFixIpv4(offset = "IP")]

         if enable_flow_cache:
              vm = STLScVmRaw(list_of_commands = vm,
                              cache_size = num_flows)

         return STLPktBuilder(pkt = the_packet,
                              vm  = vm)
    else:
         return STLPktBuilder(pkt = the_packet)

def create_garp_pkt (mac_src, ip_src, vlan_id, arp_op, flow_mods, num_flows, enable_flow_cache, flow_offset = 0, old_mac_flow = True):
    arp_mac_target = 'ff:ff:ff:ff:ff:ff'

    tmp_num_flows = num_flows - 1

    ip_src = { "start": ip_to_int(ip_src) + flow_offset, "end": ip_to_int(ip_src) + tmp_num_flows + flow_offset}

    vm = []
    if flow_mods['ip']['src'] and tmp_num_flows:
         vm = vm + [
              STLVmFlowVar(name = "ip_psrc", min_value = ip_src['start'], max_value = ip_src['end'], size = 4, op = "inc"),
              STLVmWrFlowVar(fv_name = "ip_psrc", pkt_offset = "ARP.psrc")
         ]
         vm = vm + [
              STLVmFlowVar(name = "ip_pdst", min_value = ip_src['start'], max_value = ip_src['end'], size = 4, op = "inc"),
              STLVmWrFlowVar(fv_name = "ip_pdst", pkt_offset = "ARP.pdst")
         ]

    if flow_mods['mac']['src'] and tmp_num_flows:
         if old_mac_flow:
              vm = vm + [
                   STLVmFlowVar(name = "ether_mac_src", min_value = 0 + flow_offset, max_value = tmp_num_flows + flow_offset, size = 4, op = "inc"),
                   STLVmWrFlowVar(fv_name = "ether_mac_src", pkt_offset = 7)
                   #STLVmWrFlowVar(fv_name = "ether_mac_src", pkt_offset = "Ether.src", offset_fixup = 1)
              ]
              vm = vm + [
                   STLVmFlowVar(name = "arp_mac_src", min_value = 0 + flow_offset, max_value = tmp_num_flows + flow_offset, size = 4, op = "inc"),
                   STLVmWrFlowVar(fv_name = "arp_mac_src", pkt_offset = "ARP.hwsrc", offset_fixup = 1)
              ]
         else:
              vm = vm + [
                   STLVmFlowVar(name = "ether_mac_src", min_value = 0 + flow_offset, max_value = tmp_num_flows + flow_offset, size = 2, op="inc"),
                   STLVmWrMaskFlowVar(fv_name = "ether_mac_src", pkt_offset = "Ether.src", offset_fixup = 4, mask = 0xFFFF, pkt_cast_size = 2)
              ]
              vm = vm + [
                   STLVmFlowVar(name = "arp_mac_src", min_value = 0 + flow_offset, max_value = tmp_num_flows + flow_offset, size = 2, op="inc"),
                   STLVmWrMaskFlowVar(fv_name = "arp_mac_src", pkt_offset = "ARP.hwsrc", offset_fixup = 4, mask = 0xFFFF, pkt_cast_size = 2)
              ]

    the_packet = Ether(src = mac_src, dst = arp_mac_target)

    if vlan_id is not None:
         the_packet = the_packet/Dot1Q(vlan = vlan_id)

    the_packet = the_packet/ARP(op = arp_op, hwsrc = mac_src, psrc = str(ip_src['start']), hwdst = arp_mac_target, pdst = str(ip_src['start']))

    #the_packet.show2()

    if tmp_num_flows and (flow_mods['ip']['src'] or flow_mods['mac']['src']):
         if enable_flow_cache:
              vm = STLScVmRaw(list_of_commands = vm,
                              cache_size = num_flows)

         return STLPktBuilder(pkt = the_packet,
                              vm  = vm)
    else:
         return STLPktBuilder(pkt = the_packet)

# simple packet creation
def create_generic_pkt (size, mac_src, mac_dst, ip_src, ip_dst, port_src, port_dst, packet_protocol, vlan_id, flow_mods, num_flows, enable_flow_cache, flow_offset = 0, old_mac_flow = True):
    # adjust packet size due to CRC
    size = int(size)
    size -= 4

    port_range = { "start": 0, "end": 65535 }
    if num_flows > 1 and (flow_mods['port']['src'] or flow_mods['port']['dst']):
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

    tmp_num_flows = num_flows - 1

    ip_src = { "start": ip_to_int(ip_src) + flow_offset, "end": ip_to_int(ip_src) + tmp_num_flows + flow_offset }
    ip_dst = { "start": ip_to_int(ip_dst) + flow_offset, "end": ip_to_int(ip_dst) + tmp_num_flows + flow_offset }

    vm = []
    if flow_mods['ip']['src'] and tmp_num_flows:
        vm = vm + [
            STLVmFlowVar(name="ip_src",min_value=ip_src['start'],max_value=ip_src['end'],size=4,op="inc"),
            STLVmWrFlowVar(fv_name="ip_src",pkt_offset= "IP.src")
        ]

    if flow_mods['ip']['dst'] and tmp_num_flows:
        vm = vm + [
            STLVmFlowVar(name="ip_dst",min_value=ip_dst['start'],max_value=ip_dst['end'],size=4,op="inc"),
            STLVmWrFlowVar(fv_name="ip_dst",pkt_offset= "IP.dst")
        ]

    if flow_mods['mac']['src'] and tmp_num_flows:
         if old_mac_flow:
              vm = vm + [
                   STLVmFlowVar(name = "mac_src", min_value = 0 + flow_offset, max_value = tmp_num_flows + flow_offset, size = 4, op="inc"),
                   STLVmWrFlowVar(fv_name = "mac_src", pkt_offset = 7)
              ]
         else:
              vm = vm + [
                   STLVmFlowVar(name = "mac_src", min_value = 0 + flow_offset, max_value = tmp_num_flows + flow_offset, size = 2, op="inc"),
                   STLVmWrMaskFlowVar(fv_name = "mac_src", pkt_offset = "Ether.src", offset_fixup = 4, mask = 0xFFFF, pkt_cast_size = 2)
              ]

    if flow_mods['mac']['dst'] and tmp_num_flows:
         if old_mac_flow:
              vm = vm + [
                   STLVmFlowVar(name = "mac_dst", min_value = 0 + flow_offset, max_value = tmp_num_flows + flow_offset, size = 4, op = "inc"),
                   STLVmWrFlowVar(fv_name = "mac_dst", pkt_offset = 1)
              ]
         else:
              vm = vm + [
                   STLVmFlowVar(name = "mac_dst", min_value = 0 + flow_offset, max_value = tmp_num_flows + flow_offset, size = 2, op = "inc"),
                   STLVmWrMaskFlowVar(fv_name = "mac_dst", pkt_offset = "Ether.dst", offset_fixup = 4, mask = 0xFFFF, pkt_cast_size = 2)
              ]

    if flow_mods['port']['src'] and tmp_num_flows:
        offset = "%s.sport" % (packet_protocol)
        vm = vm + [
            STLVmFlowVar(name = "port_src", init_value = port_src['init'], min_value = port_src['start'], max_value = port_src['end'], size = 2, op = "inc"),
            STLVmWrFlowVar(fv_name = "port_src", pkt_offset = offset)
        ]

    if flow_mods['port']['dst'] and tmp_num_flows:
        offset = "%s.dport" % (packet_protocol)
        vm = vm + [
            STLVmFlowVar(name = "port_dst", init_value = port_dst['init'], min_value = port_dst['start'], max_value = port_dst['end'], size = 2, op = "inc"),
            STLVmWrFlowVar(fv_name = "port_dst", pkt_offset = offset)
        ]

    base = Ether(src = mac_src, dst = mac_dst)

    if vlan_id is not None:
        base = base/Dot1Q(vlan = vlan_id)
        # with vlan tag, minimum 64 L2 frame size is required, otherwise trex will fail
        size = max(64, size) 

    base = base/IP(src = str(ip_src['start']), dst = str(ip_dst['start']))

    if packet_protocol == "UDP":
         base = base/UDP(sport = port_src['init'], dport = port_dst['init'] )
    elif packet_protocol == "TCP":
         base = base/TCP(sport = port_src['init'], dport = port_dst['init'] )
    pad = max(0, size-len(base)) * 'x'

    the_packet = base/pad
    #the_packet.show2()
    #print("")

    if tmp_num_flows and (flow_mods['ip']['src'] or flow_mods['ip']['dst'] or flow_mods['mac']['src'] or flow_mods['mac']['dst'] or flow_mods['port']['src'] or flow_mods['port']['dst']):
         if packet_protocol == "UDP":
              vm = vm + [ STLVmFixChecksumHw(l3_offset = "IP", l4_offset = "UDP", l4_type = CTRexVmInsFixHwCs.L4_TYPE_UDP) ]
         elif packet_protocol == "TCP":
              vm = vm + [ STLVmFixChecksumHw(l3_offset = "IP", l4_offset = "TCP", l4_type = CTRexVmInsFixHwCs.L4_TYPE_TCP) ]

         if enable_flow_cache:
              vm = STLScVmRaw(list_of_commands = vm,
                              cache_size = num_flows)

         return STLPktBuilder(pkt = the_packet,
                              vm  = vm)
    else:
         return STLPktBuilder(pkt = the_packet)

def create_flow_mod_object (use_src_mac_flows = False,
                            use_dst_mac_flows = False,
                            use_src_ip_flows = False,
                            use_dst_ip_flows = False,
                            use_src_port_flows = False,
                            use_dst_port_flows = False,
                            use_protocol_flows = False):
    obj = { 'mac'      : { 'src' : use_src_mac_flows,
                           'dst' : use_dst_mac_flows },
            'ip'       : { 'src' : use_src_ip_flows,
                           'dst' : use_dst_ip_flows },
            'port'     : { 'src' : use_src_port_flows,
                           'dst' : use_dst_port_flows },
            'protocol' : use_protocol_flows }
    return obj

def create_profile_stream (flows = 0,
                           frame_size = 0,
                           flow_mods = None,
                           rate = 0,
                           frame_type = 'generic',
                           measurement = True,
                           teaching_warmup = False,
                           teaching_measurement = False,
                           latency = True,
                           latency_only = False,
                           protocol = 'UDP',
                           traffic_direction = 'bidirectiona',
                           stream_id = None ):
    stream = { 'flows': flows,
               'frame_size': frame_size,
               'flow_mods': copy.deepcopy(flow_mods),
               'rate': rate,
               'frame_type': frame_type,
               'stream_types': [],
               'latency': latency,
               'latency_only': latency_only,
               'protocol': protocol,
               'traffic_direction': traffic_direction }

    if measurement:
        stream['stream_types'].append('measurement')

    if teaching_warmup:
        stream['stream_types'].append('teaching_warmup')

    if teaching_measurement:
        stream['stream_types'].append('teaching_measurement')

    if stream_id:
        stream['stream_id'] = stream_id

    validate_profile_stream(stream, 100.0)

    return(stream)

def validate_profile_stream(stream, rate_modifier):
    for key in stream:
        if not key in [ 'flows', 'frame_size', 'flow_mods', 'rate', 'frame_type', 'stream_types', 'latency', 'latency_only', 'protocol', 'traffic_direction', 'stream_id' ]:
            raise ValueError("Invalid property found (%s)" % (key))

        if isinstance(stream[key], basestring):
            # convert from unicode to string
            stream[key] = str(stream[key])

            fields = stream[key].split(':')
            if len(fields) == 2:
                if fields[0] == 'function':
                    stream[key] = eval(fields[1])

    if not 'stream_types' in stream or len(stream['stream_types']) == 0:
        stream['stream_types'] = [ 'measurement' ]
    else:
        for stream_type in stream['stream_types']:
            if not stream_type in [ 'measurement', 'teaching_warmup', 'teaching_measurement' ]:
                raise ValueError("You must specify a valid stream type (not '%s')" % (stream_type))

    if not 'frame_type' in stream:
        stream['frame_type'] = 'generic'
    else:
        if not stream['frame_type'] in [ 'generic', 'icmp', 'garp' ]:
            raise ValueError("You must specify a valid frame type (not '%s')" % (stream['frame_type']))

    if not 'latency_only' in stream:
        stream['latency_only'] = False

    if not 'latency' in stream:
        stream['latency'] = True

    if not 'protocol' in stream:
        stream['protocol'] = 'UDP'
    else:
        stream['protocol'] = stream['protocol'].upper()

    if not stream['protocol'] in [ 'TCP', 'UDP' ]:
        raise ValueError("You must specify a valid protocol (not '%s')" % (stream['protocol']))

    if not 'traffic_direction' in stream:
        stream['traffic_direction'] = "bidirectional"
    else:
        stream['traffic_direction'] = stream['traffic_direction'].lower()

    if not stream['traffic_direction'] in [ 'bidirectional', 'unidirectional', 'revunidirectional' ]:
        raise ValueError("You must specify a valid traffic direction (not '%s')" % (stream['traffic_direction']))

    if not 'stream_id' in stream:
        stream['stream_id'] = False

    max_flows = 256*256
    if stream['flows'] > max_flows:
        raise ValueError("You must specify <= %d flows per stream (not %d)" % (max_flows, stream['flows']))

    stream['rate'] = stream['rate'] * rate_modifier / 100.0
    if stream['rate'] <= 0:
        raise ValueError("You must specify a rate that is >= 0 (not %f)" % (stream['rate']))

    return(0)

def load_traffic_profile (traffic_profile = "", rate_modifier = 100.0):
     try:
          traffic_profile_fp = open(traffic_profile, 'r')
          profile = json.load(traffic_profile_fp)
          traffic_profile_fp.close()

          if not 'streams' in profile or len(profile['streams']) == 0:
               raise ValueError("There are no streams in the loaded traffic profile")
     except:
          print("EXCEPTION: %s" % traceback.format_exc())
          print(error("Could not load a valid traffic profile from %s" % (traffic_profile)))
          return 1

     try:
         for stream in profile['streams']:
             validate_profile_stream(stream, rate_modifier)

             if stream['traffic_direction'] == "bidirectional":
                 stream['direction'] = "<-->"
             elif stream['traffic_direction'] == "unidirectional":
                 stream['direction'] = "->"
             elif stream['traffic_direction'] == "revunidirectional":
                 stream['direction'] = "<-"

             stream['flow_offset'] = 0

             # flows are "duplicated" across protocols when protocol
             # flows are enabled so flows need to be cut in half. In
             # case of an uneven flow count then round up to ensure an
             # even number of flows for both protocols.
             if stream['flow_mods']['protocol']:
                 stream['flows'] = math.ceil(stream['flows'] / 2.0)
     except:
          print("EXCEPTION: %s" % traceback.format_exc())
          print(error("Could not process the traffic profile from %s" % (traffic_profile)))
          return 1

     return profile

def trex_profiler (connection, claimed_device_pairs, interval, profiler_pgids, profiler_queue, thread_exit):
     try:
          while not thread_exit.is_set():
               time.sleep(interval)

               ts = time.time() * 1000

               xstats = {}
               for device in claimed_device_pairs:
                    xstats[device] = connection.get_xstats(device)

               stats = connection.get_stats(ports = claimed_device_pairs)
               pgid = connection.get_pgid_stats(profiler_pgids)
               util = connection.get_util_stats()

               profiler_queue.append({ 'timestamp': ts,
                                       'stats':     stats,
                                       'pgid':      pgid,
                                       'util':      util,
                                       'xstats':    xstats })

     except STLError as e:
          print("TRex Profiler: STLERROR: %s" % e)

     except StandardError as e:
          print("TRex Profiler: STANDARDERROR: %s" % e)

     finally:
         return(0)

def trex_profiler_logger (logfile, profiler_queue, thread_exit):
     profiler_logfile = None

     try:
          profiler_logfile = open(logfile, 'w')
          profiler_logfile_close = True

     except IOError:
          print(error("Could not open profiler log %s for writing" % (logfile)))
          return(1)

     while not thread_exit.is_set() or len(profiler_queue):
          try:
               log_entry = profiler_queue.popleft()
               print(dump_json_parsable(log_entry), end = '\n\n', file = profiler_logfile)
          except IndexError:
               foo = None

          time.sleep(1)

     profiler_logfile.close()

     return(0)

def trex_profiler_process_sample(sample, stats):
    sample = json.loads(sample)
    #print(dump_json_readable(sample))

    if 'flow_stats' in sample['pgid']:
        for pgid in sorted(sample['pgid']['flow_stats']):
            if not pgid == 'global':
                data = sample['pgid']['flow_stats'][pgid]
                stat_sample = { 'tx_pps': {},
                            'rx_pps': {} }

                for port in sorted(data['tx_pps']):
                    stat_sample['tx_pps'][port] = data['tx_pps'][port]

                for port in sorted(data['rx_pps']):
                    stat_sample['rx_pps'][port] = data['rx_pps'][port]

                if 'latency' in sample['pgid'] and pgid in sample['pgid']['latency']:
                    data = sample['pgid']['latency'][pgid]['latency']
                    stat_sample['latency'] = { 'average': data['average'],
                                               'total_max': data['total_max'],
                                               'total_min': data['total_min'] }

                stats[sample['timestamp']]['pgids'][pgid] = stat_sample

    for port in sorted(sample['stats']):
        data = sample['stats'][port]

        if not port in [ 'latency', 'global', 'flow_stats' ]:
            stats[sample['timestamp']]['ports'][port] = { 'tx': { 'pps': data['tx_pps'],
                                                                  'util': data['tx_util'],
                                                                  'bps': data['tx_bps'],
                                                                  'bps_l1': data['tx_bps_L1'] },
                                                          'rx': { 'pps': data['rx_pps'],
                                                                  'util': data['rx_util'],
                                                                  'bps': data['rx_bps'],
                                                                  'bps_l1': data['rx_bps_L1'] } }
        elif port == 'global':
            stats[sample['timestamp']]['global'] = { 'tx': { 'pps': data['tx_pps'],
                                                             'bps': data['tx_bps'] },
                                                     'rx': { 'pps': data['rx_pps'],
                                                             'bps': data['rx_bps'],
                                                             'drop_bps': data['rx_drop_bps'],
                                                             'cpu_util': data['rx_cpu_util'] },
                                                     'misc': { 'queue_full': data['queue_full'],
                                                               'cpu_util': data['cpu_util'],
                                                               'bw_per_core': data['bw_per_core'] } }

    return(0)

def trex_profiler_populate_lists (sample, lists):
    sample = json.loads(sample)

    lists['timestamps'].append(sample['timestamp'])

    if 'flow_stats' in sample['pgid']:
        for pgid in sample['pgid']['flow_stats']:
            if not pgid == 'global' and not pgid in lists['pgids']:
                lists['pgids'].append(pgid)

    for port in sample['stats']:
        if not port in [ 'latency', 'global', 'total', 'flow_stats' ] and not port in lists['ports']:
            lists['ports'].append(port)

    return(0)

def trex_profiler_build_stats_object (lists):
    stats = {}

    for timestamp in lists['timestamps']:
        pgids = {}
        for pgid in lists['pgids']:
            pgids[pgid] = None

        ports = { 'total': None }
        for port in lists['ports']:
            ports[port] = None

        stat = { 'pgids': pgids,
                 'ports': ports,
                 'global': None }

        stats[timestamp] = stat

    return(stats)

def trex_profiler_postprocess_file (input_file):
    try:
        fp = open(input_file, 'r')

        lists = { 'pgids': [],
                  'timestamps': [],
                  'ports': []
              }
        for line in fp:
            line = line.rstrip('\n')

            if len(line):
               trex_profiler_populate_lists(line, lists)

        for key in lists:
            lists[key].sort()

        stats = trex_profiler_build_stats_object(lists)

        fp.seek(0)
        for line in fp:
            line = line.rstrip('\n')

            if len(line):
                 trex_profiler_process_sample(line, stats)

        fp.close()

        return(stats)

    except:
        print("EXCEPTION: %s" % (traceback.format_exc()))
        print(error("Could not process the input file"))
        return(None)
