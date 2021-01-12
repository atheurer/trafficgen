from __future__ import print_function

import sys
sys.path.append('/opt/trex/current/automation/trex_control_plane/interactive')
import json
import traceback
from trex.stl.api import *
from collections import deque
from tg_lib import *

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

    #print("create_icmp_pkt: scapy:%s\n" % (the_packet.command()))

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

    #print("create_garp_pkt: scapy:%s\n" % (the_packet.command()))

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
         else:
             raise ValueError("When source and/or destination port flows are enabled then the per stream flow count must be less than 1000, divisible by 1000, or divisible by 1024 (not %d)." % (num_flows))

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

    ip_src = { "start": int_to_ip(ip_to_int(ip_src) + flow_offset), "end": int_to_ip(ip_to_int(ip_src) + tmp_num_flows + flow_offset) }
    ip_dst = { "start": int_to_ip(ip_to_int(ip_dst) + flow_offset), "end": int_to_ip(ip_to_int(ip_dst) + tmp_num_flows + flow_offset) }

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
    #print("create_generic_pkt: scapy:%s\n" % (the_packet.command()))

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

# load a user defined packet
def load_user_pkt (the_packet, size, mac_src, mac_dst, ip_src, ip_dst, port_src, port_dst, flow_mods, num_flows, enable_flow_cache, flow_offset = 0, old_mac_flow = True):
    # adjust packet size due to CRC
    size = int(size)
    size -= 4

    packet_protocol = "UDP"

    layer_counter = 0
    while True:
        layer = the_packet.getlayer(layer_counter)
        if not layer is None:
            #print("Layer %d is '%s'" % (layer_counter, layer.name))
            #print(dump_json_readable(layer))

            if layer.name == "TCP" or layer.name == "UDP":
                packet_protocol = layer.name

                layer.sport = port_src
                layer.dport = port_dst
            elif layer.name == "IP":
                layer.src = str(ip_to_int(ip_src))
                layer.dst = str(ip_to_int(ip_dst))
            elif layer.name == "Ethernet":
                layer.src = mac_src
                layer.dst = mac_dst

            #print(dump_json_readable(layer))
        else:
            break
        layer_counter += 1

    port_range = { "start": 0, "end": 65535 }
    if num_flows > 1 and (flow_mods['port']['src'] or flow_mods['port']['dst']):
         if num_flows < 1000:
              num_flows_divisor = num_flows
         elif (num_flows % 1000) == 0:
              num_flows_divisor = 1000
         elif (num_flows % 1024 == 0):
              num_flows_divisor = 1024
         else:
             raise ValueError("When source and/or destination port flows are enabled then the per stream flow count must be less than 1000, divisible by 1000, or divisible by 1024 (not %d)." % (num_flows))

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

    if len(the_packet) < size:
        pad = max(0, size-len(the_packet)) * 'x'
        the_packet = the_packet/pad

    #print("load_user_pkt: scapy:%s\n" % (the_packet.command()))

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
                           traffic_direction = 'bidirectional',
                           stream_id = None,
                           enabled = True ):
    stream = { 'flows': flows,
               'frame_size': frame_size,
               'flow_mods': copy.deepcopy(flow_mods),
               'rate': rate,
               'frame_type': frame_type,
               'stream_types': [],
               'enabled': enabled,
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
        if not key in [ 'flows', 'frame_size', 'flow_mods', 'rate', 'frame_type', 'stream_types', 'latency', 'latency_only', 'protocol', 'traffic_direction', 'stream_id', 'offset', 'duration', 'repeat', 'repeat_delay', 'repeat_flows', 'the_packet', 'enabled' ]:
            raise ValueError("Invalid property found (%s)" % (key))

        if isinstance(stream[key], basestring):
            # convert from unicode to string
            stream[key] = str(stream[key])

            fields = stream[key].split(':', 1)
            if len(fields) == 2:
                if fields[0] == 'function':
                    try:
                        stream[key] = eval(fields[1])
                    except:
                        raise ValueError("Failed to eval '%s' for '%s'" % (fields[1], key))
                elif (key == 'the_packet') and (fields[0] == 'scapy'):
                    try:
                        stream[key] = eval(fields[1])
                        #print("validate_profile_stream:the_packet: scapy:%s\n" % (stream[key].command()))
                    except:
                        raise ValueError("Failed to eval '%s' for '%s'" % (fields[1], key))

    if not 'stream_types' in stream or len(stream['stream_types']) == 0:
        stream['stream_types'] = [ 'measurement' ]
    else:
        for stream_type in stream['stream_types']:
            if not stream_type in [ 'measurement', 'teaching_warmup', 'teaching_measurement', 'ddos' ]:
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

    if not 'enabled' in stream:
        stream['enabled'] = True

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

    if not 'offset' in stream:
        stream['offset'] = 0
    else:
        if stream['offset'] < 0:
            raise ValueError("You must specify an offset of >= 0 seconds (not %d)" % (stream['offset']))

    if not 'duration' in stream:
        stream['duration'] = None
    else:
        if not stream['duration'] is None and stream['duration'] <= 0:
            raise ValueError("You must specify a duration of > 0 seconds (not %d)" % (stream['duration']))

    if not 'repeat' in stream:
        stream['repeat'] = False

    if not 'repeat_delay' in stream:
        if stream['repeat']:
            stream['repeat_delay'] = stream['offset']
        else:
            stream['repeat_delay'] = None
    else:
        if not stream['repeat_delay'] is None:
            if stream['repeat_delay'] < 0:
                raise ValueError("You must specify a repeat delay of > 0 seconds (not %d)" % (stream['repeat_delay']))

    if not 'repeat_flows' in stream:
        stream['repeat_flows'] = True

    if not 'stream_id' in stream:
        stream['stream_id'] = False

    if not 'the_packet' in stream:
        stream['the_packet'] = None

    max_flows = 256*256
    if stream['flows'] > max_flows:
        raise ValueError("You must specify <= %d flows per stream (not %d)" % (max_flows, stream['flows']))

    stream['rate'] = stream['rate'] * rate_modifier / 100.0
    if stream['rate'] <= 0:
        raise ValueError("You must specify a rate that is >= 0 (not %f)" % (stream['rate']))

    return(0)

def load_traffic_profile (traffic_profile = "", rate_modifier = 100.0, log_function = print):
     try:
          traffic_profile_fp = open(traffic_profile, 'r')
          profile = json.load(traffic_profile_fp)
          traffic_profile_fp.close()

          if not 'streams' in profile or len(profile['streams']) == 0:
               raise ValueError("There are no streams in the loaded traffic profile")
     except:
          log_function("EXCEPTION: %s" % traceback.format_exc())
          log_function(error("Could not load a valid traffic profile from %s" % (traffic_profile)))
          return(1)

     try:
         stream_counter = 0
         for stream in profile['streams']:
             validate_profile_stream(stream, rate_modifier)

             if stream['traffic_direction'] == "bidirectional":
                 stream['direction'] = "<-->"
             elif stream['traffic_direction'] == "unidirectional":
                 stream['direction'] = "->"
             elif stream['traffic_direction'] == "revunidirectional":
                 stream['direction'] = "<-"

             stream['flow_offset'] = 0
             stream['profile_id'] = stream_counter

             # flows are "duplicated" across protocols when protocol
             # flows are enabled so flows need to be cut in half --
             # except when 'the_packet' invalidates 'protocol'. In
             # case of an uneven flow count then round up to ensure an
             # even number of flows for both protocols.
             if stream['flow_mods']['protocol'] and stream['the_packet'] is None:
                 stream['flows'] = math.ceil(stream['flows'] / 2.0)

             stream_counter += 1
     except:
          log_function("EXCEPTION: %s" % traceback.format_exc())
          log_function(error("Could not process the traffic profile from %s" % (traffic_profile)))
          return(1)

     return(profile)

def trex_profiler (connection, claimed_device_pairs, interval, profiler_pgids, profiler_queue, thread_exit):
     try:
          while not thread_exit.is_set():
               ts1 = time.time()

               xstats = {}
               for device in claimed_device_pairs:
                    xstats[device] = connection.get_xstats(device)

               stats = connection.get_stats(ports = claimed_device_pairs)
               pgid = connection.get_pgid_stats(profiler_pgids)
               util = connection.get_util_stats()

               ts2 = time.time()

               profiler_queue.append({ 'timestamp': (ts2 + ts1)/2 * 1000,
                                       'timestamp_delta': (ts2 - ts1) * 1000,
                                       'stats':     stats,
                                       'pgid':      pgid,
                                       'util':      util,
                                       'xstats':    xstats })

               time.sleep(interval)

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

def sanitize_profiler_value(value):
    if value == "N/A" or value < 0:
        return(0)
    else:
        return(value)

def trex_profiler_process_sample(sample, stats, prev_sample):
    sample = json.loads(sample)
    prev_sample = json.loads(prev_sample)
    #print(dump_json_readable(sample))
    #print(dump_json_readable(prev_sample))

    stats[sample['timestamp']]['tsdelta'] = sample['timestamp_delta']

    sample_delta_seconds = (sample['timestamp']/1000) - (prev_sample['timestamp']/1000)

    if 'flow_stats' in sample['pgid'] and 'flow_stats' in prev_sample['pgid']:
        for pgid in sorted(sample['pgid']['flow_stats']):
            if not pgid in prev_sample['pgid']['flow_stats']:
                continue

            if not pgid == 'global':
                data = sample['pgid']['flow_stats'][pgid]
                prev_data = prev_sample['pgid']['flow_stats'][pgid]
                stat_sample = { 'tx_pps': {},
                            'rx_pps': {} }

                for port in sorted(data['tx_pps']):
                    stat_sample['tx_pps'][port] = (sanitize_profiler_value(data['tx_pkts'][port]) - sanitize_profiler_value(prev_data['tx_pkts'][port])) / sample_delta_seconds

                for port in sorted(data['rx_pps']):
                    stat_sample['rx_pps'][port] = (sanitize_profiler_value(data['rx_pkts'][port]) - sanitize_profiler_value(prev_data['rx_pkts'][port])) / sample_delta_seconds

                if 'latency' in sample['pgid'] and pgid in sample['pgid']['latency']:
                    ldata = sample['pgid']['latency'][pgid]['latency']
                    edata = sample['pgid']['latency'][pgid]['err_cntrs']
                    stat_sample['latency'] = { 'average':      sanitize_profiler_value(ldata['average']),
                                               'total_max':    sanitize_profiler_value(ldata['total_max']),
                                               'total_min':    sanitize_profiler_value(ldata['total_min']),
                                               'duplicate':    sanitize_profiler_value(edata['dup']),
                                               'dropped':      sanitize_profiler_value(edata['dropped']),
                                               'out_of_order': sanitize_profiler_value(edata['out_of_order']),
                                               'seq_too_high': sanitize_profiler_value(edata['seq_too_high']),
                                               'seq_too_low':  sanitize_profiler_value(edata['seq_too_low']) }

                stats[sample['timestamp']]['pgids'][pgid] = stat_sample

    for port in sorted(sample['stats']):
        data = sample['stats'][port]
        prev_data = prev_sample['stats'][port]

        if not port in [ 'latency', 'global', 'flow_stats' ]:
            stats[sample['timestamp']]['ports'][port] = { 'tx': { 'pps':    (sanitize_profiler_value(data['opackets']) - sanitize_profiler_value(prev_data['opackets'])) / sample_delta_seconds,
                                                                  'util':   sanitize_profiler_value(data['tx_util']),
                                                                  'bps':    sanitize_profiler_value(data['tx_bps']),
                                                                  'bps_l1': sanitize_profiler_value(data['tx_bps_L1']) },
                                                          'rx': { 'pps':    (sanitize_profiler_value(data['ipackets']) - sanitize_profiler_value(prev_data['ipackets'])) / sample_delta_seconds,
                                                                  'util':   sanitize_profiler_value(data['rx_util']),
                                                                  'bps':    sanitize_profiler_value(data['rx_bps']),
                                                                  'bps_l1': sanitize_profiler_value(data['rx_bps_L1']) } }
        elif port == 'global':
            stats[sample['timestamp']]['global'] = { 'tx': { 'pps':           sanitize_profiler_value(data['tx_pps']),
                                                             'bps':           sanitize_profiler_value(data['tx_bps']) },
                                                     'rx': { 'pps':           sanitize_profiler_value(data['rx_pps']),
                                                             'bps':           sanitize_profiler_value(data['rx_bps']),
                                                             'drop_bps':      sanitize_profiler_value(data['rx_drop_bps']),
                                                             'cpu_util':      sanitize_profiler_value(data['rx_cpu_util']) },
                                                     'misc': { 'queue_full':  sanitize_profiler_value(data['queue_full']),
                                                               'cpu_util':    sanitize_profiler_value(data['cpu_util']),
                                                               'bw_per_core': sanitize_profiler_value(data['bw_per_core']) } }

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
                 'global': None,
                 'tsdelta': None }

        stats[timestamp] = stat

    return(stats)

def trex_profiler_postprocess_file (input_file):
    try:
        fp = open(input_file, 'r')

        lists = { 'pgids': [],
                  'timestamps': [],
                  'ports': []
              }
        last_line = None
        for line in fp:
            line = line.rstrip('\n')

            if len(line):
               if last_line is not None:
                   trex_profiler_populate_lists(line, lists)
               last_line = line

        for key in lists:
            lists[key].sort()

        stats = trex_profiler_build_stats_object(lists)

        fp.seek(0)
        last_line = None
        for line in fp:
            line = line.rstrip('\n')

            if len(line):
                 if last_line is not None:
                     trex_profiler_process_sample(line, stats, last_line)
                 last_line = line

        fp.close()

        return(stats)

    except:
        print("EXCEPTION: %s" % (traceback.format_exc()))
        print(error("Could not process the input file"))
        return(None)
