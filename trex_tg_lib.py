import sys
sys.path.append('/opt/trex/current/automation/trex_control_plane/stl/examples')
sys.path.append('/opt/trex/current/automation/trex_control_plane/stl')
import json
from trex_stl_lib.api import *

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

def create_icmp_bcast_pkt (mac_src, ip_src, vlan_id, flow_mods, num_flows, enable_flow_cache):
    mac_dst = 'ff:ff:ff:ff:ff:ff'
    ip_dst  = '255.255.255.255'

    local_flow_mods = copy.deepcopy(flow_mods)

    local_flow_mods['mac']['dst'] = False
    local_flow_mods['ip']['dst'] = False

    return create_icmp_pkt(64, mac_src, mac_dst, ip_src, ip_dst, vlan_id, local_flow_mods, num_flows, enable_flow_cache)

def create_icmp_pkt (size, mac_src, mac_dst, ip_src, ip_dst, vlan_id, flow_mods, num_flows, enable_flow_cache):
    ip_src = { "start": ip_to_int(ip_src), "end": ip_to_int(ip_src) + num_flows }
    ip_dst = { "start": ip_to_int(ip_dst), "end": ip_to_int(ip_dst) + num_flows }

    vm = []
    if flow_mods['ip']['src'] and num_flows:
         vm = vm + [
              STLVmFlowVar(name = "ip_src", min_value = ip_src['start'], max_value = ip_src['end'], size = 4, op = "inc"),
              STLVmWrFlowVar(fv_name = "ip_src", pkt_offset = "IP.src")
         ]

    if flow_mods['ip']['dst'] and num_flows:
         vm = vm + [
              STLVmFlowVar(name = "ip_dst", min_value = ip_dst['start'], max_value = ip_dst['end'], size = 4, op = "inc"),
              STLVmWrFlowVar(fv_name = "ip_dst", pkt_offset = "IP.dst")
         ]

    if flow_mods['mac']['src'] and num_flows:
         vm = vm + [
              STLVmFlowVar(name = "ether_mac_src", min_value = 0, max_value = num_flows, size = 4, op = "inc"),
              STLVmWrFlowVar(fv_name = "ether_mac_src", pkt_offset = 7)
              #STLVmWrFlowVar(fv_name = "ether_mac_src", pkt_offset = "Ether.src", offset_fixup = 1)
         ]

    if flow_mods['mac']['dst'] and num_flows:
         vm = vm + [
              STLVmFlowVar(name = "ether_mac_dst", min_value = 0, max_value = num_flows, size = 4, op = "inc"),
              STLVmWrFlowVar(fv_name = "ether_mac_dst", pkt_offset = 7)
              #STLVmWrFlowVar(fv_name = "ether_mac_dst", pkt_offset = "Ether.dst", offset_fixup = 1)
         ]

    the_packet = Ether(src = mac_src, dst = mac_dst)

    if vlan_id is not None:
         the_packet = the_packet/Dot1Q(vlan = vlan_id)

    the_packet = the_packet/IP(src = str(ip_src['start']), dst = str(ip_dst['start']))/ICMP(type = 8, code = 0, id = 0, seq = 0)

    pad = max(0, size - len(the_packet)) * 'x'
    the_packet = the_packet/pad

    #the_packet.show2()

    if num_flows and (flow_mods['ip']['src'] or flow_mods['ip']['dst'] or flow_mods['mac']['src'] or flow_mods['mac']['dst']):
         vm = vm + [STLVmFixIpv4(offset = "IP")]

         if enable_flow_cache:
              vm = STLScVmRaw(list_of_commands = vm,
                              cache_size = num_flows)

         return STLPktBuilder(pkt = the_packet,
                              vm  = vm)
    else:
         return STLPktBuilder(pkt = the_packet)

def create_garp_pkt (mac_src, ip_src, vlan_id, arp_op, flow_mods, num_flows, enable_flow_cache):
    arp_mac_target = 'ff:ff:ff:ff:ff:ff'

    ip_src = { "start": ip_to_int(ip_src), "end": ip_to_int(ip_src) + num_flows }

    vm = []
    if flow_mods['ip']['src'] and num_flows:
         vm = vm + [
              STLVmFlowVar(name = "ip_psrc", min_value = ip_src['start'], max_value = ip_src['end'], size = 4, op = "inc"),
              STLVmWrFlowVar(fv_name = "ip_psrc", pkt_offset = "ARP.psrc")
         ]
         vm = vm + [
              STLVmFlowVar(name = "ip_pdst", min_value = ip_src['start'], max_value = ip_src['end'], size = 4, op = "inc"),
              STLVmWrFlowVar(fv_name = "ip_pdst", pkt_offset = "ARP.pdst")
         ]

    if flow_mods['mac']['src'] and num_flows:
         vm = vm + [
              STLVmFlowVar(name = "ether_mac_src", min_value = 0, max_value = num_flows, size = 4, op = "inc"),
              STLVmWrFlowVar(fv_name = "ether_mac_src", pkt_offset = 7)
              #STLVmWrFlowVar(fv_name = "ether_mac_src", pkt_offset = "Ether.src", offset_fixup = 1)
         ]
         vm = vm + [
              STLVmFlowVar(name = "arp_mac_src", min_value = 0, max_value = num_flows, size = 4, op = "inc"),
              STLVmWrFlowVar(fv_name = "arp_mac_src", pkt_offset = "ARP.hwsrc", offset_fixup = 1)
         ]
         vm = vm + [
              STLVmFlowVar(name = "arp_mac_dst", min_value = 0, max_value = num_flows, size = 4, op = "inc"),
              STLVmWrFlowVar(fv_name = "arp_mac_dst", pkt_offset = "ARP.hwdst", offset_fixup = 1)
         ]

    the_packet = Ether(src = mac_src, dst = arp_mac_target)

    if vlan_id is not None:
         the_packet = the_packet/Dot1Q(vlan = vlan_id)

    the_packet = the_packet/ARP(op = arp_op, hwsrc = mac_src, psrc = str(ip_src['start']), hwdst = arp_mac_target, pdst = str(ip_src['start']))

    #the_packet.show2()

    if num_flows and (flow_mods['ip']['src'] or flow_mods['mac']['src']):
         if enable_flow_cache:
              vm = STLScVmRaw(list_of_commands = vm,
                              cache_size = num_flows)

         return STLPktBuilder(pkt = the_packet,
                              vm  = vm)
    else:
         return STLPktBuilder(pkt = the_packet)

# simple packet creation
def create_generic_pkt (size, mac_src, mac_dst, ip_src, ip_dst, port_src, port_dst, packet_protocol, vlan_id, flow_mods, num_flows, enable_flow_cache):
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

    ip_src = { "start": ip_to_int(ip_src), "end": ip_to_int(ip_src) + tmp_num_flows }
    ip_dst = { "start": ip_to_int(ip_dst), "end": ip_to_int(ip_dst) + tmp_num_flows }

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
        vm = vm + [
            STLVmFlowVar(name="mac_src",min_value=0,max_value=tmp_num_flows,size=4,op="inc"),
            STLVmWrFlowVar(fv_name="mac_src",pkt_offset=7)
        ]

    if flow_mods['mac']['dst'] and tmp_num_flows:
        vm = vm + [
            STLVmFlowVar(name="mac_dst",min_value=0,max_value=tmp_num_flows,size=4,op="inc"),
            STLVmWrFlowVar(fv_name="mac_dst",pkt_offset=1)
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
                              cache_size = tmp_num_flows)

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

def load_traffic_profile (traffic_profile = "", rate_modifier = 100.0):
     try:
          traffic_profile_fp = open(traffic_profile, 'r')
          profile = json.load(traffic_profile_fp)
          traffic_profile_fp.close()

          if not 'streams' in profile or len(profile['streams']) == 0:
               raise ValueError("There are no streams in the loaded traffic profile")
     except:
          print("EXCEPTION: %s" % traceback.format_exc())
          print("ERROR: Could not load a valid traffic profile from %s" % traffic_profile)
          return 1

     for stream in profile['streams']:
          for key in stream:
               if isinstance(stream[key], basestring):
                    # convert from unicode to string
                    stream[key] = str(stream[key])

                    fields = stream[key].split(':')
                    if len(fields) == 2:
                         if fields[0] == 'function':
                              stream[key] = eval(fields[1])

          if not 'stream_types' in stream:
               stream['stream_types'] = [ 'measurement' ]

          if not 'frame_type' in stream:
               stream['frame_type'] = 'generic'

          if not 'latency_only' in stream:
               stream['latency_only'] = False

          if not 'latency' in stream:
               stream['latency'] = True

          if not 'protocol' in stream:
               stream['protocol'] = 'UDP'

          if not 'traffic_direction' in stream:
               stream['traffic_direction'] = "bidirectional"

          if stream['traffic_direction'] == "bidirectional":
               stream['direction'] = "<-->"
          elif stream['traffic_direction'] == "unidirectional":
               stream['direction'] = "->"
          elif stream['traffic_direction'] == "revunidirectional":
               stream['direction'] = "<-"
          else:
               raise ValueError("You must specify a valid traffic direction (not '%s')" % stream['traffic_direction'])

          stream['rate'] = stream['rate'] * rate_modifier / 100.0

     return profile
