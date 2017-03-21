#!/bin/python

import sys, getopt
import argparse
import subprocess
import re
# import stl_path
import time
import json
import string
# from decimal import *
# from trex_stl_lib.api import *

class t_global(object):
     args=None;

def process_options ():
    parser = argparse.ArgumentParser(usage=""" 
    Conduct a binary search to find the maximum packet rate within acceptable loss percent
    """);

    parser.add_argument('--frame-size', 
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
                        help='implement flows by destination MAC',
                        default=1,
                        type = int,
                        )
    parser.add_argument('--use-encap-src-ip-flows', 
                        dest='use_encap_src_ip_flows',
                        help='implement flows by source IP in the encapsulated packet',
                        default=0,
                        type = int,
                        )
    parser.add_argument('--use-encap-dst-ip-flows', 
                        dest='use_encap_dst_ip_flows',
                        help='implement flows by destination IP in the encapsulated packet',
                        default=0,
                        type = int,
                        )
    parser.add_argument('--use-encap-src-mac-flows', 
                        dest="use_encap_src_mac_flows",
                        help='implement flows by source MAC in the encapsulated packet',
                        default=0,
                        type = int,
                        )
    parser.add_argument('--use-encap-dst-mac-flows', 
                        dest="use_encap_dst_mac_flows",
                        help='implement flows by destination MAC in the encapsulated packet',
                        default=0,
                        type = int,
                        )
    parser.add_argument('--one-shot', 
                        dest='one_shot',
                        help='0 = run regular binary seach, 1 = run single trial',
                        default=0,
                        type = int,
                        )
    parser.add_argument('--run-bidirec', 
                        dest='run_bidirec',
                        help='0 = Tx on first device, 1 = Tx on both devices',
                        default=1,
                        type = int,
                        )
    parser.add_argument('--validation-runtime', 
                        dest='validation_runtime',
                        help='tiral period in seconds during final validation',
                        default=30,
                        type = int,
                        )
    parser.add_argument('--search-runtime', 
                        dest='search_runtime',
                        help='tiral period in seconds during binary search',
                        default=30,
                        type = int,
                        )
    parser.add_argument('--rate', 
                        dest='rate',
                        help='rate in millions of packets per second per device',
                        default = 0.0,
                        type = float
                        )
    parser.add_argument('--max-loss-pct', 
                        dest='max_loss_pct',
                        help='maximum percentage of packet loss',
                        default=0.002,
			type = float
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
    parser.add_argument('--encap-dst-macs-list', 
                        dest='encap_dst_macs_list',
                        help='comma separated list of destination MACs for encapulsated network, 1 per device',
                        default=""
                        )
    parser.add_argument('--encap-src-macs-list', 
                        dest='encap_src_macs_list',
                        help='comma separated list of src MACs for encapulsated network, 1 per device',
                        default=""
                        )
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
    parser.add_argument('--vxlan-ids-list', 
                        dest='vxlan_ids_list',
                        help='comma separated list of VxLAN IDs, 1 per device',
                        default=""
                        )
    parser.add_argument('--vlan-ids-list', 
                        dest='vlan_ids_list',
                        help='comma separated list of VLAN IDs, 1 per device',
                        default=""
                        )
    parser.add_argument('--encap-dst-ips-list', 
                        dest='encap_dst_ips_list',
                        help='comma separated list of destination IPs for excapsulated network, 1 per device',
                        default=""
                        )
    parser.add_argument('--encap-src-ips-list', 
                        dest='encap_src_ips_list',
                        help='comma separated list of src IPs for excapsulated network,, 1 per device',
                        default=""
                        )
    parser.add_argument('--traffic-generator', 
                        dest='traffic_generator',
                        help='name of traffic generator: trex-txrx or moongen-txrx',
                        default="moongen-txrx"
                        )


    t_global.args = parser.parse_args();
    print(t_global.args)

def run_trial (trial_params):
    stats = dict()
    stats[0] = dict()
    stats[0]['tx_packets'] = 0
    stats[0]['rx_packets'] = 0
    stats[1] = dict()
    stats[1]['tx_packets'] = 0
    stats[1]['rx_packets'] = 0
    cmd = ""

    if trial_params['traffic_generator'] == 'moongen-txrx':
        cmd = './MoonGen/build/MoonGen txrx.lua'
        cmd = cmd + ' --devices=0,1' # fix to allow different devices
        cmd = cmd + ' --measureLatency=0' # fix to allow latency measurment (whern txrx supports)
        cmd = cmd + ' --rate=' + str(trial_params['rate'])
	cmd = cmd + ' --size=' + str(trial_params['frame_size'])
	cmd = cmd + ' --runTime=' + str(trial_params['runtime'])
	cmd = cmd + ' --bidirectional=' + str(trial_params['run_bidirec'])
        if trial_params['vlan_ids_list'] != '':
            cmd = cmd + ' --vlanIds=' + str(trial_params['vlan_ids_list'])
        if trial_params['vxlan_ids_list'] != '':
            cmd = cmd + ' --vxlanIds=' + str(trial_params['vxlan_ids_list'])
        if trial_params['src_ips_list'] != '':
            cmd = cmd + ' --srcIps=' + str(trial_params['src_ips_list'])
        if trial_params['dst_ips_list'] != '':
            cmd = cmd + ' --dstIps=' + str(trial_params['dst_ips_list'])
        if trial_params['src_macs_list'] != '':
            cmd = cmd + ' --srcMacs=' + str(trial_params['src_macs_list'])
        if trial_params['dst_macs_list'] != '':
            cmd = cmd + ' --dstMacs=' + str(trial_params['dst_macs_list'])
        if trial_params['encap_src_ips_list'] != '':
            cmd = cmd + ' --encapSrcIps=' + str(trial_params['encap_src_ips_list'])
        if trial_params['encap_dst_ips_list'] != '':
            cmd = cmd + ' --encapDstIps=' + str(trial_params['encap_dst_ips_list'])
        if trial_params['encap_src_macs_list'] != '':
            cmd = cmd + ' --encapSrcMacs=' + str(trial_params['encap_src_macs_list'])
        if trial_params['encap_dst_macs_list'] != '':
            cmd = cmd + ' --encapDstMacs=' + str(trial_params['encap_dst_macs_list'])
        flow_mods_opt = ' --flowMods=\"'
        if trial_params['use_src_ip_flows'] == 1:
	    flow_mods_opt = flow_mods_opt + ',srcIps'
        if trial_params['use_dst_ip_flows'] == 1:
	    flow_mods_opt = flow_mods_opt + ',dstIps'
        if trial_params['use_encap_src_ip_flows'] == 1:
	    flow_mods_opt = flow_mods_opt + ',encapSrcIps'
        if trial_params['use_encap_dst_ip_flows'] == 1:
	    flow_mods_opt = flow_mods_opt + ',encapDstIps'
        if trial_params['use_src_mac_flows'] == 1:
	    flow_mods_opt = flow_mods_opt + ',srcMacs'
        if trial_params['use_dst_mac_flows'] == 1:
	    flow_mods_opt = flow_mods_opt + ',dstMacs'
        if trial_params['use_encap_src_mac_flows'] == 1:
	    flow_mods_opt = flow_mods_opt + ',encapSrcMacs'
        if trial_params['use_encap_dst_mac_flows'] == 1:
	    flow_mods_opt = flow_mods_opt + ',encapDstMacs'
        flow_mods_opt = flow_mods_opt + '\"'
        re.sub(r"^,", "", flow_mods_opt)
        cmd = cmd + flow_mods_opt
    elif trial_params['traffic_generator'] == 'trex-txrx':
        cmd = 'python trex-txrx.py'
        #cmd = cmd + ' --devices=0,1' # fix to allow different devices
        #cmd = cmd + ' --measureLatency=0' # fix to allow latency measurment (whern txrx supports)
        cmd = cmd + ' --rate=' + str(trial_params['rate'])
        cmd = cmd + ' --size=' + str(trial_params['frame_size'])
        cmd = cmd + ' --runtime=' + str(trial_params['runtime'])
        cmd = cmd + ' --run-bidirec=' + str(trial_params['run_bidirec'])
        cmd = cmd + ' --num-flows=' + str(trial_params['num_flows'])
        if trial_params['src_ips_list'] != '':
             cmd = cmd + ' --src-ips-list=' + str(trial_params['src_ips_list'])
        if trial_params['dst_ips_list'] != '':
             cmd = cmd + ' --dst-ips-list=' + str(trial_params['dst_ips_list'])
        if trial_params['src_macs_list'] != '':
             cmd = cmd + ' --src-macs-list=' + str(trial_params['src_macs_list'])
        if trial_params['dst_macs_list'] != '':
             cmd = cmd + ' --dst-macs-list=' + str(trial_params['dst_macs_list'])
        if trial_params['encap_src_ips_list'] != '':
             cmd = cmd + ' --encap-src-ips-list=' + str(trial_params['encap_src_ips_list'])
        if trial_params['encap_dst_ips_list'] != '':
             cmd = cmd + ' --encap-dst-ips-list=' + str(trial_params['encap_dst_ips_list'])
        if trial_params['encap_src_macs_list'] != '':
             cmd = cmd + ' --encap-src-macs-list=' + str(trial_params['encap_src_macs_list'])
        if trial_params['encap_dst_macs_list'] != '':
             cmd = cmd + ' --encap-dst-macs-list=' + str(trial_params['encap_dst_macs_list'])
        # currently trex-txrx.py does not seperate src and dst ip flow
        # enablement so if either is enabled they both are
        if trial_params['use_src_ip_flows'] == 1 or trial_params['use_dst_ip_flows'] == 1:
             cmd = cmd + ' --use-ip-flows=1'
        else:
             cmd = cmd + ' --use-ip-flows=0'
        # currently trex-txrx.py does not seperate src and dst mac flow
        # enablement so if either is enabled they both are
        if trial_params['use_src_mac_flows'] == 1 or trial_params['use_dst_mac_flows'] == 1:
             cmd = cmd + ' --use-mac-flows=1'
        else:
             cmd = cmd + ' --use-mac-flows=0'

    print('running trial, rate', trial_params['rate'])
    print('cmd:', cmd)
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
	print(line.rstrip('\n'))
        if trial_params['traffic_generator'] == 'moongen-txrx':
             #[INFO]  [0]->[1] txPackets: 10128951 rxPackets: 10128951 packetLoss: 0 txRate: 2.026199 rxRate: 2.026199 packetLossPct: 0.000000
             #[INFO]  [0]->[1] txPackets: 10130148 rxPackets: 10130148 packetLoss: 0 txRate: 2.026430 rxRate: 2.026430 packetLossPct: 0.000000
             m = re.search(r"\[INFO\]\s+\[(\d+)\]\-\>\[(\d+)\]\s+txPackets:\s+(\d+)\s+rxPackets:\s+(\d+)\s+packetLoss:\s+(\-*\d+)\s+txRate:\s+(\d+\.\d+)\s+rxRate:\s+(\d+\.\d+)\s+packetLossPct:\s+(\-*\d+\.\d+)", line)
             if m:
                  print('tx_packets, tx_rate, device', m.group(3), m.group(6), int(m.group(1)))
                  print('rx_packets, rx_rate, device', m.group(4), m.group(7), int(m.group(2)))
                  #stats[0] = {'rx_packets':int(m.group(4)), 'tx_packets':int(m.group(3)), 'tx_rate':float(m.group(6)), 'rx_rate':float(m.group(7))}
                  #stats[1] = {'rx_packets':0, 'tx_packets':0, 'tx_rate':0, 'rx_rate':0}
                  stats[int(m.group(1))]['tx_packets'] = int(m.group(3))
                  stats[int(m.group(1))]['tx_pps'] = float(m.group(3) / trial_params['runtime'])
                  stats[int(m.group(2))]['rx_packets'] = int(m.group(4))
                  stats[int(m.group(2))]['rx_pps'] = float(m.group(4) / trial_params['runtime'])
        elif trial_params['traffic_generator'] == 'trex-txrx':
             #PARSABLE RESULT: {"0":{"tx_util":37.68943472,"rx_bps":11472348160.0,"obytes":43064997504,"rx_pps":22406932.0,"ipackets":672312848,"oerrors":0,"rx_util":37.6436432,"opackets":672890586,"tx_pps":22434198.0,"tx_bps":11486302208.0,"ierrors":0,"rx_bps_L1":15057457280.0,"tx_bps_L1":15075773888.0,"ibytes":43028022272},"1":{"tx_util":37.6893712,"rx_bps":11486310400.0,"obytes":43063561984,"rx_pps":22434204.0,"ipackets":672890586,"oerrors":0,"rx_util":37.6894576,"opackets":672868156,"tx_pps":22434148.0,"tx_bps":11486284800.0,"ierrors":0,"rx_bps_L1":15075783040.0,"tx_bps_L1":15075748480.0,"ibytes":43064997504},"latency":{"global":{"bad_hdr":0,"old_flow":0}},"global":{"rx_bps":22958659584.0,"bw_per_core":7.34,"rx_cpu_util":0.0,"rx_pps":44841136.0,"queue_full":0,"cpu_util":62.6,"tx_pps":44868344.0,"tx_bps":22972585984.0,"rx_drop_bps":0.0},"total":{"tx_util":75.37880591999999,"rx_bps":22958658560.0,"obytes":86128559488,"ipackets":1345203434,"rx_pps":44841136.0,"rx_util":75.3331008,"oerrors":0,"opackets":1345758742,"tx_pps":44868346.0,"tx_bps":22972587008.0,"ierrors":0,"rx_bps_L1":30133240320.0,"tx_bps_L1":30151522368.0,"ibytes":86093019776},"flow_stats":{"1":{"rx_bps":{"0":"N/A","1":"N/A","total":"N/A"},"rx_pps":{"0":"N/A","1":20884464.286073223,"total":20884464.286073223},"rx_pkts":{"0":0,"1":672890586,"total":672890586},"rx_bytes":{"total":"N/A"},"tx_bytes":{"0":43064997504,"1":0,"total":43064997504},"tx_pps":{"0":20898314.26218906,"1":"N/A","total":20898314.26218906},"tx_bps":{"0":10699936902.240799,"1":"N/A","total":10699936902.240799},"tx_pkts":{"0":672890586,"1":0,"total":672890586},"rx_bps_L1":{"0":"N/A","1":"N/A","total":"N/A"},"tx_bps_L1":{"0":14043667184.191048,"1":"N/A","total":14043667184.191048}},"2":{"rx_bps":{"0":"N/A","1":"N/A","total":"N/A"},"rx_pps":{"0":20884967.481241994,"1":"N/A","total":20884967.481241994},"rx_pkts":{"0":672312848,"1":0,"total":672312848},"rx_bytes":{"total":"N/A"},"tx_bytes":{"0":0,"1":43063561984,"total":43063561984},"tx_pps":{"0":"N/A","1":20898728.6582104,"total":20898728.6582104},"tx_bps":{"0":"N/A","1":10700149073.003725,"total":10700149073.003725},"tx_pkts":{"0":0,"1":672868156,"total":672868156},"rx_bps_L1":{"0":"N/A","1":"N/A","total":"N/A"},"tx_bps_L1":{"0":"N/A","1":14043945658.317389,"total":14043945658.317389}},"global":{"rx_err":{},"tx_err":{}}}}
             m = re.search(r"PARSABLE RESULT:\s+(.*)$", line)
             if m:
                  results = json.loads(m.group(1))

                  stats[0]['tx_packets'] = int(results["flow_stats"]["1"]["tx_pkts"]["total"])
                  stats[0]['tx_pps'] = float(results["flow_stats"]["1"]["tx_pkts"]["total"] / trial_params['runtime'])

                  stats[1]['rx_packets'] = int(results["flow_stats"]["1"]["rx_pkts"]["total"])
                  stats[1]['rx_pps'] = float(results["flow_stats"]["1"]["rx_pkts"]["total"] / trial_params['runtime'])

                  print('tx_packets, tx_rate, device', stats[0]['tx_packets'], stats[0]['tx_pps'], 0)
                  print('rx_packets, rx_rate, device', stats[1]['rx_packets'], stats[1]['rx_pps'], 1)

                  if trial_params['run_bidirec']:
                       stats[1]['tx_packets'] = int(results["flow_stats"]["2"]["tx_pkts"]["total"])
                       stats[1]['tx_pps'] = float(results["flow_stats"]["2"]["tx_pkts"]["total"] / trial_params['runtime'])

                       stats[0]['rx_packets'] = int(results["flow_stats"]["2"]["rx_pkts"]["total"])
                       stats[0]['rx_pps'] = float(results["flow_stats"]["2"]["rx_pkts"]["total"] / trial_params['runtime'])

                       print('tx_packets, tx_rate, device', stats[1]['tx_packets'], stats[1]['tx_pps'], 1)
                       print('rx_packets, rx_rate, device', stats[0]['rx_packets'], stats[0]['rx_pps'], 0)
    retval = p.wait()
    return stats


def main():
    process_options()
    final_validation = t_global.args.one_shot == 1
    # binary search will stop once this granularity is reached
    rate_granularity = 0.01
    rate = t_global.args.rate

    # the packet rate in millions/sec is based on 10Gbps, update for other Ethernet speeds
    if rate == 0:
        rate = 9999 / ((t_global.args.frame_size) * 8 + 64 + 96.0)
    prev_rate = 0
    prev_pass_rate = 0
    prev_fail_rate = rate

    # be verbose, dump all options to binary-search
    print("traffic_generator", t_global.args.traffic_generator)
    print("rate", rate)
    print("frame_size", t_global.args.frame_size)
    print("max_loss_pct", t_global.args.max_loss_pct)
    print("one_shot", t_global.args.one_shot)
    print("search-runtime", t_global.args.search_runtime)
    print("run-bidirec", t_global.args.run_bidirec)
    print("use-num-flows", t_global.args.num_flows)
    print("use-src-mac-flows", t_global.args.use_src_mac_flows)
    print("use-dst-mac-flows", t_global.args.use_dst_mac_flows)
    print("use-src-ip-flows", t_global.args.use_src_ip_flows)
    print("use-dst-ip-flows", t_global.args.use_dst_ip_flows)
    print("use-encap-src-mac-flows", t_global.args.use_encap_src_mac_flows)
    print("use-encap-dst-mac-flows", t_global.args.use_encap_dst_mac_flows)
    print("use-encap-src-ip-flows", t_global.args.use_encap_src_ip_flows)
    print("use-encap-dst-ip-flows", t_global.args.use_encap_dst_ip_flows)
    print("src-macs-list", t_global.args.src_macs_list)
    print("dest-macs-list", t_global.args.dst_macs_list)
    print("encap-src-macs-list", t_global.args.encap_src_macs_list)
    print("encap-dest-macs-list", t_global.args.encap_dst_macs_list)
    print("src-ips-list", t_global.args.src_ips_list)
    print("dest-ips-list", t_global.args.dst_ips_list)
    print("encap-src-ips-list", t_global.args.encap_src_ips_list)
    print("encap-dest-ips-list", t_global.args.encap_dst_ips_list)

    trial_params = {} 
    # trial parameters which do not change during binary search
    trial_params['device_list'] = [0,1]
    trial_params['frame_size'] = t_global.args.frame_size
    trial_params['run_bidirec'] = t_global.args.run_bidirec
    trial_params['num_flows'] = t_global.args.num_flows
    trial_params['use_src_mac_flows']= t_global.args.use_src_mac_flows
    trial_params['use_dst_mac_flows']= t_global.args.use_dst_mac_flows
    trial_params['use_encap_src_mac_flows'] = t_global.args.use_encap_src_mac_flows
    trial_params['use_encap_dst_mac_flows'] = t_global.args.use_encap_dst_mac_flows
    trial_params['use_src_ip_flows'] = t_global.args.use_src_ip_flows
    trial_params['use_dst_ip_flows'] = t_global.args.use_dst_ip_flows
    trial_params['use_encap_src_ip_flows'] = t_global.args.use_encap_src_ip_flows
    trial_params['use_encap_dst_ip_flows'] = t_global.args.use_encap_dst_ip_flows
    trial_params['src_macs_list'] = t_global.args.src_macs_list
    trial_params['dst_macs_list'] = t_global.args.dst_macs_list
    trial_params['encap_src_macs_list'] = t_global.args.encap_src_macs_list
    trial_params['encap_dst_macs_list'] = t_global.args.encap_dst_macs_list
    trial_params['src_ips_list'] = t_global.args.src_ips_list
    trial_params['dst_ips_list'] = t_global.args.dst_ips_list
    trial_params['encap_src_ips_list'] = t_global.args.encap_src_ips_list
    trial_params['encap_dst_ips_list'] = t_global.args.encap_dst_ips_list
    trial_params['vlan_ids_list'] = t_global.args.vlan_ids_list
    trial_params['vxlan_ids_list'] = t_global.args.vxlan_ids_list
    trial_params['traffic_generator'] = t_global.args.traffic_generator

    # the actual binary search to find the maximum packet rate
    while final_validation or abs(rate - prev_rate) > rate_granularity:
        # support a longer measurement for the last trial, AKA "final validation"
        if final_validation:
		trial_params['runtime'] = t_global.args.validation_runtime
		print('\nfinal validation')
        else:
		trial_params['runtime'] = t_global.args.search_runtime
		print('\nsearch')
        trial_params['rate'] = rate
        # run the actual trial
        stats = run_trial(trial_params)
        # calculate loss and decide what to do
        total_tx_packets = stats[0]['tx_packets'] + stats[1]['tx_packets']
        if total_tx_packets == 0:
	    print('binary search failed because no packets were transmitted')
            quit() # abort immediately because nothing works
        else:
	    print('total_tx_packets', total_tx_packets)
        total_rx_packets = stats[0]['rx_packets'] + stats[1]['rx_packets']
        if total_rx_packets == 0:
	    print('binary search failed because no packets were received')
            quit() # abort immediately because nothing works
        else:
	    print('total_rx_packets', total_rx_packets)
        total_lost_packets = total_tx_packets - total_rx_packets
	print('total_lost_packets', total_lost_packets)
        pct_lost_packets = 100.0 * (total_tx_packets - total_rx_packets) / total_tx_packets
        if t_global.args.one_shot == 1:
                break
        if pct_lost_packets > t_global.args.max_loss_pct:  # the trial failed
	    print('trial failed, percent loss', pct_lost_packets)
            if final_validation:
                final_validation = False
                next_rate = rate - rate_granularity # subtracting by rate_granularity avoids very small reductions in rate
            else:
                next_rate = (prev_pass_rate + rate) / 2
            prev_fail_rate = rate
        else: # the trial passed
	    print('trial passed, percent loss', pct_lost_packets)
            passed_stats = stats
            if final_validation: # no longer necessary to continue searching
                break
            prev_pass_rate = rate
            next_rate = (prev_fail_rate + rate) / 2
        if abs(rate - next_rate) < rate_granularity: # trigger final validation
            final_validation = True
	prev_rate = rate
        rate = next_rate

    print("RESULT:")
    if prev_pass_rate != 0: # show the stats for the most recent passing trial
    	print('[')
        print(json.dumps(passed_stats[0], indent = 4, separators=(',', ': '), sort_keys = True))
        print(',')
    	print(json.dumps(passed_stats[1], indent = 4, separators=(',', ': '), sort_keys = True))
        print(']')
    else:
       if t_global.args.one_shot == 1:
            print('[')
    	    print(json.dumps(stats[0], indent = 4, separators=(',', ': '), sort_keys = True))
            print(',')
    	    print(json.dumps(stats[1], indent = 4, separators=(',', ': '), sort_keys = True))
            print(']')
       else:    
           print("There is no trial which passed")

if __name__ == "__main__":
    main()

