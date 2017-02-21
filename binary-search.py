#!/bin/python

# This script conducts a binary search for maximum packet rate while not exceeding
# a specified percent packet loss.  This script will execute a traffic generator,
# which may be one of: txrx.lua, trafficgen.lua (pending), and TRex (pending)

import sys, getopt
import argparse
import subprocess
import re
# import stl_path # needed for TRex
# from trex_stl_lib.api import * # needed for TRex
import time
import json
import string

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
    parser.add_argument('--use-ip-flows', 
                        dest='use_ip_flows',
                        help='implement flows by IP',
                        default=1, # when using ecapsulated network like VxLAN, destination IP will be fixed in order to reach single VTEP
                        type = int,
                        )
    parser.add_argument('--use-mac-flows', 
                        dest='use_mac_flows',
                        help='implement flows by MAC',
                        default=1, # when using ecapsulated network like VxLAN, destination MAC will be fixed in order to reach single VTEP
                        type = int,
                        )
    parser.add_argument('--use-encap-ip-flows', 
                        dest='use_encap_ip_flows',
                        help='implement flows by IP in the encapsulated packet',
                        default=0,
                        type = int,
                        )
    parser.add_argument('--use-encap-mac-flows', 
                        dest="use_encap_mac_flows",
                        help='implement flows by MAC in the encapsulated packet',
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
                        dest='dst_macs_list',
                        help='comma separated list of destination IPs 1 per device',
                        default=""
                        )
    parser.add_argument('--src-ips-list', 
                        dest='src_macs_list',
                        help='comma separated list of src IPs, 1 per device',
                        default=""
                        )
    parser.add_argument('--encap-dst-ips-list', 
                        dest='encap_dst_macs_list',
                        help='comma separated list of destination IPs for excapsulated network, 1 per device',
                        default=""
                        )
    parser.add_argument('--encap-src-ips-list', 
                        dest='encap_src_macs_list',
                        help='comma separated list of src IPs for excapsulated network,, 1 per device',
                        default=""
                        )
    parser.add_argument('--traffic-generator', 
                        dest='traffic_generator',
                        help='name of traffic generator: trex, txrx',
                        default="txrx"
                        )


    t_global.args = parser.parse_args();
    print(t_global.args)

def run_trial (trial_params):
    # this only supports txrx.lua currently
    stats = dict()
    stats[0] = dict()
    stats[0]['tx_packets'] = 0
    stats[0]['rx_packets'] = 0
    stats[1] = dict()
    stats[1]['tx_packets'] = 0
    stats[1]['rx_packets'] = 0

    print('running trial, rate', trial_params['rate'])
    #txrx_cmd = './MoonGen/build/MoonGen ../txrx.lua --rate=' + str(trial_params['rate'] + ' --measureLatency=0 --runTime=5 --devices=4,4 --size=64 --flowMods="" --vxlanIds=100,100 --srcIps=192.168.100.2 --dstIps=192.168.100.1 --srcMacs=9e:e9:96:e4:76:01 --dstMacs=52:54:00:0c:d2:bd --bidirectional=0 --dstIpsVxlan=10.0.100.1 --srcIpsVxlan=10.0.100.2 --dstMacsVxlan=68:05:ca:2a:b7:f3'
    #txrx_cmd = './MoonGen/build/MoonGen ../txrx.lua'
    p = subprocess.Popen('./MoonGen/build/MoonGen txrx.lua --rate=' + str(trial_params['rate']) + ' --bidirectional=' + str(trial_params['run_bidirec']) + ' --measureLatency=0 --runTime=' + str(trial_params['runtime']) + ' --devices=0,1 --size=' + str(trial_params['frame_size']) + ' --flowMods=srcIp', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
	print(line)
	# example output from txrx.lua
	#[INFO]  [0]->[1] txPackets: 10128951 rxPackets: 10128951 packetLoss: 0 txRate: 2.026199 rxRate: 2.026199 packetLossPct: 0.000000
        #[INFO]  [0]->[1] txPackets: 10130148 rxPackets: 10130148 packetLoss: 0 txRate: 2.026430 rxRate: 2.026430 packetLossPct: 0.000000
        m = re.search(r"\[INFO\]\s+\[(\d+)\]\-\>\[(\d+)\]\s+txPackets:\s+(\d+)\s+rxPackets:\s+(\d+)\s+packetLoss:\s+(\-*\d+)\s+txRate:\s+(\d+\.\d+)\s+rxRate:\s+(\d+\.\d+)\s+packetLossPct:\s+(\-*\d+\.\d+)", line)
        if m:
            print('tx_packets, tx_rate, device', m.group(3), m.group(6), int(m.group(1)))
            print('rx_packets, rx_rate, device', m.group(4), m.group(7), int(m.group(2)))
            #stats[0] = {'rx_packets':int(m.group(4)), 'tx_packets':int(m.group(3)), 'tx_rate':float(m.group(6)), 'rx_rate':float(m.group(7))}
            #stats[1] = {'rx_packets':0, 'tx_packets':0, 'tx_rate':0, 'rx_rate':0}
            stats[int(m.group(1))]['tx_packets'] = int(m.group(3))
            stats[int(m.group(2))]['rx_packets'] = int(m.group(4))
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
    print("traffic-generator", t_global.args.traffic_generator)
    print("rate", rate)
    print("frame_size", t_global.args.frame_size)
    print("max_loss_pct", t_global.args.max_loss_pct)
    print("one_shot", t_global.args.one_shot)
    print("search-runtime", t_global.args.search_runtime)
    print("run-bidirec", t_global.args.run_bidirec)
    print("use-num-flows", t_global.args.num_flows)
    print("use-mac-flows", t_global.args.use_mac_flows)
    print("ip-flows", t_global.args.use_ip_flows)
    print("use-encap-mac-flows", t_global.args.use_encap_mac_flows)
    print("use-encap-ip-flows", t_global.args.use_encap_ip_flows)
    print("src-macs-list", t_global.args.src_macs_list)
    print("dest-macs-list", t_global.args.dst_macs_list)
    print("encap-src-macs-list", t_global.args.encap_src_macs_list)
    print("encap-dest-macs-list", t_global.args.encap_dst_macs_list)

    trial_params = {} 
    # trial parameters which do not change during binary search
    trial_params['device_list'] = [0,1]
    trial_params['frame_size'] = t_global.args.frame_size
    trial_params['run_bidirec'] = t_global.args.run_bidirec
    trial_params['num_flows'] = t_global.args.num_flows
    trial_params['use_mac_flows']= t_global.args.use_mac_flows
    trial_params['use_encap_mac_flows'] = t_global.args.use_encap_mac_flows
    trial_params['use_ip_flows'] = t_global.args.use_ip_flows
    trial_params['use_encap_ip_flows'] = t_global.args.use_encap_ip_flows
    trial_params['src_macs_list'] = t_global.args.src_macs_list
    trial_params['encap_src_macs_list'] = t_global.args.encap_src_macs_list
    trial_params['dst_macs_list'] = t_global.args.dst_macs_list
    trial_params['encap_dst_macs_list'] = t_global.args.encap_dst_macs_list

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
	    print('total_tx_packets', total_tx_packets)
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
    	    print(json.dumps(stats[0], indent = 4, separators=(',', ': '), sort_keys = True))
    	    print(json.dumps(stats[1], indent = 4, separators=(',', ': '), sort_keys = True))
       else:    
           print("There is no trial which passed")

if __name__ == "__main__":
    main()

