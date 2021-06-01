#!/usr/bin/python3

import yaml
import argparse
import logging
import sys
from pathlib import Path
import subprocess
import re

import os
TOOLBOX_HOME = os.environ.get('TOOLBOX_HOME')
if TOOLBOX_HOME is None:
    print("This script requires libraries that are provided by the toolbox project.")
    print("Toolbox can be acquired from https://github.com/perftool-incubator/toolbox and")
    print("then use 'export TOOLBOX_HOME=/path/to/toolbox' so that it can be located.")
    exit(1)
else:
    p = Path(TOOLBOX_HOME) / 'python'
    if not p.exists() or not p.is_dir():
        print("ERROR: <TOOLBOX_HOME>/python ('%s') does not exist!" % (p))
        exit(2)
    sys.path.append(str(p))
from toolbox.system_cpu_topology import *

class t_global(object):
    args = None
    cfg = [
        {
            'version': 2,
            'c': 14,
            'interfaces': [],
            'limit_memory': None,
            'port_info': [],
            'port_bandwidth_gb': None,
            'platform': {
                'master_thread_id': None,
                'latency_thread_id': None,
                'dual_if': []
            }
        }
    ]
    log_debug_format =  '[%(module)s %(funcName)s:%(lineno)d]\n[%(asctime)s][%(levelname) 8s] %(message)s'
    log_normal_format = '%(message)s'
    log = None
    device_pairs = []
    numa_nodes = {}
    system_cpus = None

def process_options():
    parser = argparse.ArgumentParser(description='Custon TRex config generator');

    parser.add_argument('--device',
                        dest = 'devices',
                        help = 'Use one or more times to specify devices to use.',
                        action = 'append',
                        required = True,
                        type = str)

    parser.add_argument('--cpu',
                        dest = 'cpus',
                        help = 'Use one or more times to specify CPUs to use.',
                        action = 'append',
                        required = True,
                        type = int)

    parser.add_argument('--log-level',
                        dest = 'log_level',
                        help = 'Control how much logging output should be generated',
                        default = 'normal',
                        choices = [ 'normal', 'debug' ])

    parser.add_argument('--memory-limit',
                        dest = 'memory_limit',
                        help = 'Limit TRex to X MB of memory so it does not consume all available hugepages',
                        default = 2048,
                        type = int)

    parser.add_argument('--use-l2',
                        dest = 'use_l2',
                        help = 'Should TRex run in L2 mode (as opposed to L3)',
                        default = 'no',
                        choices = [ 'no', 'yes' ])

    parser.add_argument('--use-smt',
                        dest = 'use_smt',
                        help = 'Should TRex use or ignore SMT CPU threads',
                        default = 'no',
                        choices = [ 'no', 'yes' ])

    parser.add_argument('--trex-binary',
                        dest = 'trex_binary',
                        help = 'Path to TRex binary which is used to query devices for L2 mode',
                        default = '/opt/trex/current/t-rex-64',
                        type = str)

    parser.add_argument('--output-file',
                        dest = 'output_file',
                        help = 'Where to write the resulting YAML config file',
                        default = None,
                        type = str)

    t_global.args = parser.parse_args()

    if t_global.args.log_level == 'debug':
        logging.basicConfig(level = logging.DEBUG, format = t_global.log_debug_format, stream = sys.stdout)
    elif t_global.args.log_level == 'normal':
        logging.basicConfig(level = logging.INFO, format = t_global.log_normal_format, stream = sys.stdout)

    t_global.log = logging.getLogger(__file__)

def main():
    process_options()

    if t_global.args.use_l2 == 'yes':
        path = Path(t_global.args.trex_binary)
        if not path.exists():
            t_global.log.error("User supplied TRex binary (%s) does not exist!" % (t_global.args.trex_binary))
            return(10)
        if not path.is_file():
            t_global.log.error("User supplied TRex binary (%s) is not a file!" % (t_global.args.trex_binary))
            return(11)

    if len(t_global.args.devices) < 2:
        t_global.log.error('You must specify at least 2 devices')
        return(1)
    elif len(t_global.args.devices) % 2 != 0:
        t_global.log.error('You must specify devices in pairs')
        return(2)

    # import 'simple' user defined options
    t_global.cfg[0]['limit_memory'] = t_global.args.memory_limit

    # build device pairs
    pair_started = False
    pair = None
    pair_idx = 1
    for dev in t_global.args.devices:
        # verify that the device exists (use lspci because we need some information from it anyway)
        result = subprocess.run(['lspci', '-s', dev], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            if len(result.stdout.rstrip()) == 0:
                t_global.log.error("You specified an invalid device [%s]" % (dev))
                return(15)

            t_global.log.debug("Device %s is a valid PCI device: %s" % (dev, result.stdout.decode('utf-8').rstrip()))

            # figure out the speed of interface, if possible -- logic derived from TRex dpdk_setup_ports.py
            #
            #81:00.0 Ethernet controller: Intel Corporation Ethernet Controller XXV710 for 25GbE SFP28 (rev 02)
            m = re.search(r"([0-9]+)Gb", result.stdout.decode('utf-8'))
            if m:
                speed = int(m.group(1))
                t_global.log.debug("Device %s has speed %dGb" % (dev, speed))
                if t_global.cfg[0]['port_bandwidth_gb'] is None or speed < t_global.cfg[0]['port_bandwidth_gb']:
                    t_global.cfg[0]['port_bandwidth_gb'] = speed
                    t_global.log.debug("Setting global config port_bandwidth_gb to %dGb" % (speed))
        else:
            t_global.log.error("You specified an invalid device [%s]" % (dev))
            return(14)

        if pair_started:
            pair.append(dev)
            port_info = None
            if t_global.args.use_l2 == 'yes':
                port_info = [
                    {
                        'src_mac': None,
                        'dst_mac': None
                    },
                    {
                        'src_mac': None,
                        'dst_mac': None
                    }
                ]
            else:
                port_info = [
                    {
                        'ip': "%d.%d.%d.%d" % (pair_idx, pair_idx, pair_idx, pair_idx),
                        'default_gw': "%d.%d.%d.%d" % (pair_idx+1, pair_idx+1, pair_idx+1, pair_idx+1)
                    },
                    {
                        'default_gw': "%d.%d.%d.%d" % (pair_idx, pair_idx, pair_idx, pair_idx),
                        'ip': "%d.%d.%d.%d" % (pair_idx+1, pair_idx+1, pair_idx+1, pair_idx+1)
                    }
                ]
            t_global.device_pairs.append( { 'devs': pair, 'port_info': port_info, 'cpus': [] } )
            pair_started = False
            pair_idx += 2
        else:
            pair = [ dev ]
            pair_started = True

    # default case if port speed could not be resolved for the devices
    if t_global.cfg[0]['port_bandwidth_gb'] is None:
        t_global.cfg[0]['port_bandwidth_gb'] = 10

    t_global.log.debug("device pairs: %s" % (t_global.device_pairs))

    # find the device's numa node and ensure they are the same between pair devices
    for pair in t_global.device_pairs:
        t_global.log.debug("pair: %s" % (pair))
        for dev in pair['devs']:
            t_global.log.debug("dev: %s" % (dev))
            path = Path('/sys/bus/pci/devices/' + dev)
            if path.exists() and path.is_dir():
                path = path / 'numa_node'
                if path.exists() and path.is_file():
                    with path.open() as fh:
                        if 'node' in pair:
                            node = int(fh.readline().rstrip())
                            if pair['node'] != node:
                                t_global.log.error("Device pair %s are not on the same NUMA node" % (pair['devs']))
                                return(3)
                        else:
                            pair['node'] = int(fh.readline().rstrip())
                else:
                    t_global.log.error("Could not determine NUMA node for device %s" % (dev))
                    return(16)
            else:
                t_global.log.error("Could not find /sys/bus/pci/devices/%s" % (dev))
                return(17)

    t_global.log.debug("device pairs: %s" % (t_global.device_pairs))

    t_global.system_cpus = system_cpu_topology(log = t_global.log)

    t_global.log.debug("cpus: %s" % (t_global.args.cpus))

    if t_global.args.use_smt == 'no':
        t_global.log.debug("Checking for SMT siblings to disable")
        # remove all but 1 SMT sibling from the list of requested CPUs
        for idx in range(0, len(t_global.args.cpus)):
            if t_global.args.cpus[idx] is None:
                continue

            siblings = t_global.system_cpus.get_thread_siblings(t_global.args.cpus[idx])
            for sibling in siblings:
                try:
                    sibling_idx = t_global.args.cpus.index(sibling)
                    t_global.args.cpus[sibling_idx] = None
                    t_global.log.debug("Disabling CPU %d because it is an SMT sibling to CPU %d" % (sibling, t_global.args.cpus[idx]))
                except ValueError:
                    pass

        t_global.log.debug("cpus: %s" % (t_global.args.cpus))

    # validate the the user requested CPUs are availble
    online_cpus = t_global.system_cpus.get_online_cpus()
    for cpu in t_global.args.cpus:
        if cpu is None:
            continue
        try:
            online_cpus.index(cpu)
        except ValueError:
            t_global.log.error("Requested CPU %d is not an online CPU on this system" % (cpu))
            return(4)

    # determine the NUMA node for the CPUs we are using
    for cpu in t_global.args.cpus:
        if cpu is None:
            continue
        node = t_global.system_cpus.get_cpu_node(cpu)
        if not node in t_global.numa_nodes:
            t_global.log.debug("Adding NUMA node %d" % (node))
            t_global.numa_nodes[node] = { 'cpus': [], 'devices': False }
        t_global.numa_nodes[node]['cpus'].append(cpu)
        t_global.log.debug("Adding CPU %d to NUMA node %d" % (cpu, node))

    t_global.log.debug("numa nodes: %s" % (t_global.numa_nodes))

    # make sure that node local CPU resources are available to every device pair
    for pair in t_global.device_pairs:
        if not pair['node'] in t_global.numa_nodes:
            t_global.log.error("Device pair %s is on a numa node (%d) that you did not provide any CPUs for!" % ('|'.join(pair['devs']), pair['node']))
            return(5)
        else:
            t_global.numa_nodes[pair['node']]['devices'] = True
            t_global.log.debug("Found device pair %s on NUMA node %d" % ('|'.join(pair['devs']), pair['node']))

    t_global.log.debug("numa nodes: %s" % (t_global.numa_nodes))

    # remove numa nodes (and their cpus) which are not node local to any device
    for node in list(t_global.numa_nodes):
        if not t_global.numa_nodes[node]['devices']:
            t_global.log.debug("Removing NUMA node %d and it's CPUs [%s] because it has no node local devices" % (node, ",".join([str(int) for int in t_global.numa_nodes[node]['cpus']])))
            del t_global.numa_nodes[node]

    t_global.log.debug("numa nodes: %s" % (t_global.numa_nodes))

    # populate the global resources
    if len(t_global.numa_nodes) == 1:
        for node in t_global.numa_nodes:
            try:
                master_thread_id = t_global.numa_nodes[node]['cpus'].pop()
                t_global.cfg[0]['platform']['master_thread_id'] = master_thread_id
                t_global.log.debug("Setting master_thread_id to CPU %d from NUMA node %d" % (master_thread_id, node))
                latency_thread_id = t_global.numa_nodes[node]['cpus'].pop()
                t_global.cfg[0]['platform']['latency_thread_id'] = latency_thread_id
                t_global.log.debug("Setting latency_thread_id to CPU %d from NUMA node %d" % (latency_thread_id, node))
            except IndexError:
                t_global.log.error("You do not have enough CPUs to fullfill the base requirements")
                return(7)
    else:
        max_cpus = -1
        nodes = []
        for node in t_global.numa_nodes:
            num_cpus = len(t_global.numa_nodes[node]['cpus'])
            if num_cpus > max_cpus:
               max_cpus = num_cpus
               nodes = [ node ]
            elif num_cpus == max_cpus:
                nodes.append(node)

        t_global.log.debug("NUMA nodes %s have the most CPUs (%d)" % (','.join(str(x) for x in nodes), max_cpus))

        if len(nodes) == 1:
            # one node has more cpus than any other node, pull the cpus from that node
            try:
                master_thread_id = t_global.numa_nodes[nodes[0]]['cpus'].pop()
                t_global.cfg[0]['platform']['master_thread_id'] = master_thread_id
                t_global.log.debug("Setting master_thread_id to CPU %d from NUMA node %d" % (master_thread_id, nodes[0]))
                latency_thread_id = t_global.numa_nodes[nodes[0]]['cpus'].pop()
                t_global.cfg[0]['platform']['latency_thread_id'] = latency_thread_id
                t_global.log.debug("Setting latency_thread_id to CPU %d from NUMA node %d" % (latency_thread_id, nodes[0]))
            except IndexError:
                t_global.log.error("You do not have enough CPUs to fullfill the base requirements")
                return(6)
        elif len(nodes) > 1:
            # at least two nodes have the same number of cpus which is the most, pull 1 cpu from each of the first two
            try:
                master_thread_id = t_global.numa_nodes[nodes[0]]['cpus'].pop()
                t_global.cfg[0]['platform']['master_thread_id'] = master_thread_id
                t_global.log.debug("Setting master_thread_id to CPU %d from NUMA node %d" % (master_thread_id, nodes[0]))
                latency_thread_id = t_global.numa_nodes[nodes[1]]['cpus'].pop()
                t_global.cfg[0]['platform']['latency_thread_id'] = latency_thread_id
                t_global.log.debug("Setting latency_thread_id to CPU %d from NUMA node %d" % (latency_thread_id, nodes[1]))
            except IndexError:
                t_global.log.error("You do not have enough CPUs to fullfill the base requirements")
                return(12)
        else:
            t_global.log.error("Fatal error, how did I get here?")
            return(13)

    t_global.log.debug("numa nodes: %s" % (t_global.numa_nodes))

    # determine how many cpus each device pair should be allocated
    for node in t_global.numa_nodes:
        node_pair_counter = 0
        for pair in t_global.device_pairs:
            if pair['node'] == node:
                node_pair_counter += 1

        t_global.log.debug("NUMA node %d has %d device pairs" % (node, node_pair_counter))

        node_cpus_per_pair = int(len(t_global.numa_nodes[node]['cpus']) / node_pair_counter)
        if node_cpus_per_pair == 0:
            t_global.log.error("You do not have enough CPUs for this device configuration!")
            return(8)
        else:
            t_global.numa_nodes[node]['node_cpus_per_pair'] = node_cpus_per_pair
            t_global.log.debug("Each device pair on NUMA node %d will have %d CPUs assigned to it" % (node, node_cpus_per_pair))

            if node_cpus_per_pair < t_global.cfg[0]['c']:
                t_global.cfg[0]['c'] = node_cpus_per_pair

    t_global.log.debug("numa nodes: %s" % (t_global.numa_nodes))

    # allocate the cpus to the device pair(s)
    for pair in t_global.device_pairs:
        for cpu_idx in range(t_global.numa_nodes[pair['node']]['node_cpus_per_pair']):
            cpu = t_global.numa_nodes[pair['node']]['cpus'].pop()
            pair['cpus'].append(cpu)
            t_global.log.debug("Assigning CPU %d from NUMA node %d to device pair %s" % (cpu, pair['node'], '|'.join(pair['devs'])))

    t_global.log.debug("numa nodes: %s" % (t_global.numa_nodes))
    t_global.log.debug("device pairs: %s" % (t_global.device_pairs))

    # if in 'use_l2' mode, determine device mac addresses now; this
    # has been deferred as long as possible since it is slow, waiting
    # until all other checks pass reduces the impact if there are
    # errors elsewhere
    if t_global.args.use_l2 == 'yes':
        for pair in t_global.device_pairs:
            for dev in pair['devs']:
                result = subprocess.run([t_global.args.trex_binary, '--dump-interfaces', dev], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                #Starting  TRex v2.82 please wait  ...
                #Showing interfaces info.
                #PCI: 0000:86:00.1 - MAC: 3C:FD:FE:B8:96:49 - Driver: net_i40e
                m = re.search(r"PCI:\s+([0-9a-fA-F:\.]+)\s+-\s+MAC:\s+([0-9a-fA-F:]+)\s.*", result.stdout.decode('utf-8'))
                if m:
                    t_global.log.debug("Found MAC address %s for device %s" % (m.group(2), m.group(1)))

                    dev_idx = pair['devs'].index(dev)

                    if dev_idx == 0:
                        pair['port_info'][0]['src_mac'] = m.group(2)
                        pair['port_info'][1]['dst_mac'] = m.group(2)
                    else:
                        pair['port_info'][1]['src_mac'] = m.group(2)
                        pair['port_info'][0]['dst_mac'] = m.group(2)
                else:
                    t_global.log.error("Failed to discover MAC address for device %s" % (dev))
                    return(9)

        t_global.log.debug("device pairs: %s" % (t_global.device_pairs))

    # add the device pairs to the cfg
    for pair in t_global.device_pairs:
        # interfaces
        t_global.cfg[0]['interfaces'].extend(pair['devs'])

        # port info
        t_global.cfg[0]['port_info'].extend(pair['port_info'])

        # dual_if
        if_obj = {
            'socket': pair['node'],
            'threads': pair['cpus']
        }
        t_global.cfg[0]['platform']['dual_if'].append(if_obj)

    if t_global.args.output_file is None:
        print("%s" % (yaml.dump(t_global.cfg, default_flow_style=False, indent=4, encoding=None)))
    else:
        t_global.log.info("Writing TRex config to %s" % (t_global.args.output_file))
        with open(t_global.args.output_file, 'w') as file:
            yaml.dump(t_global.cfg, default_flow_style=False, indent=4, encoding=None, stream=file)

    return(0)

if __name__ == "__main__":
    exit(main())
