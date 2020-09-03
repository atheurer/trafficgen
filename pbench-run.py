#!/bin/python -u

import sys
import getopt
import argparse
import subprocess
import re
import os

class t_global(object):
    launch_trex_args = None
    binary_search_args = None
    trex_device_mapping = {}
    is_trex = False

def process_options ():
    parser = argparse.ArgumentParser(description = 'Provide a single point of entry to (optionally) launch TRex and binary-search.py for use by pbench.',
                                     epilog = 'If the defined traffic generator is TRex, options defined are passed to launch-trex.sh.  Any other options provided are passed to binary-search.py.');

    parser.add_argument('--traffic-generator', 
                        dest='traffic_generator',
                        help='Name of traffic generator to use.',
                        default = "trex-txrx",
                        choices = [ 'trex-txrx', 'trex-txrx-profile', 'null-txrx' ]
                        )
    parser.add_argument('--tmp-dir',
                        dest = 'tmp_dir',
                        help = 'Directory where temporary files should be stored.',
                        default = '/tmp'
                    )
    parser.add_argument('--trex-dir',
                        dest = 'trex_dir',
                        help = 'Directory where TRex is installed.',
                        default = '/opt/trex/current'
                    )
    parser.add_argument('--use-ht',
                        dest = 'use_ht',
                        help = 'Should TRex use HT CPUs.',
                        default = 'n',
                        choices = [ 'y', 'n' ]
                    )
    parser.add_argument('--use-l2',
                        dest = 'use_l2',
                        help = 'Should TRex operate in L2 or L3 mode',
                        default = 'n',
                        choices = [ 'y', 'n' ]
                    )
    parser.add_argument('--use-vlan',
                        dest = 'use_vlan',
                        help = 'Should TRex use a VLAN tag or not',
                        default = 'n',
                        choices = [ 'y', 'n' ]
                    )
    parser.add_argument('--device-pairs',
                        dest = 'device_pairs',
                        help = 'Comma separated list of PCI device pairs to use.  Should already be bound to vfio-pci.',
                        required = True,
                        default = ''
                    )
    parser.add_argument('--yaml-file',
                        dest = 'yaml_file',
                        help = 'Optional parameter to specify a manually created TRex YAML configuration file.',
                        default = None
                    )
    parser.add_argument('--trafficgen-dir',
                        dest = 'trafficgen_dir',
                        help = 'Directory where trafficgen is installed.',
                        default = os.path.dirname(__file__)
                    )
    parser.add_argument('--debug',
                        dest = 'debug',
                        help = 'Enable debug output',
                        action = 'store_true'
                    )

    (t_global.launch_trex_args, t_global.binary_search_args) = parser.parse_known_args()

    # fixup binary-search.py options with options that this script captures
    t_global.binary_search_args.insert(0, "--traffic-generator=%s" % (t_global.launch_trex_args.traffic_generator))
    t_global.binary_search_args.insert(1, "--device-pairs=%s" % (t_global.launch_trex_args.device_pairs))

    # create the mapping of PCI addresses to TRex device indices
    device_counter = 0
    for device_pair in t_global.launch_trex_args.device_pairs.split(','):
        for device in device_pair.split(','):
            t_global.trex_device_mapping[device] = device_counter
            device_counter += 1

def launch_trex ():
    print("launching launch-trex.sh")
    cmd = t_global.launch_trex_args.trafficgen_dir + '/launch-trex.sh'
    cmd += ' --tmp-dir='  + t_global.launch_trex_args.tmp_dir
    cmd += ' --trex-dir=' + t_global.launch_trex_args.trex_dir
    cmd += ' --use-ht='   + t_global.launch_trex_args.use_ht
    cmd += ' --use-l2='   + t_global.launch_trex_args.use_l2
    cmd += ' --use-vlan=' + t_global.launch_trex_args.use_vlan
    cmd += ' --devices='  + t_global.launch_trex_args.device_pairs
    if t_global.launch_trex_args.yaml_file is not None:
        cmd += ' --yaml-file=' + t_global.launch_trex_args.yaml_file        

    return(run_process(cmd))

def kill_trex ():
    print("launching kill-trex.sh")
    cmd = t_global.launch_trex_args.trafficgen_dir + '/kill-trex.sh'

    return(run_process(cmd))

# use the device mapping to convert PCI addresses into TRex indices
def fixup_device_notation(pci_notation):
    fields = pci_notation.split('=')
    index_notation = fields[0] + '='
    device_indices = []
    for device in fields[1].split(','):
        if not device in t_global.trex_device_mapping:
            raise ValueError("Invalid device found")
        device_indices.append(t_global.trex_device_mapping[device])
    if not len(device_indices) % 2 == 0:
        raise ValueError("Devices must be listed in pairs")
    count = 0
    for index in range(0, len(device_indices), 2):
        if count > 0:
            index_notation += ','
        index_notation += '%d:%d' % (device_indices[index], device_indices[index+1])
        count += 1
    return(index_notation)

def launch_binary_search ():
    print("launching binary-search.py")
    cmd = t_global.launch_trex_args.trafficgen_dir + '/binary-search.py'
    for arg in t_global.binary_search_args:
        if t_global.is_trex:
            m = re.search(r"device-pairs", arg)
            if m:
                arg = fixup_device_notation(arg)
        cmd += ' ' + arg

    return(run_process(cmd))

#def run_process(command):
#    print("command=[%s]" % (command))
#    return(my_run_process("echo '" + command + "'"))

#def my_run_process(command):
def run_process(command):
    print("running '%s'" % (command))
    process = subprocess.Popen(command, shell = True)
    return(process.wait())

def main():
    process_options()

    m = re.search(r"^trex-.*$", t_global.launch_trex_args.traffic_generator)
    if m:
        t_global.is_trex = True

        kill_trex()

        if t_global.launch_trex_args.debug:
            print("launch_trex_args=[%s]" % (t_global.launch_trex_args))
            print("trex_device_mapping=[%s]\n" % (t_global.trex_device_mapping))

        ret_val = launch_trex()
        if ret_val:
            return(ret_val)

    if t_global.launch_trex_args.debug:
        print("\nbinary_search_args=[%s]\n" % (t_global.binary_search_args))

    ret_val = launch_binary_search()
    if ret_val:
        return(ret_val)

    if t_global.is_trex:
        ret_val = kill_trex()

    return(ret_val)


if __name__ == "__main__":
    exit(main())
