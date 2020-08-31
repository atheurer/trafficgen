# binary-search.py
A script to conduct a binary-search for maximum packet throughput.  This script is designed to work with different traffic generator solutions.  Currently it natively supports TRex (https://trex-tgn.cisco.com/) with two different traffic generator implementations: trex-txrx.py and trex-txrx-profile.py.  The goal is to refine and enhance the binary-search features completely separate from the actual traffic generators.

## Installation
1.  Download

    First, download this git repository

    ```
    # git clone https://github.com/atheurer/trafficgen
    ```
    
2.  Build/Install

    If you intend to use TRex, the trafficgen repo includes a script (trex-install.sh) that will download and install TRex in /opt/trex:

    
    ```
    # cd /path/to/trafficgen
    # ./install-trex.sh
    Downloading TRex v2.81 from https://trex-tgn.cisco.com/trex/release/v2.81.tar.gz...
    installed TRex v2.81 from https://trex-tgn.cisco.com/trex/release/v2.81.tar.gz
    # ls -l /opt/trex
    total 4
    lrwxrwxrwx  1 root  root    5 Aug 26 15:27 current -> v2.81
    drwxr-xr-x 17 33066   25 4096 May  7 12:17 v2.81
    ```

## Configuration

1. Allocate huegpages needed by the traffic generator.  1GB page size is recommended.  Reboot after grub has been modified.

   ```         
   # grubby --update-kernel=`grubby --default-kernel` --args="default_hugepagesz=1G hugepagesz=1G hugepages=32"
   ```

2. Bind DPDK to two network interfaces needed by the traffic generator.

   If you intend to use TRex, it also includes a binding utility under /opt/trex/current/dpdk_set_ports.py.  Binding with vfio-pci kernel module is recommended.
      
## Running
   
   binary-search.py is controlled entirely by command line options.  Please see all of the options with --help.  The recommded minimum number of optons are:

   ```
   --devices
   --traffic-generator
   --max-loss-pct
   --frame-size
   ```

   Note that you must use two physical devices, and these device shoud be connected direcly to a "device-under-test" or to each other to enable loopback testing.
