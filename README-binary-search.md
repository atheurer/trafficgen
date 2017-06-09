# binary-search.py
A script to conduct a binary-search for maximum packet throughput.  This script is designed to work with different traffic generator solutions.  Currently it supports two software traffic generators: MoonGen (with txrx.lua) and TRex (with trex-txrx.lua).  The goal is to refine and enhance the binary-search features completely separate from the actual traffic generators.

## Installation
1.  Download the code
    ```
    [root@LinuxServer root]#git clone https://github.com/atheurer/lua-trafficgen
    ```
    
2.  Build the code.  

    If your intention is to only use TRex with binary-search.py, you do not need to build anything from this repo.  However, we recommend you install TRex in /opt/trex/trex-version and create a symlink /opt/trex/current to point to the version you have installed.  http://trex-tgn.cisco.com/trex/release/v2.22.tar.gz is the recommended version.
    
    ```
    [root@perf104 trex]# pwd
    /opt/trex
    [root@perf104 trex]# ls -l
    total 4
    lrwxrwxrwx  1 root  root    5 Jun  9 01:00 current -> v2.22
    drwxr-xr-x 11 33066   25 4096 Jun  9 11:38 v2.22
    ```

    If your intention is to use MoonGen for trials, then MoonGen can be build from this repo.  This repo includes a git submodule of a specific version of MoonGen repo, so that the txrx.lua script is synced with the proper version of MoonGen.  To build everything:

    ```
    [root@LinuxServer root]#cd lua-trafficgen
    [root@LinuxServer lua-trafficgen]#./setup.sh 
    ```
## Configuration

1. Allocate huegpages needed by the traffic generator.  1GB page size is recommended.  Reboot after grub has been modified.
   ```         
   [root@LinuxServer lua-trafficgen]# grubby --update-kernel=`grubby --default-kernel` --args="default_hugepagesz=1G hugepagesz=1G hugepages=32"
   ```

2. Bind DPDK to two network interfaces needed by the traffic generator.  If you intend to use MoonGen and ran ./setup.sh previously, then you can use ./MoonGen/libmoon/deps/dpdk/tools/dpdk-devbind.py.  If you intend to use TRex, it also includes a binding utility under [/opt/trex/current]/dpdk_set_ports.py.  Binding with vfio-pci kernel module is recommended.
      
## Running
   
   binary-search.py is controlled entirely by command line options.  Please see all of the options with --help.  The recommded minimum number of optons are:
   
   --devices
   --traffic-generator
   --max-loss-pct
   --frame-size
   
