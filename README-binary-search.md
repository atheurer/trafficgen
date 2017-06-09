# binary-search.py
A script to conduct a binary-search for maximum packet throughput.  This script is designed to work with different traffic generator solutions.  Currently it supports two software traffic generators: MoonGen (with txrx.lua) and TRex (with trex-txrx.lua).  The goal is to refine and enhance the binary-search features completely separate from the actual traffic generators.

## Installation
1.  Download

    First, download this git repository
    ```
    [root@LinuxServer ~]#cd /opt
    [root@LinuxServer opt]#git clone https://github.com/atheurer/lua-trafficgen
    ```
    Next, if you intend on using TRex with binary-search.py, also download the TRex package, here: http://trex-tgn.cisco.com/trex/release/v2.22.tar.gz
    
2.  Build/Intsall  

    If you intend to use TRex, install TRex in /opt/trex/trex-version and create a symlink /opt/trex/current to point to the version you have installed.
    
    ```
    [root@LinuxServer ~]# cd /opt
    [root@LinuxServer opt]# mkdir -p trex
    [root@LinuxServer opt]# cd trex
    [root@LinuxServer trex]# tar zxf /your/path/to/v2.22.tar.gz
    [root@LinuxServer trex]# ln -sf v2.22 current
    [root@LinuxServer trex]# ls -l
    total 4
    lrwxrwxrwx  1 root  root    5 Jun  9 01:00 current -> v2.22
    drwxr-xr-x 11 33066   25 4096 Jun  9 11:38 v2.22
    ```

    If intend to use MoonGen, then it can be build from this repo.  This repo includes a git submodule of a specific version of MoonGen repo, so that the txrx.lua script is synced with the proper version of MoonGen.  To build everything:

    ```
    [root@LinuxServer opt]#cd lua-trafficgen
    [root@LinuxServer lua-trafficgen]#./setup.sh 
    ```
## Configuration

1. Allocate huegpages needed by the traffic generator.  1GB page size is recommended.  Reboot after grub has been modified.
   ```         
   [root@LinuxServer ~]# grubby --update-kernel=`grubby --default-kernel` --args="default_hugepagesz=1G hugepagesz=1G hugepages=32"
   ```

2. Bind DPDK to two network interfaces needed by the traffic generator.  If you intend to use MoonGen and ran ./setup.sh previously, then you can use ./MoonGen/libmoon/deps/dpdk/tools/dpdk-devbind.py.  If you intend to use TRex, it also includes a binding utility under [/opt/trex/current]/dpdk_set_ports.py.  Binding with vfio-pci kernel module is recommended.
      
## Running
   
   binary-search.py is controlled entirely by command line options.  Please see all of the options with --help.  The recommded minimum number of optons are:
   
   --devices
   --traffic-generator
   --max-loss-pct
   --frame-size
   
   Note that you must use two physical devices, and these device shoud be connected direcly to a "device-under-test" or to each other to loopback testing
