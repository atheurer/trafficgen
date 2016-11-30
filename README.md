# lua-trafficgen
A network traffic generator using Lua programming language and the MoonGen project

## Installation:
1.  Download the code:
    ```
    [root@LinuxServer root]#git clone https://github.com/atheurer/lua-trafficgen
    ```
    
2.  Build the code:
    ```
    [root@LinuxServer root]#cd lua-trafficgen
    [root@LinuxServer lua-trafficgen]#./setup.sh 
    ```

2.  Create a file called opnfv-vsperf-cfg.lua within the lua-trafficgen directory. 
    ```
    This is a configuration file that one can use to override default values. It should have the content structure:

    VSPERF {
    nrFlows = 1024,
    testType = "throughput",
    runBidirec = false,
    searchRunTime = 60,
    validationRunTime = 60,
    acceptableLossPct = 0.002,
    frameSize = 64,
    mppsPerQueue = 5,
    queuesPerTask = 3,
    ports = {0,1}
    }
    
    Please read the top comments within the trafficgen.lua for more details about settings.
    ```

4. Configure hugepage allocation
    Set up the huge allocation via setup-hugetlbfs.sh, or can do it via parameters at boot time thus will 
    be persistant across system reboots, e.g.:
        
        [root@LinuxServer lua-trafficgen]# ./MoonGen/setup-hugetlbfs.sh 
        
        or
        
        [root@LinuxServer lua-trafficgen]# cat /proc/cmdline
        BOOT_IMAGE=/vmlinuz-3.10.0-325.el7.x86_64 root=/dev/mapper/LinuxServer_rhel72-root ro crashkernel=auto rd.lvm.lv=LinuxServer_rhel72/root rd.lvm.lv=LinuxServer_rhel72/swap rhgb quiet LANG=en_US.UTF-8 intel_iommu=on default_hugepagesz=1G hugepagesz=1G hugepages=32 selinux=0 iommu=pt
        
        via using for example the grubby utility:
        
        [root@LinuxServer lua-trafficgen]# grubby --update-kernel=`grubby --default-kernel` --args="default_hugepagesz=1G hugepagesz=1G hugepages=32"
        
        Note that if the boot command line is modified, a reboot must occur in order to allocate memory with 
        the new hugepage settings.

5. Bind DPDK to interfaces of interest
    DPDK bypasses the native Linux networking stack and uses a userspace poll mode driver to transmit and 
    receive packets from the wire.  This is known as a "pass through mode".  
    ```    
    There are at least a few flavors of kernel drivers that will enable this packet pass through:
    - uio_pci_generic
          Generic User I/O kernel modules packaged with Linux kernel
    - igb_uio
          User I/O kernel modules packaged with MoonGen (within the DPDK dependency).  igb_uio built within 
          MoonGen dependencies and Intel specific
    - vfio-pci
          A more secure User I/O kernel driver that utilizes IOMMU hardware.  If using an Intel processor with IOMMU 
          supported hardware, the kernel bootloader parameter 'intel_iommu=on' must be added and can be again done using the   
          'grubby' utility  (grubby --update-kernel=`grubby --default-kernel` --args="intel_iommu=on") and then reboot
      
          It is recommended that if hardware support for IOMMU is there, use vfio-pci.  If not, use uio_pci_generic or i
          gb_uio.  One way to determine if IOMMU support is present is to look into the kernel log:
          [root@LinuxServer ~]# dmesg | grep -i IOMMU
          [    0.000000 ] Intel-IOMMU: enabled
      ```
6. Determine the PCI 'Doman:Bus:Device:Function' information for the interfaces which you want to use 
   MoonGen (and thus bind DPDK).  
    ```
    This can be done via the 'ethtool' (yum install ethtool) utility via 'ethtool -i <interface_name>', e.g.:
      
    [root@LinuxServer MoonGen]# ethtool -i em1 | grep 'bus-info'
    bus-info: 0000:01:00.0
    [root@LinuxServer MoonGen]# ethtool -i em2 | grep 'bus-info'
    bus-info: 0000:01:00.1
      
    where in this case network devices 'em1' and 'em2' are both 10G capable ports where its desired to use 
    MoonGen to TX/RX traffic.
      
    This can also be seen via the DPDK utility 'dpdk-devbind.py' again under MoonGen's DPDK dependency directory:

    [root@LinuxServer lua-trafficgen]./MoonGen/libmoon/deps/dpdk/tools/dpdk-devbind.py --status

    Network devices using DPDK-compatible driver
    ============================================
    <none>

    Network devices using kernel driver
    ===================================
    0000:01:00.0 '82599ES 10-Gigabit SFI/SFP+ Network Connection' if=em1 drv=ixgbe unused= 
    0000:01:00.1 '82599ES 10-Gigabit SFI/SFP+ Network Connection' if=em2 drv=ixgbe unused= 
    0000:03:00.0 'Ethernet Controller XL710 for 40GbE QSFP+' if=p3p1 drv=i40e unused= 
    0000:03:00.1 'Ethernet Controller XL710 for 40GbE QSFP+' if=p3p2 drv=i40e unused= 
    0000:05:00.0 'I350 Gigabit Network Connection' if=em3 drv=igb unused= *Active*
    0000:05:00.1 'I350 Gigabit Network Connection' if=em4 drv=igb unused= 
    0000:81:00.0 '82599ES 10-Gigabit SFI/SFP+ Network Connection' if=p2p1 drv=ixgbe unused= 
    0000:81:00.1 '82599ES 10-Gigabit SFI/SFP+ Network Connection' if=p2p2 drv=ixgbe unused= 

    Other network devices
    =====================
    <none>
    
    Use 'dpdk-devbind.py' to unbind network devices from current drivers. In this case, its ixgbe. Before 
    doing the unbind, shutdown the interfaces.
     
    [root@LinuxServer lua-trafficgen]# ifdown em1 
    [root@LinuxServer lua-trafficgen]# ifdown em2 
    [root@LinuxServer lua-trafficgen]./MoonGen/libmoon/deps/dpdk/tools/dpdk-devbind.py --unbind 0000:01:00.0 0000:01:00.1

    Again using 'dpdk-devbind.py', bind DPDK to the interfaces to be used with MoonGen.  In this case, 
    the two 10G network devices will be used:

    [root@LinuxServer lua-trafficgen]#modprobe vfio-pci 
    [root@LinuxServer lua-trafficgen]#./MoonGen/libmoon/deps/dpdk/tools/dpdk-devbind.py --bind=vfio-pci 0000:01:00.0 0000:01:00.1
        
    And now it can be seen that the 10G network devices are bound to the appropriate DPDK supported driver:
        
    [root@LinuxServer lua-trafficgen]./MoonGen/libmoon/deps/dpdk/tools/dpdk-devbind.py --status
    
    Network devices using DPDK-compatible driver
    ============================================
    0000:01:00.0 '82599ES 10-Gigabit SFI/SFP+ Network Connection' drv=vfio-pci unused=ixgbe
    0000:01:00.1 '82599ES 10-Gigabit SFI/SFP+ Network Connection' drv=vfio-pci unused=ixgbe

    Network devices using kernel driver
    ===================================
    0000:03:00.0 'Ethernet Controller XL710 for 40GbE QSFP+' if=p3p1 drv=i40e unused=vfio-pci 
    0000:03:00.1 'Ethernet Controller XL710 for 40GbE QSFP+' if=p3p2 drv=i40e unused=vfio-pci 
    0000:05:00.0 'I350 Gigabit Network Connection' if=em3 drv=igb unused=vfio-pci *Active*
    0000:05:00.1 'I350 Gigabit Network Connection' if=em4 drv=igb unused=vfio-pci 
    0000:81:00.0 '82599ES 10-Gigabit SFI/SFP+ Network Connection' if=p2p1 drv=ixgbe unused=vfio-pci 
    0000:81:00.1 '82599ES 10-Gigabit SFI/SFP+ Network Connection' if=p2p2 drv=ixgbe unused=vfio-pci 

    Other network devices
    =====================
    <none>

     ```

## Running trafficgen/MoonGen
   
   ```
   Simply run trafficgen/MoonGen as follows.  Note there will be a calibration phase at the 
   beginning followed by the RFC 2544 test.
   
   Here is an example of a short run (100% packet loss allowed so test won't run very long):
   
[root@LinuxServer lua-trafficgen]#./MoonGen/build/MoonGen trafficgen.lua 

[WARN]  malloc() allocates objects >= 1 MiB from LuaJIT memory space.
[WARN]  Install libjemalloc if you encounter out of memory errors.
[INFO]  Initializing DPDK. This will take a few seconds...
EAL: Detected 24 lcore(s)
EAL: Probing VFIO support...
EAL: VFIO support initialized
EAL: PCI device 0000:01:00.0 on NUMA socket 0
EAL:   probe driver: 8086:10fb rte_ixgbe_pmd
EAL:   using IOMMU type 1 (Type 1)
EAL: Ignore mapping IO port bar(2) addr: 2021
EAL: PCI device 0000:01:00.1 on NUMA socket 0
EAL:   probe driver: 8086:10fb rte_ixgbe_pmd
EAL: Ignore mapping IO port bar(2) addr: 2001
EAL: PCI device 0000:03:00.0 on NUMA socket 0
EAL:   probe driver: 8086:1583 rte_i40e_pmd
EAL: PCI device 0000:03:00.1 on NUMA socket 0
EAL:   probe driver: 8086:1583 rte_i40e_pmd
EAL: PCI device 0000:05:00.0 on NUMA socket 0
EAL:   probe driver: 8086:1521 rte_igb_pmd
EAL: PCI device 0000:05:00.1 on NUMA socket 0
EAL:   probe driver: 8086:1521 rte_igb_pmd
EAL: PCI device 0000:81:00.0 on NUMA socket 1
EAL:   probe driver: 8086:10fb rte_ixgbe_pmd
EAL: PCI device 0000:81:00.1 on NUMA socket 1
EAL:   probe driver: 8086:10fb rte_ixgbe_pmd
[INFO]  Found 2 usable devices:
   Device 0: EC:F4:BB:CE:CF:78 (Intel Corporation 82599ES 10-Gigabit SFI/SFP+ Network Connection)
   Device 1: EC:F4:BB:CE:CF:7A (Intel Corporation 82599ES 10-Gigabit SFI/SFP+ Network Connection)
[INFO]  reading [opnfv-vsperf-cfg.lua]
[INFO]  testParams => {
[INFO]  	srcIp: 16843009
[INFO]  	srcMac: 00:00:00:00:00:00
[INFO]  	nrFlows: 256
[INFO]  	latencyRunTime: 1800
[INFO]  	searchRunTime: 30
[INFO]  	oneShot: true
[INFO]  	rxQueuesPerDev: 1
[INFO]  	acceptableLossPct: 100
[INFO]  	srcPort: 1234
[INFO]  	dstIp: 1515870810
[INFO]  	linkSpeed: 10000000000
[INFO]  	queuesPerTask: 3
[INFO]  	mppsPerQueue: 5
[INFO]  	dstPort: 1234
[INFO]  	negativeLossRetry: true
[INFO]  	startRate: 14.880952380952
[INFO]  	flowMods => {
[INFO]  		1: srcIp
[INFO]  	}
[INFO]  	testType: throughput
[INFO]  	rate_granularity: 0.1
[INFO]  	frameSize: 64
[INFO]  	validationRunTime: 30
[INFO]  	runBidirec: true
[INFO]  	dstMac: 00:00:00:00:00:00
[INFO]  	txMethod: hardware
[INFO]  	ports => {
[INFO]  		1: 0
[INFO]  		2: 1
[INFO]  	}
[INFO]  }
[INFO]  testparams.txQueuesPerDev: 3
[INFO]  testparams.txTasks: 1
[INFO]  number of rx queues: 1
[INFO]  number of tx queues: 3
[INFO]  device 0 transmits to device 1
[INFO]  device 1 transmits to device 0
[INFO]  device 0 src MAC: [[TxQueue: id=0, qid=0]]
[INFO]  device 1 src MAC: [[TxQueue: id=1, qid=0]]
[INFO]  device 0 when transmitting will use dst MAC: [[TxQueue: id=1, qid=0]]
[INFO]  device 1 when transmitting will use dst MAC: [[TxQueue: id=0, qid=0]]
[INFO]  Waiting for devices to come up...
[INFO]  Device 1 (EC:F4:BB:CE:CF:7A) is up: 10000 MBit/s
[INFO]  Device 0 (EC:F4:BB:CE:CF:78) is up: 10000 MBit/s
[INFO]  2 devices are up.
[INFO]  Finding maximum Tx Rate
[INFO]  calibrateSlave: devId: 1  taskId: 0  calibratedRate: 14.8810 queues: [TxQueue: id=0, qid=0][TxQueue: id=0, qid=1][TxQueue: id=0, qid=2]
[Device: id=0] TX: 14.88 Mpps, 7618 Mbit/s (9999 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 (StdDev 0.00) Mpps, 7619 (StdDev 0) Mbit/s (10000 Mbit/s with framing), total 74402307 packets with 4761747648 bytes (incl. CRC)
[INFO]  Max Tx rate: 14.88
[INFO]  testparams.txQueuesPerDev: 3
[INFO]  testparams.txTasks: 1
[INFO]  calibrateSlave: devId: 1  taskId: 0  calibratedRate: 14.8807 queues: [TxQueue: id=0, qid=0][TxQueue: id=0, qid=1][TxQueue: id=0, qid=2]
[Device: id=0] TX: 14.88 Mpps, 7617 Mbit/s (9997 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 (StdDev 0.00) Mpps, 7619 (StdDev 0) Mbit/s (10000 Mbit/s with framing), total 74396259 packets with 4761360576 bytes (incl. CRC)
[INFO]  measuredRate: 14.8807  desiredRate:14.8807  new correction_ratio: 0.9900  new calibratedRate: 14.7319 
[INFO]  calibrateSlave: devId: 1  taskId: 0  calibratedRate: 14.7319 queues: [TxQueue: id=0, qid=0][TxQueue: id=0, qid=1][TxQueue: id=0, qid=2]
[Device: id=0] TX: 14.88 Mpps, 7617 Mbit/s (9998 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 (StdDev 0.00) Mpps, 7619 (StdDev 0) Mbit/s (10000 Mbit/s with framing), total 74396826 packets with 4761396864 bytes (incl. CRC)
[INFO]  measuredRate: 14.8807  desiredRate:14.8807  new correction_ratio: 0.9900  new calibratedRate: 14.5846 
[INFO]  calibrateSlave: devId: 1  taskId: 0  calibratedRate: 14.5846 queues: [TxQueue: id=0, qid=0][TxQueue: id=0, qid=1][TxQueue: id=0, qid=2]
[Device: id=0] TX: 14.88 Mpps, 7618 Mbit/s (9998 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 (StdDev 0.00) Mpps, 7619 (StdDev 0) Mbit/s (10000 Mbit/s with framing), total 74396826 packets with 4761396864 bytes (incl. CRC)
[INFO]  measuredRate: 14.8807  desiredRate:14.8807  new correction_ratio: 0.9900  new calibratedRate: 14.4388 
[INFO]  calibrateSlave: devId: 1  taskId: 0  calibratedRate: 14.4388 queues: [TxQueue: id=0, qid=0][TxQueue: id=0, qid=1][TxQueue: id=0, qid=2]
[Device: id=0] TX: 14.88 Mpps, 7618 Mbit/s (9999 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 (StdDev 0.00) Mpps, 7619 (StdDev 0) Mbit/s (10000 Mbit/s with framing), total 74402307 packets with 4761747648 bytes (incl. CRC)
[INFO]  measuredRate: 14.8807  desiredRate:14.8807  new correction_ratio: 0.9900  new calibratedRate: 14.2944 
[INFO]  calibrateSlave: devId: 1  taskId: 0  calibratedRate: 14.2944 queues: [TxQueue: id=0, qid=0][TxQueue: id=0, qid=1][TxQueue: id=0, qid=2]
[Device: id=0] TX: 14.88 Mpps, 7618 Mbit/s (9999 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 (StdDev 0.00) Mpps, 7619 (StdDev 0) Mbit/s (10000 Mbit/s with framing), total 74401551 packets with 4761699264 bytes (incl. CRC)
[INFO]  measuredRate: 14.8807  desiredRate:14.8807  new correction_ratio: 0.9900  new calibratedRate: 14.1514 
[INFO]  calibrateSlave: devId: 1  taskId: 0  calibratedRate: 14.1514 queues: [TxQueue: id=0, qid=0][TxQueue: id=0, qid=1][TxQueue: id=0, qid=2]
[Device: id=0] TX: 14.85 Mpps, 7604 Mbit/s (9980 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 (StdDev 0.00) Mpps, 7619 (StdDev 0) Mbit/s (10000 Mbit/s with framing), total 74373579 packets with 4759909056 bytes (incl. CRC)
[INFO]  measuredRate: 14.8807  desiredRate:14.8807  new correction_ratio: 0.9900  new calibratedRate: 14.0099 
[INFO]  calibrateSlave: devId: 1  taskId: 0  calibratedRate: 14.0099 queues: [TxQueue: id=0, qid=0][TxQueue: id=0, qid=1][TxQueue: id=0, qid=2]
[Device: id=0] TX: 14.88 Mpps, 7618 Mbit/s (9999 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 (StdDev 0.00) Mpps, 7619 (StdDev 0) Mbit/s (10000 Mbit/s with framing), total 74401173 packets with 4761675072 bytes (incl. CRC)
[INFO]  measuredRate: 14.8807  desiredRate:14.8807  new correction_ratio: 0.9900  new calibratedRate: 13.8698 
[INFO]  calibrateSlave: devId: 1  taskId: 0  calibratedRate: 13.8698 queues: [TxQueue: id=0, qid=0][TxQueue: id=0, qid=1][TxQueue: id=0, qid=2]
[Device: id=0] TX: 14.72 Mpps, 7537 Mbit/s (9892 Mbit/s with framing)
[Device: id=0] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.76 (StdDev 0.00) Mpps, 7559 (StdDev 0) Mbit/s (9921 Mbit/s with framing), total 73771425 packets with 4721371200 bytes (incl. CRC)
[WARN]  Start rate has been reduced from 14.88 to 14.88 because the original start rate could not be achieved.
Running single throughput test
[INFO]  testparams.txQueuesPerDev: 3
[INFO]  testparams.txTasks: 1
[INFO]  number of rx queues: 1
[INFO]  number of tx queues: 3
[INFO]  device 0 transmits to device 1
[INFO]  device 1 transmits to device 0
[WARN]  Device 0 already configured, skipping initilization
[INFO]  device 0 src MAC: [[TxQueue: id=0, qid=0]]
[WARN]  Device 1 already configured, skipping initilization
[INFO]  device 1 src MAC: [[TxQueue: id=1, qid=0]]
[INFO]  device 0 when transmitting will use dst MAC: [[TxQueue: id=1, qid=0]]
[INFO]  device 1 when transmitting will use dst MAC: [[TxQueue: id=0, qid=0]]
[INFO]  Waiting for devices to come up...
[INFO]  Device 1 (EC:F4:BB:CE:CF:7A) is up: 10000 MBit/s
[INFO]  Device 0 (EC:F4:BB:CE:CF:78) is up: 10000 MBit/s
[INFO]  2 devices are up.
[INFO]  Starting tramsnit rate calibration for device 0
[INFO]  calibrateSlave: devId: 1  taskId: 0  calibratedRate: 14.8807 queues: [TxQueue: id=0, qid=0][TxQueue: id=0, qid=1][TxQueue: id=0, qid=2]
[Device: id=0] TX: 14.88 Mpps, 7618 Mbit/s (9999 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 (StdDev 0.00) Mpps, 7619 (StdDev 0) Mbit/s (10000 Mbit/s with framing), total 74401362 packets with 4761687168 bytes (incl. CRC)
[INFO]  Device 2 measuredRate: 14.8807  desiredRate:14.8807  new correction_ratio: 0.9900  new calibratedRate: 14.7319 
[INFO]  calibrateSlave: devId: 1  taskId: 0  calibratedRate: 14.7319 queues: [TxQueue: id=0, qid=0][TxQueue: id=0, qid=1][TxQueue: id=0, qid=2]
[Device: id=0] TX: 14.87 Mpps, 7615 Mbit/s (9994 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 (StdDev 0.00) Mpps, 7619 (StdDev 0) Mbit/s (10000 Mbit/s with framing), total 74395692 packets with 4761324288 bytes (incl. CRC)
[INFO]  Device 2 measuredRate: 14.8807  desiredRate:14.8807  new correction_ratio: 0.9900  new calibratedRate: 14.5846 
[INFO]  calibrateSlave: devId: 1  taskId: 0  calibratedRate: 14.5846 queues: [TxQueue: id=0, qid=0][TxQueue: id=0, qid=1][TxQueue: id=0, qid=2]
[Device: id=0] TX: 14.88 Mpps, 7618 Mbit/s (9998 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (9999 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=0] TX: 14.88 (StdDev 0.00) Mpps, 7619 (StdDev 0) Mbit/s (10000 Mbit/s with framing), total 74396826 packets with 4761396864 bytes (incl. CRC)
[INFO]  Device 0 rate calibration complete
[INFO]  Starting tramsnit rate calibration for device 1
[INFO]  calibrateSlave: devId: 2  taskId: 0  calibratedRate: 14.5846 queues: [TxQueue: id=1, qid=0][TxQueue: id=1, qid=1][TxQueue: id=1, qid=2]
[Device: id=1] TX: 14.88 Mpps, 7617 Mbit/s (9997 Mbit/s with framing)
[Device: id=1] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] TX: 14.88 (StdDev 0.00) Mpps, 7619 (StdDev 0) Mbit/s (10000 Mbit/s with framing), total 74400417 packets with 4761626688 bytes (incl. CRC)
[INFO]  Device 1 measuredRate: 14.8807  desiredRate:14.8807  new correction_ratio: 0.9900  new calibratedRate: 14.4388 
[INFO]  calibrateSlave: devId: 2  taskId: 0  calibratedRate: 14.4388 queues: [TxQueue: id=1, qid=0][TxQueue: id=1, qid=1][TxQueue: id=1, qid=2]
[Device: id=1] TX: 14.88 Mpps, 7618 Mbit/s (9999 Mbit/s with framing)
[Device: id=1] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] TX: 14.88 (StdDev 0.00) Mpps, 7619 (StdDev 0) Mbit/s (10000 Mbit/s with framing), total 74401929 packets with 4761723456 bytes (incl. CRC)
[INFO]  Device 1 measuredRate: 14.8807  desiredRate:14.8807  new correction_ratio: 0.9900  new calibratedRate: 14.2944 
[INFO]  calibrateSlave: devId: 2  taskId: 0  calibratedRate: 14.2944 queues: [TxQueue: id=1, qid=0][TxQueue: id=1, qid=1][TxQueue: id=1, qid=2]
[Device: id=1] TX: 14.88 Mpps, 7618 Mbit/s (9999 Mbit/s with framing)
[Device: id=1] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] TX: 14.88 (StdDev 0.00) Mpps, 7619 (StdDev 0) Mbit/s (10000 Mbit/s with framing), total 74402496 packets with 4761759744 bytes (incl. CRC)
[INFO]  Device 1 measuredRate: 14.8807  desiredRate:14.8807  new correction_ratio: 0.9900  new calibratedRate: 14.1514 
[INFO]  calibrateSlave: devId: 2  taskId: 0  calibratedRate: 14.1514 queues: [TxQueue: id=1, qid=0][TxQueue: id=1, qid=1][TxQueue: id=1, qid=2]
[Device: id=1] TX: 14.88 Mpps, 7617 Mbit/s (9998 Mbit/s with framing)
[Device: id=1] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] TX: 14.88 (StdDev 0.00) Mpps, 7619 (StdDev 0) Mbit/s (10000 Mbit/s with framing), total 74397015 packets with 4761408960 bytes (incl. CRC)
[INFO]  Device 1 measuredRate: 14.8807  desiredRate:14.8807  new correction_ratio: 0.9900  new calibratedRate: 14.0099 
[INFO]  calibrateSlave: devId: 2  taskId: 0  calibratedRate: 14.0099 queues: [TxQueue: id=1, qid=0][TxQueue: id=1, qid=1][TxQueue: id=1, qid=2]
[Device: id=1] TX: 14.88 Mpps, 7618 Mbit/s (9999 Mbit/s with framing)
[Device: id=1] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] TX: 14.88 (StdDev 0.00) Mpps, 7619 (StdDev 0) Mbit/s (10000 Mbit/s with framing), total 74400984 packets with 4761662976 bytes (incl. CRC)
[INFO]  Device 1 measuredRate: 14.8807  desiredRate:14.8807  new correction_ratio: 0.9900  new calibratedRate: 13.8698 
[INFO]  calibrateSlave: devId: 2  taskId: 0  calibratedRate: 13.8698 queues: [TxQueue: id=1, qid=0][TxQueue: id=1, qid=1][TxQueue: id=1, qid=2]
[Device: id=1] TX: 14.76 Mpps, 7555 Mbit/s (9916 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=1] TX: 14.76 (StdDev 0.00) Mpps, 7559 (StdDev 0) Mbit/s (9921 Mbit/s with framing), total 73807902 packets with 4723705728 bytes (incl. CRC)
[INFO]  Device 1 rate calibration complete
[Device: id=1] RX: 0.00 Mpps, 0 Mbit/s (0 Mbit/s with framing)
[Device: id=0] RX: 0.00 Mpps, 0 Mbit/s (0 Mbit/s with framing)
[Device: id=1] RX: 0.00 Mpps, 0 Mbit/s (0 Mbit/s with framing)
[Device: id=0] RX: 0.00 Mpps, 0 Mbit/s (0 Mbit/s with framing)
[INFO]  Starting final validation
Testing 14.88 Mfps
Testing 14.88 Mfps
[Device: id=1] RX: 0.00 Mpps, 0 Mbit/s (0 Mbit/s with framing)
[Device: id=0] RX: 0.00 Mpps, 0 Mbit/s (0 Mbit/s with framing)
[INFO]  loadSlave: devId: 2  taskId: 0  calibratedRate: 13.8698 queues: [TxQueue: id=1, qid=0][TxQueue: id=1, qid=1][TxQueue: id=1, qid=2]
[INFO]  loadSlave test to run for 30 seconds
[INFO]  loadSlave: devId: 1  taskId: 0  calibratedRate: 14.5846 queues: [TxQueue: id=0, qid=0][TxQueue: id=0, qid=1][TxQueue: id=0, qid=2]
[INFO]  loadSlave test to run for 30 seconds
[Device: id=1] RX: 1.41 Mpps, 721 Mbit/s (946 Mbit/s with framing)
[Device: id=0] RX: 1.28 Mpps, 657 Mbit/s (862 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7557 Mbit/s (9918 Mbit/s with framing)
[Device: id=0] TX: 14.86 Mpps, 7607 Mbit/s (9984 Mbit/s with framing)
[Device: id=1] RX: 1.45 Mpps, 743 Mbit/s (976 Mbit/s with framing)
[Device: id=0] RX: 1.30 Mpps, 666 Mbit/s (874 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7617 Mbit/s (9997 Mbit/s with framing)
[Device: id=1] RX: 1.46 Mpps, 748 Mbit/s (982 Mbit/s with framing)
[Device: id=0] RX: 1.31 Mpps, 670 Mbit/s (879 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.46 Mpps, 748 Mbit/s (982 Mbit/s with framing)
[Device: id=0] RX: 1.31 Mpps, 671 Mbit/s (881 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7558 Mbit/s (9920 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.47 Mpps, 752 Mbit/s (987 Mbit/s with framing)
[Device: id=0] RX: 1.31 Mpps, 671 Mbit/s (880 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.46 Mpps, 750 Mbit/s (984 Mbit/s with framing)
[Device: id=0] RX: 1.31 Mpps, 672 Mbit/s (882 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.46 Mpps, 747 Mbit/s (981 Mbit/s with framing)
[Device: id=0] RX: 1.31 Mpps, 669 Mbit/s (878 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.46 Mpps, 748 Mbit/s (982 Mbit/s with framing)
[Device: id=0] RX: 1.31 Mpps, 670 Mbit/s (879 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.47 Mpps, 751 Mbit/s (986 Mbit/s with framing)
[Device: id=0] RX: 1.31 Mpps, 672 Mbit/s (882 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.48 Mpps, 758 Mbit/s (995 Mbit/s with framing)
[Device: id=0] RX: 1.32 Mpps, 678 Mbit/s (890 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7558 Mbit/s (9920 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.46 Mpps, 749 Mbit/s (983 Mbit/s with framing)
[Device: id=0] RX: 1.31 Mpps, 671 Mbit/s (880 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.46 Mpps, 746 Mbit/s (979 Mbit/s with framing)
[Device: id=0] RX: 1.31 Mpps, 669 Mbit/s (878 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.48 Mpps, 756 Mbit/s (992 Mbit/s with framing)
[Device: id=0] RX: 1.32 Mpps, 675 Mbit/s (886 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.48 Mpps, 758 Mbit/s (995 Mbit/s with framing)
[Device: id=0] RX: 1.32 Mpps, 678 Mbit/s (890 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.50 Mpps, 769 Mbit/s (1009 Mbit/s with framing)
[Device: id=0] RX: 1.34 Mpps, 688 Mbit/s (903 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.50 Mpps, 768 Mbit/s (1008 Mbit/s with framing)
[Device: id=0] RX: 1.34 Mpps, 687 Mbit/s (901 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.50 Mpps, 767 Mbit/s (1006 Mbit/s with framing)
[Device: id=0] RX: 1.34 Mpps, 685 Mbit/s (898 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.50 Mpps, 769 Mbit/s (1010 Mbit/s with framing)
[Device: id=0] RX: 1.34 Mpps, 687 Mbit/s (902 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.50 Mpps, 767 Mbit/s (1007 Mbit/s with framing)
[Device: id=0] RX: 1.34 Mpps, 685 Mbit/s (900 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.50 Mpps, 766 Mbit/s (1006 Mbit/s with framing)
[Device: id=0] RX: 1.34 Mpps, 685 Mbit/s (899 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.50 Mpps, 768 Mbit/s (1008 Mbit/s with framing)
[Device: id=0] RX: 1.34 Mpps, 685 Mbit/s (899 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.50 Mpps, 766 Mbit/s (1005 Mbit/s with framing)
[Device: id=0] RX: 1.34 Mpps, 685 Mbit/s (899 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.49 Mpps, 762 Mbit/s (1000 Mbit/s with framing)
[Device: id=0] RX: 1.33 Mpps, 682 Mbit/s (896 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.49 Mpps, 761 Mbit/s (999 Mbit/s with framing)
[Device: id=0] RX: 1.33 Mpps, 679 Mbit/s (891 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.49 Mpps, 763 Mbit/s (1001 Mbit/s with framing)
[Device: id=0] RX: 1.33 Mpps, 682 Mbit/s (896 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.50 Mpps, 766 Mbit/s (1005 Mbit/s with framing)
[Device: id=0] RX: 1.33 Mpps, 683 Mbit/s (897 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.49 Mpps, 762 Mbit/s (1000 Mbit/s with framing)
[Device: id=0] RX: 1.33 Mpps, 680 Mbit/s (892 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.48 Mpps, 760 Mbit/s (998 Mbit/s with framing)
[Device: id=0] RX: 1.33 Mpps, 681 Mbit/s (894 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.47 Mpps, 754 Mbit/s (990 Mbit/s with framing)
[Device: id=0] RX: 1.32 Mpps, 675 Mbit/s (886 Mbit/s with framing)
[Device: id=1] TX: 14.76 Mpps, 7559 Mbit/s (9921 Mbit/s with framing)
[Device: id=0] TX: 14.88 Mpps, 7619 Mbit/s (10000 Mbit/s with framing)
[Device: id=1] RX: 1.49 Mpps, 761 Mbit/s (998 Mbit/s with framing)
[Device: id=0] RX: 1.33 Mpps, 681 Mbit/s (893 Mbit/s with framing)
[Device: id=1] TX: 14.76 (StdDev 0.00) Mpps, 7559 (StdDev 0) Mbit/s (9921 Mbit/s with framing), total 442891071 packets with 28345028544 bytes (incl. CRC)
[Device: id=0] TX: 14.88 (StdDev 0.00) Mpps, 7619 (StdDev 0) Mbit/s (10000 Mbit/s with framing), total 446390784 packets with 28569010176 bytes (incl. CRC)
[INFO]  Stopping final validation
[Device: id=1] RX: 0.06 Mpps, 30 Mbit/s (39 Mbit/s with framing)
[Device: id=0] RX: 0.03 Mpps, 17 Mbit/s (22 Mbit/s with framing)
[Device: id=1] RX: 0.00 Mpps, 0 Mbit/s (0 Mbit/s with framing)
[Device: id=0] RX: 0.00 Mpps, 0 Mbit/s (0 Mbit/s with framing)
[Device: id=1] RX: 1.31 (StdDev 0.48) Mpps, 669 (StdDev 245) Mbit/s (878 Mbit/s with framing), total 44400652 packets with 2841641728 bytes (incl. CRC)
[Device: id=0] RX: 1.17 (StdDev 0.43) Mpps, 598 (StdDev 220) Mbit/s (785 Mbit/s with framing), total 39715099 packets with 2541766336 bytes (incl. CRC)
[INFO]  Device 0->1: PASSED - frame loss (401990132, 90.05341203%) is less than or equal to the maximum (100.00000000%)
[INFO]  Device 1->0: PASSED - frame loss (403175972, 91.03276142%) is less than or equal to the maximum (100.00000000%)
[INFO]  Test Result: PASSED
[PARAMETERS] startRate: 14.880952 nrFlows: 256 frameSize: 64 runBidirec: true searchRunTime: 30 validationRunTime: 30 acceptableLossPct: 100.000000 ports: 1,2
[REPORT]Device 0->1: Tx frames: 446390784 Rx Frames: 44400652 frame loss: 401990132, 90.053412% Rx Mpps: 1.480113
[REPORT]Device 1->0: Tx frames: 442891071 Rx Frames: 39715099 frame loss: 403175972, 91.032761% Rx Mpps: 1.323869
[REPORT]      total: Tx frames: 889281855 Rx Frames: 84115751 frame loss: 805166104, 90.541160% Tx Mpps: 29.644006 Rx Mpps: 2.803982

   
   ```
   
   
  
