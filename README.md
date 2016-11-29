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
