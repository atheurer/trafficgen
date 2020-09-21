# README - Xena/trafficgen integration (using Valkyrie2544)

## Installation & Setup

1. For Linux, install Mono (https://www.mono-project.com/):
* Notes:
   * instructions are for CentOS/RHEL/Fedora, other distros please refer to https://www.mono-project.com/download/stable/#download-lin 
   * commands should be run in a root shell or using `sudo`

* Add Mono repo to system:
```bash
rpmkeys --import "http://pool.sks-keyservers.net/pks/lookup?op=get&search=0x3fa7e0328081bff6a14da29aa6a19b38d3d831ef"
su -c 'curl https://download.mono-project.com/repo/centos8-stable.repo | tee /etc/yum.repos.d/mono-centos8-stable.repo'
```

   * Install Mono:
```bash
yum install mono-complete -y
```

2. Download the trafficgen git repository
```bash
git clone https://github.com/atheurer/trafficgen
```


3. Obtain .x2544 config file & executable
   * Create a test config inside xena2544 utility on the xenaweb system (ask @ctrautma for IP if necessary)
   * Save config into the ftp folder off the c drive
   * Use FTP commands to download the config and the latest copy of Valkyrie2544.exe
   * Place both config and exe inside the trafficgen folder
```
ftp 11.11.111.11 [user]/[pwd]
bin
get valkyrie2544.exe
get <your config file>
```

5. Install TRex
   * Within trafficgen, open `install-trex.sh` for editing
   * Make the following change:
        * original: `if curl --output ${tarfile} ${trex_url} && tar zxf ${tarfile}; then`
        * modified: ``if curl --insecure --output ${tarfile} ${trex_url} && tar zxf ${tarfile}; then``
   * As root or using `sudo`, run: `./install-trex.sh`
   * After install completes, replace the following files with copies from test ZIP `fix_trex_install` (or make changes listed in Known Issues):
        * `trex_client.py` --> `/opt/trex/current/automation/trex_control_plane/interactive/trex/common/trex_client.py`
        * `trex_conn.py` --> `/opt/trex/current/automation/trex_control_plane/interactive/trex/common/trex_conn.py`
        * `trex_global_stats.py` --> `/opt/trex/current/automation/trex_control_plane/interactive/trex/common/stats/trex_global_stats.py`

6. Setup is complete, ready for testing


## Usage

* Run tests by issuing command line arguments to `binary-search.py` (see next section for syntax)
   * Ex: `python binary-search.py --traffic-generator valkyrie2544 --traffic-profile TestConfig1kflows.x2544 --validation-runtime 120 --search-runtime 60`

* Each test, a config file will be generated (by default `2bUsed.x2544`) - manually reviewing this file is helpful when troubleshooting
   * This file will be automatically created if none exists
   * Once created, this file will be overwritten by each successive test run

* Test information will be printed to terminal while running

* Results reports can be output in CSV, XML, or PDF
   * Default: CSV and XML reports are generated
   * PDF reports should not be used on Linux 

## Command Parameters

* `--traffic-generator valkyrie2544` : required to use Xena functionality

* `--traffic-profile <path_to_config_file>` : saved from Valkyrie2544.exe GUI with your config.

* `--valkyrie2544-smart_search` : enable smart search, if verify fails will resume the search at the half way point between the last verify attempt and the minimum search value. Otherwise the search will resume at the last verify attempt value, minus the value threshhold.

* `--validation-runtime` : sets the length of verification in seconds
        > Default : 600 (10 minutes)

* `--max-retries` : Maximum number of verify attempts before giving up
        > Default : 1

* `--valkyrie2544-pdf_output` : Output PDF report file. Disabled by default; will cause a crash on linux usually as a PDF renderer is not installed.

* `--valkyrie2544-windows_mode` : Enable windows mode. By default the mono package will be used to run the .exe file. If running on Windows this is not necessary.

* `--search-runtime` : Modify original config to use the duration specified.

* `--valkyrie2544-packet_sizes` : Customize packet sizes for throughput testing

* `--max-loss-pct` : Specify number of packages which can be lost as a percentage ([0 - 100]) (ex: a max loss rate of 5% would be written as `--max-loss-pct 5`)

* `--valkyrie2544-save_file_name` : Save config file which was created with the new arguments passed to this command.
        > Default : `./2bUsed.x2544`

* `--valkyrie2544-initial_tput` : Specify initial rate for throughput test (ex: a initial rate of 50% would be written as `--valkyrie2544-initial_tput 50`)

* `--valkyrie2544-max_tput` : Specify maximum rate for throughput test (ex: a maximum rate of 95% would be written as `--valkyrie2544-max_tput 95`)
        > Default : 100.00

* `--min-rate` : Specify minimum rate % for throughput test (ex: a minimum rate of 60% would be written as `--min-rate 60`)

* `--valkyrie2544-resolution_tput` : Specify resolution for throughput testing

* `--src-macs`: MAC address that becomes source of first active entity and destination for second (if two exist).

* `--dst-macs` : If specified, becomes destination of first active entity and source for second

* `--src-ips` : IP address that becomes source of first active entity and destination for second (if two exist).

* `--dst-ips` : If specified, becomes destination of first active entity (src-ips) and source for second

* `--use-src-ip-flows` / `--use-dst-ip-flows` : Apply flows to both MAC and IP addresses (if enabled overrides MAC flows option). Invoking either src-ip or dst-ip, or both, yields the same result 
        > Default : 1

* `--use-src-mac-flows` / `--use-dst-mac-flows` : Apply flows to MAC addresses only (overridden if IP flows are enabled). Invoking either src-mac or dst-mac, or both, yields the same result
        > Default: 1

* `--xena_module` : Specify int corresponding to the Xena chassis module number.

## Known Issues
* SyntaxError from `trex_client.py`
  * Open `/opt/trex/current/automation/trex_control_plane/interactive/trex/common/trex_client.py`
  * Change line 1188 from: `self.conn.async.set_timeout_sec(timeout_sec)` to: `self.conn.async_.set_timeout_sec(timeout_sec)`

* SyntaxError from `trex_conn.py`
  * Open `/opt/trex/current/automation/trex_control_plane/interactive/trex/common/trex_conn.py`
  * Change line 36 from: `self.async = TRexSubscriber(self.ctx, self.rpc)` to: `self.async_ = TRexSubscriber(self.ctx, self.rpc)`
  * Change line 60 from: `self.async.disconnect()` to: `self.async_.disconnect()`
  * Change line 89 from: `self.async.barrier()` to: `self.async_.barrier()`
  * Change line 98 from: `return self.async.barrier(baseline = True)` to: `return self.async_.barrier(baseline = True)`
  * Change line 110 from: `self.async.set_as_zombie()` to: `self.async_.set_as_zombie()`
  * Change line 143 from: `return ( self.async.last_data_recv_ts is not None and ((time.time() - self.async.last_data_recv_ts) <= 3) )` to `return ( self.async_.last_data_recv_ts is not None and ((time.time() - self.async_.last_data_recv_ts) <= 3) )`
  * Change line 189 from: `rc = self.async.connect()` to `rc = self.async_.connect()`

* SyntaxError from `trex_global_stats.py`
  * Open `/opt/trex/current/automation/trex_control_plane/interactive/trex/common/stats/trex_global_stats.py`
  * Change line 81 from: `("async_util.", "{0}% / {1}".format( format_threshold(round_float(self.client.conn.async.monitor.get_cpu_util()), [85, 100], [0, 85]),` to: `("async_util.", "{0}% / {1}".format( format_threshold(round_float(self.client.conn.async_.monitor.get_cpu_util()), [85, 100], [0, 85]),`
  * Change line 82 from: `format_num(self.client.conn.async.monitor.get_bps() / 8.0, suffix = "B/sec"))),` to: `format_num(self.client.conn.async_.monitor.get_bps() / 8.0, suffix = "B/sec"))),`
