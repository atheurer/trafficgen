# Valkyrie2544


## Installation / Setup

1. Download the trafficgen git repository
    ```
    git clone https://github.com/atheurer/trafficgen
    ```

2. For Linux, install Mono (https://www.mono-project.com/):
    * instructions are for CentOS/RHEL/Fedora, other distros please refer to https://www.mono-project.com/download/stable/#download-lin 
    * commands should be run in a root shell
    * Add Mono repo to system
      ```bash
      rpmkeys --import "http://pool.sks-keyservers.net/pks/lookup?op=get&search=0x3fa7e0328081bff6a14da29aa6a19b38d3d831ef"
      su -c 'curl https://download.mono-project.com/repo/centos8-stable.repo | tee /etc/yum.repos.d/mono-centos8-stable.repo'
      ```
    * Install Mono
    ```bash
    yum install mono-complete
    ```
3. Download the latest copy of Valkyrie2544.exe and the x2544 config file from the control box

4. Make sure both Valkyrie2544.exe and config file are present in the local trafficgen repo folder 

## Running
Arguments:
* `--traffic-profile <path_to_config_file>` : saved from Valkyrie2544.exe GUI with your config.

* `--valkyrie2544-smart_search` : enable smart search, if verify fails will resume the search at the half way point between the last verify attempt and the minimum search value. Otherwise the search will resume at the last verify attempt value, minus the value threshhold.

* `--validation-runtime` : sets the length of verification in seconds
        > Default : 600 (10 minutes)

* `--max-retries` : Maximum number of verify attempts before giving up
        > Default : 1

* `--valkyrie2544-pdf_output` : Output PDF file. By default output of PDF report is disabled. Will cause a crash on linux usually as a pdf renderer is not installed.

* `--valkyrie2544-windows_mode` : Enable windows mode. By default the mono package will be used to run the .exe file. If running on windows this is not necessary.

* `--search-runtime` : Modify original config to use the duration specified.

* `--valkyrie2544-packet_sizes` : Customize packet sizes for throughput testing

* `--max-loss-pct` : Specify number of packages which can be lost as a percentage ([0 - 100])

* `--valkyrie2544-save_file_name` : Save config file which was created with the new arguments passed to this command.
        > Default : `./2bUsed.x2544`

* `--valkyrie2544-initial_tput` : Specify initial rate for throughput test

* `--rate` : Specify maximum rate for throughput test

* `--min-rate` : Specify minimum rate for throughput test

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

