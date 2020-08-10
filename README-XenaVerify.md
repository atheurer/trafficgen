# Xena2544ThroughputVerify
## Setup:

1. For linux Install Mono ->

    ```bash
    rpm --import "http://keyserver.ubuntu.com/pks/lookup?op=get&search=0x3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF"
    ```

    ```bash
    yum-config-manager --add-repo http://download.mono-project.com/repo/centos/
    ```

    ```bash
    yum -y install mono-complete-5.8.0.127-0.xamarin.3.epel7.x86_64
    ```

2. If python 3 not installed, install python 3. For RHEL instructions are below->

    ```
    cat <<'EOT' >> /etc/yum.repos.d/python34.repo

    [centos-sclo-rh]

    name=CentOS-7 - SCLo rh

    baseurl=http://mirror.centos.org/centos/7/sclo/$basearch/rh/

    gpgcheck=0

    enabled=1

    gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-SIG-SCLo

    EOT
    ```

    # install python34 scl package

    ```bash
    yum -y install rh-python34 rh-python34-python-tkinter
    ```

    # cleanup python 34 repo file

    ```bash
    rm -f /etc/yum.repos.d/python34.repo
    ```

3. Enable python34 -> `scl enable rh-python34 bash`

4. Make sure Valkyrie2544.exe is present in the current folder (formerly Xena2544.exe)

5. Copy your x2544 config file to the script folder

## Arguments to run this script:

    * `-f <path_to_config_file>` : saved from Valkyrie2544.exe GUI with your config.

    * `[-s]` : enable smart search, if verify fails will resume the search at the half way point between the last verify attempt and the minimum search value. Otherwise it will just resume at the last verify attempt value minus the value threshhold.

    * `[-l <verify_length_in_seconds>]` :
        > Default : 7200 (2 hours)

    * `[-r <retry_attempts>]` : Maximum number of verify attempts for giving up
        > Default : 10

    * `[-d]` : Enable debug mode

    * `[-p]` : Output PDF file. By default output of PDF report is disabled. Will cause a crash on linux usually as a pdf renderer is not installed.

    * `[-w]` : Enable windows mode. By default it will use the mono package to run the exe file. If running on windows this is not necessary.

    * `[-t <search_trial_duration_in_seconds>]` : Modify original config to use the duration specified.
        > Default : 0

    * `[-k <packet_size>+]` : Customize packet sizes for throughput testing

    * `[-a <acceptable_loss>]` : Specify number of packages which can be lost as a percentage ([0 - 100])

    * `[-v <save_file_name>]` : Save config file which was created with the new arguments passed to this command.
        > Default : `./2bUsed.x2544`

    * `[-i <initial_tput>]` : Specify initial rate for throughput test

    * `[-M <max_tput>]` : Specify maximum rate for throughput test

    * `[-m <min_tput>]` : Specify minimum rate for throughput test

    * `[-o <resolution_tput>]` : Specify resolution for throughput testing

    * `[-n <mac_address> [<mac_address>]]` : First MAC address becomes source of first active entity and destination for second (if two exist). Vice versa for the optional second argument.

    * `[-c <connection_ip> [<connection_ip>]]` : First IP address becomes source of first active entity and destination for second (if two exist). Vice versa for the optional second argument.

    * `[-u {1|1k|4k|10k|100k|1M}]` : Specify hardware modifier flows. Default behavior is to apply this to source and destination IP addresses
        * `[-b]` : Apply flows to both MAC and IP addresses (overrides `[-e]`)
        * `[-e]` : Apply flows to MAC addresses only
    
    * `--module` : Specify int corresponding to the Xena chassis module number.

## Sample execution:

   > Runs a 60 second trial with a 600 second verify using the myconfig.x2544 configuration file.

   ```bash
   python XenaVerify.py -f myconfig.x2544 -s -l 600 -t 60
   ```

#### Improvements to be done

* Add debug logging

* Add more customized options for modifying the running config
