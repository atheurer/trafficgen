# trafficgen
This is a collection of traffic generator scripts for use with TRex (https://trex-tgn.cisco.com/).  Please see the respective README files depending on your needs.

script | description | README
-------|-------------|-------
binary-search.py | This script is the primary interface through which trafficgen is operated.  It implements the binary search logic for finding maximum throughput and executes the specified traffic generator for running trials.  The binary search logic can be tested by using the null-txrx.py traffic generator.  | README-binary-search.md
trex-txrx.py | A simple TRex based traffic generator that executes a single trial based on the provided arguments.  Usually invoked by binary-search.py. | README-trex-txrx.md
trex-txrx-profile.py | A more complex TRex based traffic generator that executes a single trial based on a supplied JSON profile file.  Usually invoked by binary-search.py. | README-trex-txrx-profile.md
trex-query.py | Queries TRex for information about the requested ports.  Usually invoked by binary-search.py or the TRex traffic generator script. |
null-txrx.py | A faux traffic producer which is used to test the binary search logic of binary-search.py.  Usually invoked by binary-search.py. |
install-trex.sh | Installs TRex.  The version of TRex installed is hard coded because it has been tested for functionality and compatibility with trafficgen. |
launch-trex.sh | Configure and launch the TRex server.  By default it detects system specific details and uses those to generate what it believes to be an optimal TRex configuration.  It can be used to launch TRex with a user supplied configuration file if necessary. |
pbench-run.py | This is a shim script to aide in invoking trafficgen from Pbench (https://github.com/distributed-system-analysis/pbench).  This should not be directly used by an end user. |
postprocess-trex-profiler.py | Process data collected by the trex-txrx-profile.py TRex profiler which captures TRex statistics while a trial is running.  This is run by binary-search.py and should usually not be directly invoked by an end user. |
profile-builder.py | Take simple, trex-txrx.py like arguments and generate a traffic profile usable by trex-txrx-profile.py |
reporter.py | Used to extract information about a binary-search.py run from the resulting binary-search.json file |
tg_lib.py | Library of generic Python routines that are shared across many of the scripts in this project.  Should not/cannot be directly invoked. |
trex_tg_lib.py | Library of TRex related Python routines that are shared between the TRex traffic generators.  Should not/cannot be directly invoked. |
