# trafficgen
This is a collection of traffic generator scripts for both MoonGen and TRex.  Please see the respective README files depending on your needs.

script | description | README
-------|-------------|-------
trafficgen.lua | all-in-one binary-search for maximum throughput using MoonGen | README-trafficgen.md
binary-search.py | only binary-search logic for maximum throughput, executes either txrx.lua or trex-txrx.py for trials.  Can also execute null-txrx.py for search logic testing.  | README-binary-search.md
txrx.lua | produces traffic only (no binary-search logic) using MoonGen  | README-txrx.md
trex-txrx.py | produces traffic only (no binary-search logic) using TRex  | README-trex-txrx.md
trex-txrx-profile.py | produce traffic only (no binary-search logic) using TRex from a supplied JSON profile file | README-trex-txrx-profile.md
trex-query.py | queries TRex for information about the requested ports |
null-txrx.py | a faux traffic producer which is used to test the binary search logic of binary-search.py |
install-trex.sh | Install the TRex server |
launch-trex.sh | Configure and launch the TRex server |
