# lua-trafficgen
This is a collection of traffic generator scripts for both MoonGen and TRex.  Please see the respective README files depedning on your needs

script | description | README
-------|-------------|-------
trafficgen.lua | all-in-one binary-search for maximum throughput using MoonGen | README-trafficgen.md
binary-search.py | only binary-search logic for maximum throughput, executes either txrx.lua or trex-txrx.py for trials | README-binary-search.md
txrx.lua | produces traffic only (no binary-search logic) using MoonGen  | README-txrx.md
trex-txrx.lua | produces traffic only (no binary-search logic) using TRex  | README-trex-txrx.md
