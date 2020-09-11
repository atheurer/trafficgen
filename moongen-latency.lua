local mg     = require "moongen"
local memory = require "memory"
local device = require "device"
local ts     = require "timestamping"
local stats  = require "stats"
local hist   = require "histogram"
local timer  = require "timer"
local log    = require "log"

package.cpath = "/opt/trafficgen/lua-luaipc/?.so;"..package.cpath
local sem    = require "ipc.sem"

local FWD_ETH_DST = "24:6E:96:19:DE:DA"
local REV_ETH_DST = "24:6E:96:19:DE:D8"

function binary_search_log(msg)
	io.stderr:write("[BS] "..msg.."\n")
end

function dual_log(args, msg)
	if args.binarysearch == 1 then
		io.stderr:write("[BS] "..msg.."\n")
	end

	io.stdout:write(msg.."\n")
end

function configure(parser)
	parser:description("Generates bidirectional CBR traffic with hardware rate control and measure latencies.")
	parser:option("--fwddev", "Forward device."):convert(tonumber):default(0)
	parser:option("--revdev", "Reverse device."):convert(tonumber):default(1)
	parser:option("--fwdfile", "Filename of the forward latency histogram."):default("fwd-histogram.csv")
	parser:option("--revfile", "Filename of the reverse latency histogram."):default("rev-histogram.csv")
	parser:option("-t --time", "Number of seconds to run"):default(30):convert(tonumber)
	parser:option("-o --output", "Directory to write results to."):default("./")
	parser:option("--binarysearch", "binary-search.py is invoking this script so handle output accordingly."):convert(tonumber):default(0)
end

function master(args)
	if args.binarysearch == 1 then
		binary_search_log("Invoked by binary-search.py")
	end

	local dev1 = device.config({port = args.fwddev, rxQueues = 1, txQueues = 1})
	local dev2 = device.config({port = args.revdev, rxQueues = 1, txQueues = 1})

	device.waitForLinks()
	if args.binarysearch == 1 then
		binary_search_log("Devices online")

		parent_launch_sem = sem.open("trafficgen_child_launch")
		parent_go_sem = sem.open("trafficgen_child_go")

		binary_search_log("Signaling binary-search.py that I am ready")
		parent_launch_sem:inc()

		binary_search_log("Waiting for binary-search.py to tell me to go")
		parent_go_sem:dec()
		binary_search_log("Received go from binary-search.py")

		parent_launch_sem:close()
		parent_go_sem:close()

		binary_search_log("Synchronization services complete")
	end

	stats.startStatsTask({ devices = { dev1, dev2 } })
	mg.startTask("timerSlave", dev1, dev2, args)

	if args.binarysearch == 1 then
		binary_search_log("Running")
	end

	mg.waitForTasks()

	if args.binarysearch == 1 then
		binary_search_log("Finished")
	end
end

function dump_histogram(args, direction, dev1, dev2, histogram, tx_samples)
	rx_samples, sum, avg = histogram:totals()
	dual_log(args, string.format("[%s Latency: %d->%d] TX Samples:            %d", direction, dev1, dev2, tx_samples))
	dual_log(args, string.format("[%s Latency: %d->%d] RX Samples:            %d", direction, dev1, dev2, rx_samples))
	dual_log(args, string.format("[%s Latency: %d->%d] Average:               %f", direction, dev1, dev2, avg))
	dual_log(args, string.format("[%s Latency: %d->%d] Median:                %f", direction, dev1, dev2, histogram:median()))
	dual_log(args, string.format("[%s Latency: %d->%d] Minimum:               %f", direction, dev1, dev2, histogram:min()))
	dual_log(args, string.format("[%s Latency: %d->%d] Maximum:               %f", direction, dev1, dev2, histogram:max()))
	dual_log(args, string.format("[%s Latency: %d->%d] Std. Dev:              %f", direction, dev1, dev2, histogram:standardDeviation()))
	dual_log(args, string.format("[%s Latency: %d->%d] 95th Percentile:       %f", direction, dev1, dev2, histogram:percentile(95) or 0.0))
	dual_log(args, string.format("[%s Latency: %d->%d] 99th Percentile:       %f", direction, dev1, dev2, histogram:percentile(99) or 0.0))
	dual_log(args, string.format("[%s Latency: %d->%d] 99.9th Percentile:     %f", direction, dev1, dev2, histogram:percentile(99.9) or 0.0))
	dual_log(args, string.format("[%s Latency: %d->%d] 99.99th Percentile:    %f", direction, dev1, dev2, histogram:percentile(99.99) or 0.0))
	dual_log(args, string.format("[%s Latency: %d->%d] 99.999th Percentile:   %f", direction, dev1, dev2, histogram:percentile(99.999) or 0.0))
	dual_log(args, string.format("[%s Latency: %d->%d] 99.9999th Percentile:  %f", direction, dev1, dev2, histogram:percentile(99.9999) or 0.0))
end

function timerSlave(dev1, dev2, args)
	local fwd_timestamper = ts:newTimestamper(dev1:getTxQueue(0), dev2:getRxQueue(0))
	local fwd_hist = hist:new()
	local fwd_samples = 0

	local rev_timestamper = ts:newTimestamper(dev2:getTxQueue(0), dev1:getRxQueue(0))
	local rev_hist = hist:new()
	local rev_samples = 0

	if args.time > 0 then
		ts_runtimer = timer:new(args.time)
	end

	mode = 0
	while (args.time == 0 or ts_runtimer:running()) and mg.running() do
		if mode == 0 then
			fwd_hist:update(fwd_timestamper:measureLatency(function(buf) buf:getEthernetPacket().eth.dst:setString(FWD_ETH_DST) end))
			mode = 1
			fwd_samples = fwd_samples + 1
		else
			rev_hist:update(rev_timestamper:measureLatency(function(buf) buf:getEthernetPacket().eth.dst:setString(REV_ETH_DST) end))
			mode = 0
			rev_samples = rev_samples + 1
		end
	end

	mg.stop()

	mg.sleepMillis(2000)

	dump_histogram(args, "Forward", args.fwddev, args.revdev, fwd_hist, fwd_samples)
	dump_histogram(args, "Reverse", args.revdev, args.fwddev, rev_hist, rev_samples)

	fwd_hist:save(args.output.."/"..args.fwdfile)
	rev_hist:save(args.output.."/"..args.revfile)
end

