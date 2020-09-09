local mg     = require "moongen"
local memory = require "memory"
local device = require "device"
local ts     = require "timestamping"
local stats  = require "stats"
local hist   = require "histogram"
local timer  = require "timer"
local log    = require "log"

local FWD_ETH_DST = "24:6E:96:19:DE:DA"
local REV_ETH_DST = "24:6E:96:19:DE:D8"

function binary_search_log(msg)
	io.stderr:write("[BS] "..msg.."\n")
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

function timerSlave(dev1, dev2, args)
	local fwd_timestamper = ts:newTimestamper(dev1:getTxQueue(0), dev2:getRxQueue(0))
	local fwd_hist = hist:new()

	local rev_timestamper = ts:newTimestamper(dev2:getTxQueue(0), dev1:getRxQueue(0))
	local rev_hist = hist:new()

	if args.time > 0 then
		ts_runtimer = timer:new(args.time)
	end

	mode = 0
	while (args.time == 0 or ts_runtimer:running()) and mg.running() do
		if mode == 0 then
			fwd_hist:update(fwd_timestamper:measureLatency(function(buf) buf:getEthernetPacket().eth.dst:setString(FWD_ETH_DST) end))
			mode = 1
		else
			rev_hist:update(rev_timestamper:measureLatency(function(buf) buf:getEthernetPacket().eth.dst:setString(REV_ETH_DST) end))
			mode = 0
		end
	end

	mg.stop()

	mg.sleepMillis(2000)

	log:info("Forward Latency: %d->%d", args.fwddev, args.revdev)
	fwd_hist:print()
	fwd_hist:save(args.output.."/"..args.fwdfile)

	log:info("Reverse Latency: %d->%d", args.revdev, args.fwddev)
	rev_hist:print()
	rev_hist:save(args.output.."/"..args.revfile)
end

