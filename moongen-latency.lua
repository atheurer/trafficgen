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

function configure(parser)
	parser:description("Generates bidirectional CBR traffic with hardware rate control and measure latencies.")
	parser:argument("dev1", "Device to transmit from."):convert(tonumber)
	parser:argument("dev2", "Device to receive to."):convert(tonumber)
	parser:option("-f --file", "Filename of the latency histogram."):default("histogram.csv")
	parser:option("-t --time", "Number of seconds to run"):default(30):convert(tonumber)
end

function master(args)
	local dev1 = device.config({port = args.dev1, rxQueues = 1, txQueues = 1})
	local dev2 = device.config({port = args.dev2, rxQueues = 1, txQueues = 1})
	device.waitForLinks()
	stats.startStatsTask{dev1, dev2}
	mg.startTask("timerSlave", dev1, dev2, args)
	mg.waitForTasks()
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

	log:info("Forward Latency: %d->%d", args.dev1, args.dev2)
	fwd_hist:print()
	fwd_hist:save("fwd-"..args.file)

	log:info("Reverse Latency: %d->%d", args.dev2, args.dev1)
	rev_hist:print()
	rev_hist:save("rev-"..args.file)
end

