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

function dual_log(args, msg)
	if args.binarysearch == 1 then
		io.stderr:write("[BS] "..msg.."\n")
	end

	log:info(msg)
end

function get_ts()
	return os.date('%H:%M:%S on %Y-%m-%d')
end

function configure(parser)
	parser:description("Measure round trip latency using HW PTP timestamps.")
	parser:option("--fwddev", "Forward device."):convert(tonumber):default(0)
	parser:option("--revdev", "Reverse device."):convert(tonumber):default(1)
	parser:option("--fwdfile", "Filename of the forward latency histogram."):default("fwd-histogram.csv")
	parser:option("--revfile", "Filename of the reverse latency histogram."):default("rev-histogram.csv")
	parser:option("--time", "Number of seconds to run"):default(30):convert(tonumber)
	parser:option("--output", "Directory to write results to."):default("./")
	parser:option("--binarysearch", "binary-search.py is invoking this script so handle output accordingly."):convert(tonumber):default(0)
	parser:option("--traffic-direction", "Control traffic direction.  One of: bi, uni, revuni"):default("bi"):target("traffic_direction")
	parser:option("--warmup-packets", "How many packets to send from each device to warmup the environment when being invoked from binary-search.py."):default(10):target("warmup_packets"):convert(tonumber)
	parser:option("--max-latency", "How long to wait for a packet before declaring it lost (in milliseconds)."):default(5):target("max_latency"):convert(tonumber)
	parser:option("--packet-size", "How big should the packet be."):default(76):target("packet_size"):convert(tonumber)
end

function validate_traffic_direction(direction)
	if     direction == "bi"     then return 0
	elseif direction == "uni"    then return 0
	elseif direction == "revuni" then return 0
	else                              return 1
	end
end

function master(args)
	if args.binarysearch == 1 then
		dual_log(args, "Invoked by binary-search.py")
	end

	if validate_traffic_direction(args.traffic_direction) == 1 then
		dual_log(args, string.format("Invalid traffic direction = %s", args.traffic_direction))
		return ""
	else
		dual_log(args, string.format("Generating %sdirectional latency traffic", args.traffic_direction))
	end

	local dev1 = device.config({port = args.fwddev, rxQueues = 1, txQueues = 1})
	local dev2 = device.config({port = args.revdev, rxQueues = 1, txQueues = 1})

	local devices_online = device.waitForLinks()
	dual_log(args, string.format("Devices online: %d", devices_online))
	if devices_online ~= 2 then
		dual_log(args, "Failed to online 2 devices")
		return ""
	end

	mg.sleepMillis(2000)

	if args.binarysearch == 1 then
		if args.warmup_packets > 0 then
			dual_log(args, string.format("Warming up with %d packets per active direction at %s", args.warmup_packets, get_ts()))
			mg.startTask("warmup", dev1, dev2, args)
			mg.waitForTasks()
			dual_log(args, string.format("Warmup complete at %s", get_ts()))
		else
			dual_log(args, "Skipping warmup")
		end

		parent_launch_sem = sem.open("trafficgen_child_launch")
		parent_go_sem = sem.open("trafficgen_child_go")

		dual_log(args, string.format("Signaling binary-search.py that I am ready at %s", get_ts()))
		parent_launch_sem:inc()

		dual_log(args, string.format("Waiting for binary-search.py to tell me to go at %s", get_ts()))
		parent_go_sem:dec()
		dual_log(args, string.format("Received go from binary-search.py at %s", get_ts()))

		parent_launch_sem:close()
		parent_go_sem:close()

		dual_log(args, string.format("Synchronization services complete at %s", get_ts()))
	else
		dual_log(args, "Regular run")
	end

	dual_log(args, string.format("Starting at %s", get_ts()))

	stats.startStatsTask({ devices = { dev1, dev2 } })
	mg.startTask("timerSlave", dev1, dev2, args)

	dual_log(args, string.format("Running at %s", get_ts()))

	mg.waitForTasks()

	dual_log(args, string.format("Finished at %s", get_ts()))
end

function dump_histogram(args, direction, dev1, dev2, histogram, tx_samples)
	rx_samples, sum, avg = histogram:totals()
	dual_log(args, string.format("[%s Latency: %d->%d] TX Samples:            %d", direction, dev1, dev2, tx_samples))
	dual_log(args, string.format("[%s Latency: %d->%d] RX Samples:            %d", direction, dev1, dev2, rx_samples))
	dual_log(args, string.format("[%s Latency: %d->%d] Loss Ratio:            %f", direction, dev1, dev2, (1-(rx_samples/tx_samples))*100.0))
	dual_log(args, string.format("[%s Latency: %d->%d] Average:               %f", direction, dev1, dev2, avg or 0.0))
	dual_log(args, string.format("[%s Latency: %d->%d] Median:                %f", direction, dev1, dev2, histogram:median() or 0.0))
	dual_log(args, string.format("[%s Latency: %d->%d] Minimum:               %f", direction, dev1, dev2, histogram:min() or 0.0))
	dual_log(args, string.format("[%s Latency: %d->%d] Maximum:               %f", direction, dev1, dev2, histogram:max() or 0.0))
	dual_log(args, string.format("[%s Latency: %d->%d] Std. Dev:              %f", direction, dev1, dev2, histogram:standardDeviation() or 0.0))
	dual_log(args, string.format("[%s Latency: %d->%d] 95th Percentile:       %f", direction, dev1, dev2, histogram:percentile(95) or 0.0))
	dual_log(args, string.format("[%s Latency: %d->%d] 99th Percentile:       %f", direction, dev1, dev2, histogram:percentile(99) or 0.0))
	dual_log(args, string.format("[%s Latency: %d->%d] 99.9th Percentile:     %f", direction, dev1, dev2, histogram:percentile(99.9) or 0.0))
	dual_log(args, string.format("[%s Latency: %d->%d] 99.99th Percentile:    %f", direction, dev1, dev2, histogram:percentile(99.99) or 0.0))
	dual_log(args, string.format("[%s Latency: %d->%d] 99.999th Percentile:   %f", direction, dev1, dev2, histogram:percentile(99.999) or 0.0))
	dual_log(args, string.format("[%s Latency: %d->%d] 99.9999th Percentile:  %f", direction, dev1, dev2, histogram:percentile(99.9999) or 0.0))
end

function update_fwd_packet(buf)
	buf:getEthernetPacket().eth.dst:setString(FWD_ETH_DST)
end

function update_rev_packet(buf)
	buf:getEthernetPacket().eth.dst:setString(REV_ETH_DST)
end

function timerSlave(dev1, dev2, args)
	local fwd_timestamper = ts:newUdpTimestamper(dev1:getTxQueue(0), dev2:getRxQueue(0))
	local fwd_hist = hist:new()
	local fwd_samples = 0

	local rev_timestamper = ts:newUdpTimestamper(dev2:getTxQueue(0), dev1:getRxQueue(0))
	local rev_hist = hist:new()
	local rev_samples = 0

	if args.time > 0 then
		ts_runtimer = timer:new(args.time)
	end

	local mode = 0
	if args.traffic_direction == "revuni" then
		mode = 1
	end

	local latency = nil
	local num_packets = nil
	while (args.time == 0 or ts_runtimer:running()) and mg.running() do
		if mode == 0 then
			if args.traffic_direction == "bi" then
				mode = 1
			end

			fwd_samples = fwd_samples + 1

			latency, num_packets = fwd_timestamper:measureLatency(args.packet_size, update_fwd_packet, args.max_latency)

			if latency == nil then
				log:warn("%s | Lost Packet | Fwd Sample #: %d | Num Packets: %d", get_ts(), fwd_samples, num_packets)
			elseif latency == -1 then
				log:warn("%s | Ignoring Packet | Fwd Sample #: %d | Num Packets: %d", get_ts(), fwd_samples, num_packets)
				fwd_samples = fwd_samples - 1
				mode = 0
			else
				if num_packets > 1 then
					log:warn("%s | Multi-packet RX | Fwd Sample #: %d | Num Packets: %d | Latency: %f", get_ts(), fwd_samples, num_packets, latency)
				end

				fwd_hist:update(latency)
			end
		else
			if args.traffic_direction == "bi" then
				mode = 0
			end

			rev_samples = rev_samples + 1

			latency, num_packets = rev_timestamper:measureLatency(args.packet_size, update_rev_packet, args.max_latency)

			if latency == nil then
				log:warn("%s | Lost Packet | Rev Sample #: %d | Num Packets: %d", get_ts(), rev_samples, num_packets)
			elseif latency == -1 then
				log:warn("%s | Ignoring Packet | Rev Sample #: %d | Num Packets: %d", get_ts(), rev_samples, num_packets)
				rev_samples = rev_samples - 1
				mode = 1
			else
				if num_packets > 1 then
					log:warn("%s | Multi-packet RX | Rev Sample #: %d | Num Packets: %d | Latency: %f", get_ts(), rev_samples, num_packets, latency)
				end

				rev_hist:update(latency)
			end
		end
	end

	mg.stop()

	dual_log(args, string.format("Stopped at %s", get_ts()))

	-- let MG settle before dumping results
	mg.sleepMillis(2000)

	if args.traffic_direction == "bi" or args.traffic_direction == "uni" then
		dump_histogram(args, "Forward", args.fwddev, args.revdev, fwd_hist, fwd_samples)
		fwd_hist:save(args.output.."/"..args.fwdfile)
	end

	if args.traffic_direction == "bi" or args.traffic_direction == "revuni" then
		dump_histogram(args, "Reverse", args.revdev, args.fwddev, rev_hist, rev_samples)
		rev_hist:save(args.output.."/"..args.revfile)
	end
end

function warmup(dev1, dev2, args)
	local fwd_timestamper = ts:newUdpTimestamper(dev1:getTxQueue(0), dev2:getRxQueue(0))
	local fwd_samples = 0

	local rev_timestamper = ts:newUdpTimestamper(dev2:getTxQueue(0), dev1:getRxQueue(0))
	local rev_samples = 0

	local mode = 0
	if args.traffic_direction == "revuni" then
		mode = 1
	end

	local do_warmup = 1
	while do_warmup == 1 do
		if mode == 0 then
			fwd_samples = fwd_samples + 1

			fwd_timestamper:measureLatency(args.packet_size, update_fwd_packet, args.max_latency)

			if args.traffic_direction == "bi" then
				mode = 1
			end
		else
			rev_samples = rev_samples + 1

			rev_timestamper:measureLatency(args.packet_size, update_rev_packet, args.max_latency)

			if args.traffic_direction == "bi" then
				mode = 0
			end
		end

		if fwd_samples == args.warmup_packets and rev_samples == args.warmup_packets then
			do_warmup = 0
		end
	end

	mg.sleepMillis(2000)
end
