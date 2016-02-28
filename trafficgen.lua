local dpdk      = require "dpdk"
local memory    = require "memory"
local ts        = require "timestamping"
local device    = require "device"
local filter    = require "filter"
local timer     = require "timer"
local stats     = require "stats"
local hist      = require "histogram"
local log               = require "log"
-- required here because this script creates *a lot* of mempools
-- memory.enableCache()

local REPS = 1
local RUN_TIME = 15
local LATENCY_TRIM = 3000 -- time in ms to delayied start and early end to latency mseasurement, so we are certain main packet load is present
local FRAME_SIZE = 64
local TEST_BIDIREC = false --do not do bidirectional test
local TEST_LATENCY = false --do not get letency measurements
local MAX_FRAME_LOSS_PCT = 0
local LINE_RATE = 10000000000 -- 10Gbps
local RATE_GRANULARITY = 0.1
local TX_HW_RATE_TOLERANCE_MPPS = 0.250  -- The acceptable difference between actual and measured TX rates (in Mpps)
local TX_SW_RATE_TOLERANCE_MPPS = 0.250  -- The acceptable difference between actual and measured TX rates (in Mpps)
local ETH_DST   = "10:11:12:13:14:15" -- src mac is taken from the NIC
local IP_SRC    = "192.168.0.10"
local IP_DST    = "10.0.0.1"
local PORT_SRC  = 1234
local PORT_DST  = 1234
local NR_FLOWS = 256 -- src ip will be IP_SRC + (0..NUM_FLOWS-1)
local TX_QUEUES_PER_DEV = 3
local RX_QUEUES_PER_DEV = 1

function master(...)
	local cfgFileLocations = {
		"./opnfv-vsperf-cfg.lua"
	}
	local cfg
	for _, f in ipairs(cfgFileLocations) do
		if fileExists(f) then
			cfgScript = loadfile(f)
			setfenv(cfgScript, setmetatable({ VSPERF = function(arg) cfg = arg end }, { __index = _G }))
			local ok, err = pcall(cfgScript)
			if not ok then
				log:error("Could not load DPDK config: " .. err)
				return false
			end
			if not cfg then
				log:error("Config file does not contain DPDKConfig statement")
				return false
			end
			cfg.name = f
			break
		end
	end
	if not cfg then
		log:warn("No opnfv-vsperf-cfg.lua config found, using defaults")
		cfg = {}
	end

	local testParams = cfg
	testParams.frameSize = testParams.frameSize or FRAME_SIZE
	local max_line_rate_Mfps = (LINE_RATE /(testParams.frameSize*8 +64 +96) /1000000) --max_line_rate_Mfps is in millions per second
	testParams.rate = testParams.rate or max_line_rate_Mfps
	testParams.txMethod = "hardware"
	testParams.testLatency = TEST_LATENCY
	testParams.runBidirec = testParams.runBidirec or false
	testParams.nrFlows = testParams.nrFlows or NR_FLOWS
	testParams.runTime = testParams.runTime or RUN_TIME
	testParams.acceptableLossPct = testParams.acceptableLossPct or MAX_FRAME_LOSS_PCT
	testParams.rate_granularity = testParams.rate_granularity or RATE_GRANULARITY
	testParams.ports = testParams.ports or {0,1}
	testParams.txQueuesPerDev = testParams.txQueuesPerDev or TX_QUEUES_PER_DEV
	testParams.rxQueuesPerDev = testParams.rxQueuesPerDev or RX_QUEUES_PER_DEV
	if testParams.testLatency then
		testParams.txQueuesPerDev = testParams.txQueuesPerDev + 1
		testParams.rxQueuesPerDev = testParams.rxQueuesPerDev + 1
	end
	local finalValidation = false
	local prevRate = 0
	local prevPassRate = 0
	local prevFailRate = testParams.rate
	local rateAttempts = {0}
	local maxRateAttempts = 2 -- the number of times we will allow MoonGen to get the Tx rate correct
	local runtimeMultipler = 2 -- when the test is the "final validation", the runtime is multipled by this value
	if ( method == "hardware" ) then
		tx_rate_tolerance = TX_HW_RATE_TOLERANCE_MPPS
	else
		tx_rate_tolerance = TX_SW_RATE_TOLERANCE_MPPS
	end

	local txStats = {}
	local rxStats = {}
        local devs = {}
	for i, v in ipairs(testParams.ports) do
		devs[i] = device.config{ port = testParams.ports[i], rxQueues = testParams.rxQueuesPerDev, txQueues = testParams.txQueuesPerDev}
	end
	-- connections define where one device connects to another. 
	connections = {}
	for i, v in ipairs(testParams.ports) do
		if ( i % 2 == 1) then
			log:debug("port %d connects to port %d", i, i+1);
			connections[i] = i + 1  -- device 1 transmits to device 2
			if testParams.runBidirec then
				connections[i + 1] = i  -- device 2 transmits to device 1
			end
		end
	end
	device.waitForLinks()
	printf("Starting binary search for maximum throughput with no more than %.8f%% packet loss", testParams.acceptableLossPct);
	while ( math.abs(testParams.rate - prevRate) > testParams.rate_granularity or finalValidation == true ) do
		launchTest(finalValidation, devs, testParams, txStats, rxStats)
		if true or acceptableRate(tx_rate_tolerance, testParams.rate, txStats, maxRateAttempts, rateAttempts) then
			--rate = dev1_avg_txMpps -- the actual rate may be lower, so correct "rate"
			prevRate = testParams.rate
			if acceptableLoss(rxStats, txStats, testParams.acceptableLossPct) then
				if finalValidation == true then
					return
				else
					nextRate = (prevFailRate + testParams.rate ) / 2
					if math.abs(nextRate - testParams.rate) <= testParams.rate_granularity then
						-- since the rate difference from rate that just passed and the next rate is not greater than rate_granularity, the next run is a "final validation"
						finalValidation = true
					else
						prevPassRate = testParams.rate
						testParams.rate = nextRate
					end
				end
			else
				if finalValidation == true then
					finalValidation = false
					runtimeMultipler = 1
				end
				nextRate = (prevPassRate + testParams.rate ) / 2
				if math.abs(nextRate - testParams.rate) <= testParams.rate_granularity then
					-- since the rate difference from the previous *passing* test rate and next rate is not greater than rate_granularity, the next run is a "final validation"
					finalValidation = true
				end
				prevFailRate = testParams.rate
				testParams.rate = nextRate
			end
			if not dpdk.running() then
				break
			end
		else
			--log:err("Could not achieve Tx rate");
			if rateAttempts[1] > maxRateAttempts then
				return
			end
		end
	end
	printf("Test is complete")
end

function fileExists(f)
	local file = io.open(f, "r")
	if file then
	file:close()
	end
	return not not file
end

function acceptableLoss(rxStats, txStats, acceptableLossPct)
	local pass = true
	for i, v in ipairs(txStats) do
		if connections[i] then
			local lostFrames = txStats[i].totalFrames - rxStats[connections[i]].totalFrames
			local lostFramePct = 100 * lostFrames / txStats[i].totalFrames
			if (lostFramePct > acceptableLossPct) then
				log:warn("Device %d->%d: FAILED - frame loss (%d, %.8f%%) is greater than the maximum (%.8f%%)",
				(i-1), (connections[i]-1), lostFrames, lostFramePct, acceptableLossPct);
				pass = false
			else
				log:info("Device %d->%d PASSED - frame loss (%d, %.8f%%) is less than or equal to the maximum (%.8f%%)",
				(i-1), (connections[i]-1), lostFrames, lostFramePct, acceptableLossPct);
			end
		end
	end
	if pass then
		log:info("Test Result:  PASSED")
	else
		log:warn("Test Result:  FAILED")
	end
	return pass
end
			
function acceptableRate(tx_rate_tolerance, rate, txStats, maxRateAttempts, t)
	t[1] = t[1] + 1
	for i, v in ipairs(txStats) do
		local rateDiff = math.abs(rate - txStats[i].avgMpps)
		if rateDiff > tx_rate_tolerance then
			if t[1] > maxRateAttempts then
				log:error("ABORT TEST:  difference between actual and requested Tx rate (%.2f) is greater than allowed (%.2f)", rateDiff, tx_rate_tolerance)
				do return end
			else
				log:warn("RETRY TEST: difference between actual and requested Tx rate (%.2f) is greater than allowed (%.2f)", rateDiff, tx_rate_tolerance)
				return false
			end
		end
	end
	-- if every txRate was good, reset attempts counter
	t[1] = 0
	return true
end
			
function launchTest(final, devs, testParams, txStats, rxStats)
	local qid
	local idx
	local calTasks = {}
	local calStats = {}
	local rxTasks = {}
	local txTasks = {}
	-- calibrate transmit rate
	local calibratedStartRate = testParams.rate
	for i, v in ipairs(devs) do
		if connections[i] then
			calTasks[i] = dpdk.launchLua("calibrateSlave", devs[i], testParams.txQueuesPerDev,
			testParams.rate, calibratedStartRate, testParams.frameSize, testParams.nrFlows, testParams.txMethod)
			calStats[i] = calTasks[i]:wait()
			calibratedStartRate = calStats[i].calibratedRate
		end
	end
	-- start devices which receive
	for i, v in ipairs(devs) do
		if connections[i] then
			--rxTasks[i] = dpdk.launchLua("counterSlave", devs[i]:getRxQueue(qid), testParams.runTime + 6)
			rxTasks[i] = dpdk.launchLua("counterSlave", devs[connections[i]]:getRxQueue(0), testParams.runTime + 6)
		end
	end
	dpdk.sleepMillis(3000)
	if final == true then
		log:info("Starting final validation");
	end
	-- start devices which transmit
	idx = 1
	for i, v in ipairs(devs) do
		if connections[i] then
			txTasks[i] = dpdk.launchLua("loadSlave", devs[i], testParams.txQueuesPerDev, testParams.rate,
			calStats[idx].calibratedRate, testParams.frameSize, testParams.runTime, testParams.nrFlows, testParams.txMethod)
		end
	end
	-- wait for transmit devices to finish
	for i, v in ipairs(devs) do
		if connections[i] then
			txStats[i] = txTasks[i]:wait()
		end
	end
	if final == true then
		log:info("Stopping final validation");
	end
	dpdk.sleepMillis(3000)
	-- wait for receive devices to finish
	for i, v in ipairs(devs) do
		if connections[i] then
			rxStats[connections[i]] = rxTasks[i]:wait()
		end
	end
end

function calibrateSlave(dev, numQueues, desiredRate, calibratedStartRate, frame_size, num_flows, method)
	log:info("Calibrating %s tx rate for %.2f Mfs",  method , desiredRate)
	local frame_size_without_crc = frame_size - 4
	-- TODO: this leaks memory as mempools cannot be deleted in DPDK
	local mem = memory.createMemPool(function(buf)
		buf:getUdpPacket():fill{
			pktLength = frame_size_without_crc, -- this sets all length headers fields in all used protocols
			ethSrc = txQueue, -- get the src mac from the device
			ethDst = ETH_DST,
			ip4Dst = IP_DST,
			udpSrc = PORT_SRC,
			udpDst = PORT_DST,
		}
	end)
	local bufs = mem:bufArray()
	local baseIP = parseIPAddress(IP_SRC)
	local measuredRate = 0
	local prevMeasuredRate = 0
	local calibrated = false
	local calibrationCount = 0
	local overcorrection = 1
	local calibratedRate
	if desiredRate == calibratedStartRate then
		calibratedRate = desiredRate / numQueues
	else
		calibratedRate = calibratedStartRate / numQueues
	end
	repeat
		local count = 0
		local txStats = stats:newDevTxCounter(dev, "plain")
		if ( method == "hardware" ) then
			for qid = 0, numQueues - 1 do
				dev:getTxQueue(qid):setRateMpps(calibratedRate)
			end
			rate_accuracy = TX_HW_RATE_TOLERANCE_MPPS / 2
			runtime = timer:new(5)
		else
			rate_accuracy = TX_SW_RATE_TOLERANCE_MPPS / 2
			-- s/w rate seems to be less consistent, so test over longer time period
			runtime = timer:new(10)
		end
		while runtime:running() and dpdk.running() do
			bufs:alloc(frame_size_without_crc)
                	for _, buf in ipairs(bufs) do
				local pkt = buf:getUdpPacket()
		        	pkt.ip4.src:set(baseIP + count % num_flows)
			end
                	bufs:offloadUdpChecksums()
			if ( method == "hardware" ) then
				for qid = 0, numQueues - 1 do
					dev:getTxQueue(qid):send(bufs)
				end
			else
				for _, buf in ipairs(bufs) do
					buf:setRate(calibratedRate)
				end
				for qid = 0, numQueues - 1 do
					dev:getTxQueue(qid):sendWithDelay(bufs)
				end
			end
			txStats:update()
			count = count + 1
		end
		txStats:finalize()
		measuredRate = txStats.mpps.avg
		-- the measured rate must be within the tolerance window but also not exceed the desired rate
		if ( measuredRate > desiredRate or (desiredRate - measuredRate) > rate_accuracy ) then
			local correction = (1 - desiredRate/measuredRate)
			if ( calibrationCount > 0 ) then
				overcorrection =  (measuredRate - prevMeasuredRate) / (desiredRate - prevMeasuredRate)
				if ( overcorrection > 1 ) then
					log:info("overcorrection ratio: %.4f", overcorrection)
					correction = correction/overcorrection
				end
			end
			local correction_ratio = 1 / (1 + correction)
			calibratedRate = calibratedRate * correction_ratio
			prevMeasuredRate = measuredRate
                        log:info("measuredRate: %.4f  desiredRate:%.4f  new correction: %.4f  new correction_ratio: %.4f  new calibratedRate: %.4f ",
			measuredRate, desiredRate, correction, correction_ratio, calibratedRate)
		else
			calibrated = true
		end
		calibrationCount = calibrationCount +1
	until ( calibrated  == true )
	log:info("Rate calibration complete") 

        local results = {}
	results.calibratedRate = calibratedRate * numQueues
        return results
end

function counterSlave(rxQueue, run_time)
	local rxStats = stats:newDevRxCounter(rxQueue, "plain")
	local runtime = timer:new(run_time)
	while runtime:running() and dpdk.running() do
		rxStats:update()
	end
        rxStats:finalize()
	local results = {}
        results.totalFrames = rxStats.total
        return results
end

function loadSlave(dev, numQueues, rate, calibratedRate, frame_size, run_time, num_flows, method)
	printf("Testing %.2f Mfps", rate)
	local frame_size_without_crc = frame_size - 4
	-- TODO: this leaks memory as mempools cannot be deleted in DPDK
	local mem = memory.createMemPool(function(buf)
		buf:getUdpPacket():fill{
			pktLength = frame_size_without_crc, -- this sets all length headers fields in all used protocols
			ethSrc = txQueue, -- get the src mac from the device
			ethDst = ETH_DST,
			ip4Dst = IP_DST,
			udpSrc = PORT_SRC,
			udpDst = PORT_DST,
		}
	end)
	local bufs = mem:bufArray()
	local baseIP = parseIPAddress(IP_SRC)
	local runtime = timer:new(run_time)
	local txStats = stats:newDevTxCounter(dev, "plain")
	calibratedRate = calibratedRate / numQueues
	local count = 0
	if ( method == "hardware" ) then
		for qid = 0, numQueues - 1 do
			dev:getTxQueue(qid):setRateMpps(calibratedRate)
		end
	end
	while runtime:running() and dpdk.running() do
		bufs:alloc(frame_size_without_crc)
                for _, buf in ipairs(bufs) do
			local pkt = buf:getUdpPacket()
		        pkt.ip4.src:set(baseIP + count % num_flows)
		end
                bufs:offloadUdpChecksums()
		if ( method == "hardware" ) then
			for qid = 0, numQueues - 1 do
				dev:getTxQueue(qid):send(bufs)
			end
		else
			for _, buf in ipairs(bufs) do
				buf:setRate(calibratedRate)
			end
			for qid = 0, numQueues - 1 do
				dev:getTxQueue(qid):sendWithDelay(bufs)
			end
		end
		txStats:update()
		count = count + 1
	end
	txStats:finalize()
        local results = {}
	results.totalFrames = txStats.total
	results.avgMpps = txStats.mpps.avg
        return results
end

function timerSlave(txQueue, rxQueue, frame_size, run_time, num_flows, bidirec)
	local frame_size_without_crc = frame_size - 4
	local rxDev = rxQueue.dev
	rxDev:filterTimestamps(rxQueue)
	local timestamper = ts:newUdpTimestamper(txQueue, rxQueue)
	local hist = hist()
	-- timestamping starts after and finishes before the main packet load starts/finishes
	dpdk.sleepMillis(LATENCY_TRIM)
	local runtime = timer:new(run_time - LATENCY_TRIM/1000*2)
	local baseIP = parseIPAddress(IP_SRC)
	local rateLimit = timer:new(0.01)
	while runtime:running() and dpdk.running() do
		rateLimit:wait()
		local lat = timestamper:measureLatency();
		if (lat) then
                	hist:update(lat)
		end
		rateLimit:reset()
	end
	dpdk.sleepMillis(LATENCY_TRIM + 1000) -- the extra 1000 ms ensures the stats are output after the throughput stats
	hist:save("hist.csv")
	hist:print("Histogram")
end
