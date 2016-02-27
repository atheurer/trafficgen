local dpdk      = require "dpdk"
local memory    = require "memory"
local ts        = require "timestamping"
local device    = require "device"
local filter    = require "filter"
local timer     = require "timer"
local stats     = require "stats"
local hist      = require "histogram"
-- required here because this script creates *a lot* of mempools
-- memory.enableCache()

local REPS = 1
local runTime = 15
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

function master(...)
	local port1, port2, frameSize, runBidirec, acceptableLossPct, nrFlows, max_line_rate_Mfps = tonumberall(...)

	if not port1 or not port2 then
		printf("\n\n");
		printf("Usage: \n");
		printf("         opnfv-vsperf.lua Port1 Port2 [Frame Size] [Traffic Direction] [Maximum Acceptable Frame Loss] [Number of Flows] [Maximum Frames Per Second]\n\n");
		printf("             where:\n");
		printf("                Port1 ............................ The first DPDK enabled port of interest, e.g. 0\n");
		printf("                Port2 ............................ The second DPDK enabled port of interest, e.g. 1\n");
		printf("                Frame Size ....................... Frame size in bytes.  This is the 'goodput' payload size in bytes.  It does not include");
		printf("                                                   the preamble (7 octets), start of frame delimited (1 octet), and interframe gap (12 octets). ");
		printf("                                                   The default size is 64. \n");
		printf("                uni or bi-directionl test .........0 for unidirectional, 1 for bidirectional.  Default is 0\n");
		printf("                Maximum Acceptable Frame Loss .... Percentage of acceptable packet loss.  Default is 0\n");
		printf("                Number of Flows .................. Number of packet flows.  Default is 256\n");
		printf("                Maximum Frames Per Second ........ The maximum number of frames per second (in Mfps).  For a 10 Gbps connection, this would be 14.88 (also the default)");
		printf("\n\n");
		return
	end

	local testParams = {}
	testParams.rate = max_line_rate_Mfps
	testParams.txMethod = "hardware"
	testParams.testLatency = TEST_LATENCY
	testParams.fameSize = frameSize or FRAME_SIZE
	printf("runBidirec: %d", runBidirec)
	if runBidirec == 1 then
		printf("using bidirec")
		testParams.runBidirec = true
	else
		printf("not using bidirec")
		testParams.runBidirec = false
	end
	testParams.nrFlows = nrFlows or NR_FLOWS
	testParams.frameSize = frameSize or FRAME_SIZE
	testParams.runTime = runTime or RUN_TIME
	acceptableLossPct = acceptableLossPct or MAX_FRAME_LOSS_PCT
	max_line_rate_Mfps = max_line_rate_Mfps or (LINE_RATE /(frame_size*8 +64 +96) /1000000) --max_line_rate_Mfps is in millions per second
	rate_granularity = RATE_GRANULARITY
	-- assumes port1 and port2 are not the same
	local numQueues = 1 
	if testLatency then
		numQueues = numQueues + 1 
	end
	local prevRate = 0
	local prevPassRate = 0
	local prevFailRate = max_line_rate_Mfps
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
	devs[1] = device.config{ port = port1, rxQueues = numQueues, txQueues = numQueues}
	devs[2] = device.config{ port = port2, rxQueues = numQueues, txQueues = numQueues}
	-- connections define where one device connects to another. 
	connections = {}
	connections[1] = 2  -- device 1 transmits to device 2
	if testParams.runBidirec then
		connections[2] = 1  -- device 2 transmits to device 1
	end
	device.waitForLinks()
	printf("Starting binary search for maximum throughput with no more than %.8f%% packet loss", acceptableLossPct);
	while ( math.abs(testParams.rate - prevRate) > rate_granularity or finalValidation == true ) do
		if finalValidation == true then
			printf("Starting final validation");
		end
		launchTest(devs, testParams, txStats, rxStats)
		if finalValidation == true then
			printf("Stopping final validation");
		end
		if acceptableRate(tx_rate_tolerance, testParams.rate, txStats, maxRateAttempts, rateAttempts) then
			--rate = dev1_avg_txMpps -- the actual rate may be lower, so correct "rate"
			prevRate = testParams.rate
			if acceptableLoss(rxStats, txStats, acceptableLossPct)  then
				if finalValidation == true then
					return
				else
					nextRate = (prevFailRate + testParams.rate ) / 2
					if math.abs(nextRate - testParams.rate) <= rate_granularity then
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
				if math.abs(nextRate - testParams.rate) <= rate_granularity then
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
			printf("skipping results eval, rateAttempts: %d", rateAttempts[1]);
			if rateAttempts[1] > maxRateAttempts then
				return
			end
		end
	end
	printf("Test is complete")
end

function acceptableLoss(rxStats, txStats, acceptableLossPct)
	local pass = true
	for i, v in ipairs(txStats) do
		if connections[i] then
			local lostFrames = txStats[i].totalFrames - rxStats[connections[i]].totalFrames
			local lostFramePct = 100 * lostFrames / txStats[i].totalFrames
			if (lostFramePct > acceptableLossPct) then
				printf("Device %d->%d: FAILED - frame loss (%d, %.8f%%) is greater than the maximum (%.8f%%)",
				(i-1), (connections[i]-1), lostFrames, lostFramePct, acceptableLossPct);
				pass = false
			else
				printf("Device %d->%d PASSED - frame loss (%d, %.8f%%) is less than or equal to the maximum (%.8f%%)",
				(i-1), (connections[i]-1), lostFrames, lostFramePct, acceptableLossPct);
			end
		end
	end
	if pass then
		printf("Test Result:  PASSED")
	else
		printf("Test Result:  FAILED")
	end
	return pass
end
			
function acceptableRate(tx_rate_tolerance, rate, txStats, maxRateAttempts, t)
	t[1] = t[1] + 1
	for i, v in ipairs(txStats) do
		if math.abs(rate - txStats[i].avgMpps) > tx_rate_tolerance then
			if t[1] > maxRateAttempts then
				printf("ABORT TEST:  difference between actual and requested Tx rate (%.2f) is greater than allowed (%.2f)",
				rateDiff, tx_rate_tolerance)
				do return end
			else
				printf("RETRY TEST: difference between actual and requested Tx rate (%.2f) is greater than allowed (%.2f)",
				rateDiff, tx_rate_tolerance)
				return false
			end
		end
	end
	-- if every txRate was good, reset attempts counter
	t[1] = 0
	return true
end
			
function launchTest(devs, testParams, txStats, rxStats)
	local qid = 0
	local calTasks = {}
	local calStats = {}
	local rxTasks = {}
	local txTasks = {}
	-- calibrate transmit rate
	for i, v in ipairs(devs) do
		if connections[i] then
			calTasks[i] = dpdk.launchLua("calibrateSlave", devs[i]:getTxQueue(qid),
			testParams.rate, testParams.frameSize, testParams.nrFlows, testParams.txMethod)
			calStats[i] = calTasks[i]:wait()
		end
	end
	-- start devices which receive
	for i, v in ipairs(devs) do
		if connections[i] then
			--rxTasks[i] = dpdk.launchLua("counterSlave", devs[i]:getRxQueue(qid), testParams.runTime + 6)
			rxTasks[i] = dpdk.launchLua("counterSlave", devs[connections[i]]:getRxQueue(qid), testParams.runTime + 6)
		end
	end
	dpdk.sleepMillis(3000)
	-- start devices which transmit
	for i, v in ipairs(devs) do
		if connections[i] then
			txTasks[i] = dpdk.launchLua("loadSlave", devs[i]:getTxQueue(qid),  testParams.rate,
			calStats[i].calibratedRate, testParams.frameSize, testParams.runTime, testParams.nrFlows, testParams.txMethod)
		end
	end
	-- wait for transmit devices to finish
	for i, v in ipairs(devs) do
		if connections[i] then
			txStats[i] = txTasks[i]:wait()
		end
	end
	dpdk.sleepMillis(3000)
	-- wait for receive devices to finish
	for i, v in ipairs(devs) do
		if connections[i] then
			rxStats[connections[i]] = rxTasks[i]:wait()
		end
	end
end

function calibrateSlave(txQueue, desiredRate, frame_size, num_flows, method)
	printf("Calibrating %s tx rate for %.2f Mfs",  method , desiredRate)
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
	local calibratedRate = desiredRate
	local calibrated = false
	local calibrationCount = 0
	local overcorrection = 1
	repeat
		local count = 0
		local txStats = stats:newDevTxCounter(txQueue, "plain")
		if ( method == "hardware" ) then
			txQueue:setRateMpps(calibratedRate)
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
				txQueue:send(bufs)
			else
				for _, buf in ipairs(bufs) do
					buf:setRate(calibratedRate)
				end
				txQueue:sendWithDelay(bufs)
			end
			txStats:update()
			count = count +1
		end
		txStats:finalize()
		measuredRate = txStats.mpps.avg
		-- the measured rate must be within the tolerance window but also not exceed the desired rate
		if ( measuredRate > desiredRate or (desiredRate - measuredRate) > rate_accuracy ) then
			local correction = (1 - desiredRate/measuredRate)
			if ( calibrationCount > 0 ) then
				overcorrection =  (measuredRate - prevMeasuredRate) / (desiredRate - prevMeasuredRate)
				if ( overcorrection > 1 ) then
					printf("overcorrection ratio: %.4f\n", overcorrection)
					correction = correction/overcorrection
				end
			end
			local correction_ratio = 1 / (1 + correction)
			calibratedRate = calibratedRate * correction_ratio
			prevMeasuredRate = measuredRate
                        printf("measuredRate: %.4f  desiredRate:%.4f  new correction: %.4f  new correction_ratio: %.4f  new calibratedRate: %.4f ",
			measuredRate, desiredRate, correction, correction_ratio, calibratedRate)
		else
			calibrated = true
		end
		calibrationCount = calibrationCount +1
	until ( calibrated  == true )
	printf("Rate calibration complete\n") 

        local results = {}
	results.calibratedRate = calibratedRate
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

function loadSlave(txQueue, rate, calibratedRate, frame_size, run_time, num_flows, method)
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
	local txStats = stats:newDevTxCounter(txQueue, "plain")
	local count = 0
	if ( method == "hardware" ) then
		txQueue:setRateMpps(calibratedRate)
	end
	while runtime:running() and dpdk.running() do
		bufs:alloc(frame_size_without_crc)
                for _, buf in ipairs(bufs) do
			local pkt = buf:getUdpPacket()
		        pkt.ip4.src:set(baseIP + count % num_flows)
		end
                bufs:offloadUdpChecksums()
		if ( method == "hardware" ) then
			txQueue:send(bufs)
		else
			for _, buf in ipairs(bufs) do
				buf:setRate(calibratedRate)
			end
			txQueue:sendWithDelay(bufs)
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
