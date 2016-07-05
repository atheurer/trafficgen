-- This program provides a RFC2544-like testing of network devices, using
-- libaries from the MoonGen packet generator and DPDK.  This program
-- is typically from within a MoonGen source tree, for example:
--
-- cd MoonGen
-- build/MoonGen examples/opnfv-vsperf.lua
--
-- The test will run a binary search to find the maximum packet rate while
-- not exceeding a defined percentage packet loss.
--
-- The test parameters can be adjusted by created a file, opnfv-vsperf-cfg.lua
-- in the current working directory.  The file is lua syntax and describes the
-- test paramters.  For example:
--
-- VSPERF {
--	rate = 5,
--	runBidirec = true,
--	ports = {0,1,2,3}
-- }
--
-- paramters that may be used:
-- testType		Either "throughput" or "latency"
-- ports        	A list of DPDK ports to use, for example {0,1}.  Minimum is 1 pair, and more than 1 pair can be used.
-- 			It is assumed that for each pair, packets transmitted out the first port will arrive on the second port (and the reverse)
-- startRate         	Float: The packet rate in millions/sec to start testing (default is 14.88).
-- runBidirec   	true or false: If true all ports transmit packets (and receive).  If false, only every other port transmits packets.
-- txMethod     	"hardware" or "software": The method to transmit packets (hardware recommended when adapter support is available).
-- nrFlows      	Integer: The number of unique network flows to generate.
-- latencyRunTime 	Integer: The number of seconds to run when doing a latency test.
-- searchRunTime 	Integer: The number of seconds to run when doing binary search for a throughput test.
-- validationRunTime 	Integer: The number of seconds to run when doing final validation for a throughput test.
-- acceptableLossPct	Float: The maximum percentage of packet loss allowed to consider a test as passing.
-- rate_granularity	testParams.rate_granularity or RATE_GRANULARITY
-- txQueuesPerDev	Integer: The number of queues to use when transmitting packets.  The default is 3 and should not need to be changed
-- frameSize		Integer: the size of the Ethernet frame (including CRC)
-- oneShot		true or false: set to true only if you don't want a binary search for maximum packet rate

local dpdk	= require "dpdk"
local memory	= require "memory"
local ts	= require "timestamping"
local device	= require "device"
local filter	= require "filter"
local timer	= require "timer"
local stats	= require "stats"
local hist	= require "histogram"
local log	= require "log"
-- required here because this script creates *a lot* of mempools
-- memory.enableCache()

local REPS = 1
local VALIDATION_RUN_TIME = 30
local LATENCY_RUN_TIME = 1800
local SEARCH_RUN_TIME = 60
local LATENCY_TRIM = 3000 -- time in ms to delayied start and early end to latency mseasurement, so we are certain main packet load is present
local FRAME_SIZE = 64
local TEST_TYPE = "throughput" -- "throughput" is for finding max packets/sec while not exceeding MAX_FRAME_LOSS_PCT
			       -- "latency" is for measuring round-trip packet latency while handling testParams.startRate packets/sec
			       -- "throughput-latency" will run a throughput test but also measure latency in the final validation
local TEST_BIDIREC = false --do not do bidirectional test
local MAX_FRAME_LOSS_PCT = 0
local LINK_SPEED = 40000000000 -- 40Gbps
local RATE_GRANULARITY = 0.1
local TX_HW_RATE_TOLERANCE_MPPS = 0.250  -- The acceptable difference between actual and measured TX rates (in Mpps)
local TX_SW_RATE_TOLERANCE_MPPS = 0.250  -- The acceptable difference between actual and measured TX rates (in Mpps)
local SRC_MAC   = "20:11:12:13:14:15" -- src mac is taken from the NIC
local DST_MAC   = "10:11:12:13:14:15" -- src mac is taken from the NIC
local SRC_IP    = "10.0.0.1"
local DST_IP    = "192.168.0.10"
local SRC_PORT  = 1234
local DST_PORT  = 1234
local NR_FLOWS = 256
local TX_QUEUES_PER_DEV = 3
local RX_QUEUES_PER_DEV = 1
local MAX_CALIBRATION_ATTEMPTS = 20
local VLAN_ID = 0
local MPPS_PER_QUEUE = 4 

function macToU48(mac)
	-- this is similar to parseMac, but maintains ordering as represented in the input string
	local bytes = {string.match(mac, '(%x+)[-:](%x+)[-:](%x+)[-:](%x+)[-:](%x+)[-:](%x+)')}
	if bytes == nil then
	return
	end
	for i = 1, 6 do
	if bytes[i] == nil then
			return
		end
		bytes[i] = tonumber(bytes[i], 16)
		if  bytes[i] < 0 or bytes[i] > 0xFF then
			return
		end
	end

	local acc = 0
	for i = 1, 6 do
		acc = acc + bytes[i] * 256 ^ (6 - i)
	end
	return acc
end

function master(...)
	local testParams = getTestParams()
	local finalValidation = false
	local prevRate = 0
	local prevPassRate = 0
	local rateAttempts = {0}
	local maxRateAttempts = 2 -- the number of times we will allow MoonGen to get the Tx rate correct
	if ( method == "hardware" ) then
		tx_rate_tolerance = TX_HW_RATE_TOLERANCE_MPPS
	else
		tx_rate_tolerance = TX_SW_RATE_TOLERANCE_MPPS
	end
	local txStats = {}
	local rxStats = {}
        local devs = {}
	testParams.startRate = testParams.startRate or getLineRateMpps(devs, testParams)
	testParams.rate = getMaxRateMpps(devs, testParams, testParams.startRate)
	if testParams.rate < testParams.startRate then
		log:warn("Start rate has been reduced from %.2f to %.2f because the original start rate could not be achieved.", testParams.startRate, testParams.rate)
	end
	local prevFailRate = testParams.rate

	if testParams.testType == "latency" then 
		printf("Starting latency test", testParams.acceptableLossPct);
		if launchTest(finalValidation, devs, testParams, txStats, rxStats) then
			showReport(rxStats, txStats, testParams)
		else
			log:error("Test failed");
			return
		end
	else
		if testParams.testType == "throughput" or testParams.testType == "throughput-latency" then
			if testParams.oneShot then
				printf("Running single throughput test");
				finalValidation = true
			else
				printf("Starting binary search for maximum throughput with no more than %.8f%% packet loss", testParams.acceptableLossPct);
			end
			while ( math.abs(testParams.rate - prevRate) >= testParams.rate_granularity or finalValidation ) do
				if launchTest(finalValidation, devs, testParams, txStats, rxStats) then
					if not acceptableLoss(testParams, rxStats, txStats) or acceptableRate(tx_rate_tolerance, testParams.rate, txStats, maxRateAttempts, rateAttempts) then
						prevRate = testParams.rate
						if testParams.oneShot or acceptableLoss(testParams, rxStats, txStats) then
							if finalValidation then
								showReport(rxStats, txStats, testParams)
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
							if testParams.rate <= testParams.rate_granularity then
								log:error("Could not even pass with rate <= the rate granularity, %f", testParams.rate_granularity)
								return
							end
							if finalValidation then
								finalValidation = false
								nextRate = testParams.rate - testParams.rate_granularity
							else
								nextRate = (prevPassRate + testParams.rate ) / 2
							end
							if math.abs(nextRate - testParams.rate) < testParams.rate_granularity then
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
						if rateAttempts[1] > maxRateAttempts then
							return
						end
					end
				else
					log:error("Test failed");
					return
				end
			end
		end
	end
end

function showReport(rxStats, txStats, testParams)
	local totalRxMpps = 0
	local totalTxMpps = 0
	local totalRxFrames = 0
	local totalTxFrames = 0
	local totalLostFrames = 0
	local totalLostFramePct = 0
	local portList = ""
	local count = 0
	for i, v in ipairs(testParams.ports) do
		if count == 0 then
			portList = portList..i
		else
			portList = portList..","..i
		end
		count = count + 1
	end
	if testParams.testType == "throughput" then
		printf("[PARAMETERS] startRate: %f nrFlows: %d frameSize: %d runBidirec: %s searchRunTime: %d validationRunTime: %d acceptableLossPct: %f ports: %s",
			testParams.startRate, testParams.nrFlows, testParams.frameSize, testParams.runBidirec, testParams.searchRunTime, testParams.validationRunTime, testParams.acceptableLossPct, portList) 
	end
	if testParams.testType == "latency" then
		printf("[PARAMETERS] startRate: %f nrFlows: %d frameSize: %d runBidirec: %s latencyRunTime: %d ports: %s",
			testParams.startRate, testParams.nrFlows, testParams.frameSize, testParams.runBidirec, testParams.latencyRunTime, portList) 
	end
	if testParams.testType == "throughput-latency" then
		printf("[PARAMETERS] startRate: %f nrFlows: %d frameSize: %d runBidirec: %s latencyRunTime: %d searchRunTime: %d validationRunTime: %d acceptableLossPct: %f ports: %s",
			testParams.startRate, testParams.nrFlows, testParams.frameSize, testParams.runBidirec, testParams.latencyRunTime, testParams.searchRunTime, testParams.validationRunTime, testParams.acceptableLossPct, portList) 
	end
	for i, v in ipairs(txStats) do
		if testParams.connections[i] then
			local lostFrames = txStats[i].totalFrames - rxStats[testParams.connections[i]].totalFrames
			local lostFramePct = 100 * lostFrames / txStats[i].totalFrames
			local rxMpps = txStats[i].avgMpps * (100 - lostFramePct) / 100
			totalRxMpps = totalRxMpps + rxMpps
			totalTxMpps = totalTxMpps + txStats[i].avgMpps
			totalRxFrames = totalRxFrames + rxStats[testParams.connections[i]].totalFrames
			totalTxFrames = totalTxFrames + txStats[i].totalFrames
			totalLostFrames = totalLostFrames + lostFrames
			totalLostFramePct = 100 * totalLostFrames / totalTxFrames
			printf("[REPORT]Device %d->%d: Tx frames: %d Rx Frames: %d frame loss: %d, %f%% Rx Mpps: %f",
			 testParams.ports[i], testParams.ports[testParams.connections[i]], txStats[i].totalFrames,
			 rxStats[testParams.connections[i]].totalFrames, lostFrames, lostFramePct, rxMpps)
		end
	end
	printf("[REPORT]      total: Tx frames: %d Rx Frames: %d frame loss: %d, %f%% Tx Mpps: %f Rx Mpps: %f",
	 totalTxFrames, totalRxFrames, totalLostFrames, totalLostFramePct, totalTxMpps, totalRxMpps)
end

function prepareDevs(testParams)
	local devs = {}
	local rxQueues = testParams.rxQueuesPerDev
	local txQueues = testParams.txQueuesPerDev
	if testParams.testType == "latency" or testParams.testType == "throughput-latency" then
		log:info("increasing queue count to accomodate latency testing"); 
		rxQueues = rxQueues + 1
		txQueues = txQueues + 1
	end
	log:info("number of rx queues: %d", rxQueues);
	log:info("number of tx queues: %d", txQueues);
	for i, v in ipairs(testParams.ports) do
		devs[i] = device.config{ port = testParams.ports[i],
				 	rxQueues = rxQueues,
				 	txQueues = txQueues}
	end
	-- connections define where one device connects to another 
	-- currently this follows a pattter of 1->2, 3->4, and so on
	-- if bidirectional traffic is enabled, the reverse is also true
	testParams.connections = {}
	for i, v in ipairs(testParams.ports) do
		if ( i % 2 == 1) then
			testParams.connections[i] = i + 1  -- device 1 transmits to device 2
			log:info("port %d transmits to port %d", testParams.ports[i], testParams.ports[testParams.connections[i]]);
			if testParams.runBidirec then
				testParams.connections[i + 1] = i  -- device 2 transmits to device 1
				log:info("port %d transmits to port %d", testParams.ports[testParams.connections[i]], testParams.ports[i]);
			end
		end
	end
	device.waitForLinks()
	return devs
end

function getTestParams(testParams)
	filename = "opnfv-vsperf-cfg.lua"
	local cfg
	if fileExists(filename) then
		log:info("reading [%s]", filename)
		cfgScript = loadfile(filename)
		setfenv(cfgScript, setmetatable({ VSPERF = function(arg) cfg = arg end }, { __index = _G }))
		local ok, err = pcall(cfgScript)
		if not ok then
			log:error("Could not load DPDK config: " .. err)
			return false
		end
		if not cfg then
			log:error("Config file does not contain VSPERF statement")
			return false
		end
	else
		log:warn("No %s file found, using defaults", filename)
	end

	local testParams = cfg or {}
	testParams.frameSize = testParams.frameSize or FRAME_SIZE
	testParams.testType = testParams.testType or TEST_TYPE
	testParams.startRate = testParams.startRate
	testParams.txMethod = "hardware"
	testParams.runBidirec = testParams.runBidirec or false
	testParams.nrFlows = testParams.nrFlows or NR_FLOWS
	testParams.latencyRunTime = testParams.latencyRunTime or LATENCY_RUN_TIME
	testParams.searchRunTime = testParams.searchRunTime or SEARCH_RUN_TIME
	testParams.validationRunTime = testParams.validationRunTime or VALIDATION_RUN_TIME
	testParams.acceptableLossPct = testParams.acceptableLossPct or MAX_FRAME_LOSS_PCT
	testParams.rate_granularity = testParams.rate_granularity or RATE_GRANULARITY
	testParams.ports = testParams.ports or {0,1}
	testParams.flowMods = testParams.flowMods or {"srcIp"}
	testParams.txQueuesPerDev = testParams.txQueuesPerDev or TX_QUEUES_PER_DEV
	testParams.rxQueuesPerDev = testParams.rxQueuesPerDev or RX_QUEUES_PER_DEV
	testParams.srcIp = testParams.srcIp or SRC_IP
	testParams.dstIp = testParams.dstIp or DST_IP
	testParams.srcPort = testParams.srcPort or SRC_PORT
	testParams.dstPort = testParams.dstPort or DST_PORT
	testParams.srcMac = testParams.srcMac or SRC_MAC
	testParams.dstMac = testParams.dstMac or DST_MAC
	testParams.vlanId = testParams.vlanId
	testParams.baseDstMacUnsigned = macToU48(testParams.dstMac)
	testParams.baseSrcMacUnsigned = macToU48(testParams.srcMac)
	testParams.srcIp = parseIPAddress(testParams.srcIp)
	testParams.dstIp = parseIPAddress(testParams.dstIp)
	testParams.oneShot = testParams.oneShot or false
	testParams.mppsPerQueue = testParams.mppsPerQueue or MPPS_PER_QUEUE

	return testParams
end

function fileExists(f)
	local file = io.open(f, "r")
	if file then
	file:close()
	end
	return not not file
end

function acceptableLoss(testParams, rxStats, txStats)
	local pass = true
	for i, v in ipairs(txStats) do
		if testParams.connections[i] then
			local lostFrames = txStats[i].totalFrames - rxStats[testParams.connections[i]].totalFrames
			local lostFramePct = 100 * lostFrames / txStats[i].totalFrames
			if (lostFramePct > testParams.acceptableLossPct) then
				log:warn("Device %d->%d: FAILED - frame loss (%d, %.8f%%) is greater than the maximum (%.8f%%)",
				 (i-1), (testParams.connections[i]-1), lostFrames, lostFramePct, testParams.acceptableLossPct);
				pass = false
			else
				log:info("Device %d->%d PASSED - frame loss (%d, %.8f%%) is less than or equal to the maximum (%.8f%%)",
				 (i-1), (testParams.connections[i]-1), lostFrames, lostFramePct, testParams.acceptableLossPct);
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

function getLineRateMpps(devs, testParams)
	-- TODO: check actual link rate instead of using LINK_SPEED
	return  (LINK_SPEED /(testParams.frameSize*8 +64 +96) /1000000)
end

function calcTxQueues(rate, testParams)
	return 1 + math.floor(rate / testParams.mppsPerQueue)
end

function getMaxRateMpps(devs, testParams, rate)
	local qid
	local idx
	local calTasks = {}
	local calStats = {}
	local rxTasks = {}
	local txTasks = {}
	local timerTasks = {}
	local macs = {}
	local runTime = 10

	-- set the number of transmit queues based on the transmit rate
	testParams.txQueuesPerDev = calcTxQueues(rate, testParams)
        devs = prepareDevs(testParams)
	-- find the maximum transmit rate
	local perDevCalibratedRate = {}
	local rate_accuracy = TX_HW_RATE_TOLERANCE_MPPS / 2
	for i, v in ipairs(devs) do
		if testParams.connections[i] then
			local packetCount = 0
			local measuredRate = 0
			local prevMeasuredRate = 0
			local calibrated = false
			local calibrationCount = 0
			local overcorrection = 1

			-- first find the maximum rate without setting the rate value (which should be absolute fastest rate possible)
			local calibratedRate = 0 -- using 0 will force calibrateSlave to not set a rate
			log:info("Finding maximum Tx Rate",  testParams.txMethod, rate)
			log:info("num flows: %d",  testParams.nrFlows)
			-- launch a process to transmit packets per queue
			for q = 0, testParams.txQueuesPerDev - 1 do
				calTasks[q] = dpdk.launchLua("calibrateSlave", devs[i], calibratedRate, testParams, q)
			end
			-- wait for all jobs to complete
			for q = 0, testParams.txQueuesPerDev - 1 do
				calStats[q] = calTasks[q]:wait()
			end
			local measuredRate = calStats[0].avgMpps -- only the first queue provides the measured rate [for all queues]
			log:info("Max Tx rate: %.2f",  measuredRate)
			if measuredRate < rate then
				rate = measuredRate
			end

			-- next try to achieve the maximum rate by using a calibrated rate value
			testParams.rate = rate
			calibratedRate = rate
			repeat
				log:info("Calibrating %s tx rate for %.2f Mfs",  testParams.txMethod , testParams.rate)
				log:info("num flows: %d",  testParams.nrFlows)
				-- launch 1 process per Tx queue to transmit packets
				for q = 0, testParams.txQueuesPerDev - 1 do
					calTasks[q] = dpdk.launchLua("calibrateSlave", devs[i], calibratedRate, testParams, q)
				end
				-- wait for all jobs to complete
				for q = 0, testParams.txQueuesPerDev - 1 do
					calStats[q] = calTasks[q]:wait()
				end
				local measuredRate = calStats[0].avgMpps -- only the first queue provides the measured rate [for all queues]
				-- the measured rate must be within the tolerance window but also not exceed the desired rate
				if ( measuredRate > testParams.rate or (testParams.rate - measuredRate) > rate_accuracy ) then
					local correction_ratio = testParams.rate/measuredRate
					-- ensure a minimum amount of change in rate
					if (correction_ratio < 1 and correction_ratio > 0.99 ) then
						correction_ratio = 0.99
					end
					if (correction_ratio > 1 and correction_ratio < 1.01 ) then
						correction_ratio = 1.01
					end
					calibratedRate = calibratedRate * correction_ratio
						prevMeasuredRate = measuredRate
                        		log:info("measuredRate: %.4f  desiredRate:%.4f  new correction_ratio: %.4f  new calibratedRate: %.4f ",
			 		measuredRate, testParams.rate, correction_ratio, calibratedRate)
				else
					calibrated = true
					end
				calibrationCount = calibrationCount + 1
			until ( calibrated or calibrationCount > MAX_CALIBRATION_ATTEMPTS )
			if calibrated then
				return rate
			else
				log:error("Maximum tx rate reduced to %.2f", measuredRate) 
				return measuredRate
			end
		end
	end
end
			
function launchTest(final, devs, testParams, txStats, rxStats)
	local qid
	local idx
	local calTasks = {}
	local calStats = {}
	local rxTasks = {}
	local txTasks = {}
	local timerTasks = {}
	local macs = {}
	local runTime

	if testParams.testType == "throughput" or testParams.testType == "throughput-latency" then
		if final then
			runTime = testParams.validationRunTime
		else
			runTime = testParams.searchRunTime
		end
	else
		if testParams.testType == "latency" then
			runTime = testParams.latencyRunTime
		end
	end
	-- set the number of transmit queues based on the transmit rate
	testParams.txQueuesPerDev = calcTxQueues(testParams.rate, testParams)
        devs = prepareDevs(testParams)
	-- calibrate transmit rate
	local calibratedRate = testParams.rate
	local perDevCalibratedRate = {}
	local rate_accuracy = TX_HW_RATE_TOLERANCE_MPPS / 2
	for i, v in ipairs(devs) do
		if testParams.connections[i] then
			local packetCount = 0
			local measuredRate = 0
			local prevMeasuredRate = 0
			local calibrated = false
			local calibrationCount = 0
			local overcorrection = 1
			repeat
				log:info("Calibrating %s tx rate for %.2f Mfs",  testParams.txMethod , testParams.rate)
				log:info("num flows: %d",  testParams.nrFlows)
				-- launch a process to transmit packets per queue
				for q = 0, testParams.txQueuesPerDev - 1 do
					calTasks[q] = dpdk.launchLua("calibrateSlave", devs[i], calibratedRate, testParams, q)
				end
				-- wait for all jobs to complete
				for q = 0, testParams.txQueuesPerDev - 1 do
					calStats[q] = calTasks[q]:wait()
				end
				local measuredRate = calStats[0].avgMpps -- only the first queue provides the measured rate [for all queues]
				-- the measured rate must be within the tolerance window but also not exceed the desired rate
				if ( measuredRate > testParams.rate or (testParams.rate - measuredRate) > rate_accuracy ) then
					local correction_ratio = testParams.rate/measuredRate
					-- ensure a minimum amount of change in rate
					if (correction_ratio < 1 and correction_ratio > 0.99 ) then
						correction_ratio = 0.99
					end
					if (correction_ratio > 1 and correction_ratio < 1.01 ) then
						correction_ratio = 1.01
					end
					calibratedRate = calibratedRate * correction_ratio
						prevMeasuredRate = measuredRate
                        		log:info("measuredRate: %.4f  desiredRate:%.4f  new correction_ratio: %.4f  new calibratedRate: %.4f ",
			 		measuredRate, testParams.rate, correction_ratio, calibratedRate)
				else
					calibrated = true
					end
				calibrationCount = calibrationCount + 1
			until ( calibrated or calibrationCount > MAX_CALIBRATION_ATTEMPTS )
			if calibrated then
				perDevCalibratedRate[i] = calibratedRate
				log:info("Rate calibration complete") 
			else
				log:error("Could not achive Tx packet rate") 
				return
			end
		end
	end
	-- start devices which receive
	for i, v in ipairs(devs) do
		if testParams.connections[i] then
			rxTasks[i] = dpdk.launchLua("counterSlave", devs[testParams.connections[i]]:getRxQueue(0), runTime)
		end
	end
	dpdk.sleepMillis(3000)
	if final then
		log:info("Starting final validation");
	end
	-- start devices which transmit
	idx = 1
	for i, v in ipairs(devs) do
		if testParams.connections[i] then
			printf("Testing %.2f Mfps", testParams.rate)
			for q = 0, testParams.txQueuesPerDev - 1 do
				txTasks[i*q+q] = dpdk.launchLua("loadSlave", devs[i], perDevCalibratedRate[i], runTime, testParams, q)
			end
			if testParams.testType == "latency" or
				( testParams.testType == "throughput-latency" and final ) then
				-- latency measurements do not involve a dedicated task for each direction of traffic
				if not timerTasks[testParams.connections[i]] then
					timerTasks[i] = dpdk.launchLua("timerSlave", devs[i], devs[testParams.connections[i]], i, runTime, testParams)
				end
			end
		end
	end
	-- wait for transmit devices to finish
	for i, v in ipairs(devs) do
		if testParams.connections[i] then
			for q = 0, testParams.txQueuesPerDev - 1 do
				if q == 0 then
					txStats[i] = txTasks[i*q+q]:wait()
				else
					txTasks[i*q+q]:wait()
				end
			end
		end
	end
	if final then
		log:info("Stopping final validation");
	end
	dpdk.sleepMillis(3000)
	-- wait for receive devices to finish
	for i, v in ipairs(devs) do
		if testParams.connections[i] then
			rxStats[testParams.connections[i]] = rxTasks[i]:wait()
		end
		if testParams.testType == "latency" or
			( testParams.testType == "throughput-latency" and final ) then
			if timerTasks[i] then
				timerTasks[i]:wait()
			end
		end
	end
	return true
end

function adjustHeaders(bufs, packetCount, testParams)
	for _, buf in ipairs(bufs) do
		local pkt = buf:getUdpPacket()
		local ethernetPacket = buf:getEthernetPacket()
		local flowId = packetCount % testParams.nrFlows

		for _,v in ipairs(testParams.flowMods) do

			if ( v == "srcPort" ) then
				pkt.udp:setSrcPort((testParams.srcPort + flowId) % 65536)
			end
	
			if ( v == "dstPort" ) then
				pkt.udp:setDstPort((testParams.srcPort + flowId) % 65536)
			end
	
			if ( v == "srcIp" ) then
				pkt.ip4.src:set(testParams.srcIp + flowId)
			end
	
			if ( v == "dstIp" ) then
				pkt.ip4.dst:set(testParams.dstIp + flowId)
			end
	
			if ( v == "srcMac" ) then
				addr = testParams.baseSrcMacUnsigned + flowId
				ethernetPacket.eth.src.uint8[5] = bit.band(addr, 0xFF)
				ethernetPacket.eth.src.uint8[4] = bit.band(bit.rshift(addr, 8), 0xFF)
				ethernetPacket.eth.src.uint8[3] = bit.band(bit.rshift(addr, 16), 0xFF)
				ethernetPacket.eth.src.uint8[2] = bit.band(bit.rshift(addr, 24), 0xFF)
				ethernetPacket.eth.src.uint8[1] = bit.band(bit.rshift(addr + 0ULL, 32ULL), 0xFF)
				ethernetPacket.eth.src.uint8[0] = bit.band(bit.rshift(addr + 0ULL, 40ULL), 0xFF)
			end
	
			if ( v == "dstMac" ) then
				addr = testParams.baseDstMacUnsigned + flowId
				ethernetPacket.eth.dst.uint8[5] = bit.band(addr, 0xFF)
				ethernetPacket.eth.dst.uint8[4] = bit.band(bit.rshift(addr, 8), 0xFF)
				ethernetPacket.eth.dst.uint8[3] = bit.band(bit.rshift(addr, 16), 0xFF)
				ethernetPacket.eth.dst.uint8[2] = bit.band(bit.rshift(addr, 24), 0xFF)
				ethernetPacket.eth.dst.uint8[1] = bit.band(bit.rshift(addr + 0ULL, 32ULL), 0xFF)
				ethernetPacket.eth.dst.uint8[0] = bit.band(bit.rshift(addr + 0ULL, 40ULL), 0xFF)
			end
		end

		packetCount = packetCount + 1
	end
	return packetCount
end

function calibrateSlave(dev, calibratedRate, testParams, qid)
	local frame_size_without_crc = testParams.frameSize - 4
	-- TODO: this leaks memory as mempools cannot be deleted in DPDK
	local mem = memory.createMemPool(function(buf)
		buf:getUdpPacket():fill{
			pktLength = frame_size_without_crc, -- this sets all length headers fields in all used protocols
			ethSrc = testParams.srcMac,
			ethDst = testParams.dstMac,
			ip4Dst = testParams.dstIp,
			udpSrc = testParams.srcPort,
			udpDst = testParams.dstPort
		}
	end)
	local bufs = mem:bufArray()
	local packetCount = 0
	local overcorrection = 1
	-- each queue/process does a fraction of the rate
	calibratedRate = calibratedRate / testParams.txQueuesPerDev
	-- only the first process tracks stats for the device
	if qid == 0 then
		txStats = stats:newDevTxCounter(dev, "plain")
	end
	if ( testParams.txMethod == "hardware"  and calibratedRate > 0 ) then
		dev:getTxQueue(qid):setRateMpps(calibratedRate, testParams.frameSize)
		runtime = timer:new(5)
	else
		-- s/w rate seems to be less consistent, so test over longer time period
		runtime = timer:new(10)
	end
	while runtime:running() and dpdk.running() do
		bufs:alloc(frame_size_without_crc)
		packetCount = adjustHeaders(bufs, packetCount, testParams, srcMacs, dstMacs)
		if (testParams.vlanId) then
			bufs:setVlans(testParams.vlanId)
		end
               	bufs:offloadUdpChecksums()
		if ( testParams.txMethod == "hardware" ) then
			dev:getTxQueue(qid):send(bufs)
		else
			if calibratedRate > 0 then
				for _, buf in ipairs(bufs) do
					buf:setRate(calibratedRate)
				end
			end
			dev:getTxQueue(qid):sendWithDelay(bufs)
		end
		if qid == 0 then
			txStats:update(0.5)
		end
	end
	local results = {}
	if qid == 0 then
		txStats:finalize()
		results.avgMpps = txStats.mpps.avg
	end
        return results
end

function counterSlave(rxQueue, runTime)
	local rxStats = stats:newDevRxCounter(rxQueue, "plain")
	if runTime > 0 then
		-- Rx runs a bit longer than Tx to ensure all packets are received
		runTimer = timer:new(runTime + 6)
	end
	while (runTime == 0 or runTimer:running()) and dpdk.running() do
		rxStats:update(0.5)
	end
        rxStats:finalize()
	local results = {}
        results.totalFrames = rxStats.total
        return results
end

function loadSlave(dev, calibratedRate, runTime, testParams, qid)
	local frame_size_without_crc = testParams.frameSize - 4
	-- TODO: this leaks memory as mempools cannot be deleted in DPDK
	local mem = memory.createMemPool(function(buf)
		buf:getUdpPacket():fill{
			pktLength = frame_size_without_crc, -- this sets all length headers fields in all used protocols
			ethSrc = testParams.srcMac,
			ethDst = testParams.dstMac,
			ip4Dst = testParams.dstIp,
			udpSrc = testParams.srcPort,
			udpDst = testParams.dstPort
		}
	end)
	local bufs = mem:bufArray()
	if runTime > 0 then
		runtime = timer:new(runTime)
	end
	
	local txStats = stats:newDevTxCounter(dev, "plain")
	calibratedRate = calibratedRate / testParams.txQueuesPerDev
	local count = 0
	if ( testParams.txMethod == "hardware" ) then
		dev:getTxQueue(qid):setRateMpps(calibratedRate, testParams.frameSize)
	end
	local packetCount = 0
	while (runTime == 0 or runtime:running()) and dpdk.running() do
		bufs:alloc(frame_size_without_crc)
		packetCount = adjustHeaders(bufs, packetCount, testParams, srcMacs, dstMacs)
		if (testParams.vlanId) then
			bufs:setVlans(testParams.vlanId)
		end
                bufs:offloadUdpChecksums()
		if ( testParams.txMethod == "hardware" ) then
			dev:getTxQueue(qid):send(bufs)
		else
			for _, buf in ipairs(bufs) do
				buf:setRate(calibratedRate)
			end
			dev:getTxQueue(qid):sendWithDelay(bufs)
		end
		if qid == 0 then
			txStats:update(0.5)
		end
	end
        local results = {}
	if qid == 0 then
		txStats:finalize()
		results.totalFrames = txStats.total
		results.avgMpps = txStats.mpps.avg
	end
        return results
end

function timerSlave(dev1, dev2, port1, runTime, testParams)
	local rxQid = testParams.rxQueuesPerDev
	local txQid = testParams.txQueuesPerDev
	local hist1, hist2, haveHisto1, haveHisto2, timestamper1, timestamper2
	local rxQueues = {}
	local txQueues = {}
	local transactionsPerDirection = 1 -- the number of transactions before switching direction
	local frameSizeWithoutCrc = testParams.frameSize - 4
	local rateLimit = timer:new(0.001) -- less than 100 samples per second

	hist1 = hist()
	dev2:filterTimestamps(dev2:getRxQueue(rxQid))
	timestamper1 = ts:newUdpTimestamper(dev1:getTxQueue(txQid), dev2:getRxQueue(rxQid))
	if testParams.runBidirec then
		dev1:filterTimestamps(dev1:getRxQueue(rxQid))
		timestamper2 = ts:newUdpTimestamper(dev2:getTxQueue(txQid), dev1:getRxQueue(rxQid))
		hist2 = hist()
	end
	-- timestamping starts after and finishes before the main packet load starts/finishes
	dpdk.sleepMillis(LATENCY_TRIM)
	if runTime > 0 then
		runTimer = timer:new(runTime - LATENCY_TRIM/1000*2)
	end
	local timestamper = timestamper1
	local hist = hist1
	local haveHisto = false
	local haveHisto1 = false
	local haveHisto2 = false
	while (runTime == 0 or runTimer:running()) and dpdk.running() do
		for count = 0, transactionsPerDirection - 1 do -- inner loop tests in one direction
			rateLimit:wait()
			local lat = timestamper:measureLatency();
			if (lat) then
				haveHisto = true;
                		hist:update(lat)
			end
			rateLimit:reset()
		end
		if testParams.runBidirec then
			if timestamper == timestamper2 then
				timestamper = timestamper1
				hist = hist1
				haveHisto2 = haveHisto
				haveHisto = haveHisto1
			else
				timestamper = timestamper2
				hist = hist2
				haveHisto1 = haveHisto
				haveHisto = haveHisto2
			end
		else
			haveHisto1 = haveHisto
		end
	end
	dpdk.sleepMillis(LATENCY_TRIM + 1000) -- the extra 1000 ms ensures the stats are output after the throughput stats
	local histDesc = "Histogram port " .. testParams.ports[port1] .. " to port " .. testParams.ports[testParams.connections[port1]]
	local histFile = "hist:" .. testParams.ports[port1] .. "-" .. testParams.ports[testParams.connections[port1]] .. ".csv"
	if haveHisto1 then
		hist1:print(histDesc)
		hist1:save(histFile)
	else
		log:warn("no latency samples found for %s", histDesc)
	end
	if testParams.runBidirec then
		local histDesc = "Histogram port " .. testParams.ports[testParams.connections[port1]] .. " to port " .. testParams.ports[port1]
		local histFile = "hist:" .. testParams.ports[testParams.connections[port1]] .. "-" .. testParams.ports[port1] .. ".csv"
		if haveHisto2 then
			hist2:print(histDesc)
			hist2:save(histFile)
		else
			log:warn("no latency samples found for %s", histDesc)
		end
	end
end
