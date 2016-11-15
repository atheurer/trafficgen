local moongen	= require "moongen"
local dpdk	= require "dpdk"
local memory	= require "memory"
local ts	= require "timestamping"
local device	= require "device"
local filter	= require "filter"
local timer	= require "timer"
local stats	= require "stats"
local hist	= require "histogram"
local log	= require "log"
local ip        = require "proto.ip4"

-- required here because this script creates *a lot* of mempools
-- memory.enableCache()

local PCI_ID_X710 = 0x80861572
local PCI_ID_XL710 = 0x80861583

function intsToTable(instr)
	local t = {}
	sep = ","
	for str in string.gmatch(instr, "([^"..sep.."]+)") do
               	table.insert(t, tonumber(str))
	end
	return t
end

function stringsToTable(instr)
	local t = {}
	sep = ","
	for str in string.gmatch(instr, "([^"..sep.."]+)") do
               	table.insert(t, str)
	end
	return t
end

function parseIPAddresses(t)
	for i, _ in ipairs(t) do
		t[i] = parseIPAddress(t[i])
	end
end

function parseMacs(t)
	local u = {}
	for i, _ in ipairs(t) do
		table.insert(u, macToU48(t[i]))
	end
	return u
end

function configure(parser)
	parser:option("--devices", "A comma separated list (no spaces) of one or more Tx/Rx device pairs, for example: 0,1,2,3"):default({0,1}):convert(intsToTable)
	parser:option("--vlanIds", "A comma separated list of one or more vlanIds, corresponding to each entry in deviceList"):default(nil):convert(intsToTable)
	parser:option("--size", "Frame size."):default(64):convert(tonumber)
	parser:option("--rate", "Transmit rate in Mpps"):default(1):convert(tonumber)
	parser:option("--measureLatency", "true or false"):default(false)
	parser:option("--bidirectional", "true or false"):default(false)
	parser:option("--nrFlows", "Number of unique network flows"):default(1024):convert(tonumber)
	parser:option("--runTime", "Number of seconds to run"):default(30):convert(tonumber)
	parser:option("--flowMods", "Comma separated list (no spaces), one or more of:  srcIp,dstIp,srcMac,dstMac,srcPort,dstPort"):default({"srcIp"}):convert(stringsToTable)
	parser:option("--srcIps", "A comma separated list (no spaces) of source IP address used"):default("10.0.0.1,192.168.0.1"):convert(stringsToTable)
	parser:option("--dstIps", "A comma separated list (no spaces) of destination IP address used"):default("192.168.0.1,10.0.0.1"):convert(stringsToTable)
	parser:option("--srcMacs", "A comma separated list (no spaces) of source MAC address used"):default({}):convert(stringsToTable)
	parser:option("--dstMacs", "A comma separated list (no spaces) of destination MAC address used"):default({}):convert(stringsToTable)
	parser:option("--srcPort", "Source port used"):default(1234):convert(tonumber)
	parser:option("--dstPort", "Destination port used"):default(1234):convert(tonumber)
	parser:option("--mppsPerQueue", "The maximum transmit rate in Mpps for each device queue"):default(5):convert(tonumber)
	parser:option("--queuesPerTask", "The maximum transmit number of queues to use per task"):default(3):convert(tonumber)
	parser:option("--linkSpeed", "The speed in Gbps of the device(s)"):default(10):convert(tonumber)
	parser:option("--maxLossPct", "The maximum frame loss percentage tolerated"):default(0.002):convert(tonumber)
	parser:option("--rateTolerance", "Stop the test if the specified transmit rate drops by this amount, in Mpps"):default(0.25):convert(tonumber)
end

function master(args)
	args.txMethod = "hardware"
	local txQueues = 1 + math.floor(args.rate / args.mppsPerQueue)
	local devs = {}
	parseIPAddresses(args.srcIps)
	parseIPAddresses(args.dstIps)
	-- The connections[] table defines a relationship between te device which transmits and a device which receives the same packets.
	-- This relationship is derived via the devices[] table, where if devices contained {a, b, c, d}, device a transmits to device b,
	-- and device c transmits to device d.  
	-- If bidirectional traffic is enabled, the reverse is also true, and device b transmits to device a and d to c.
	connections = {}
	for i, deviceNum in ipairs(args.devices) do -- devices = {a, b, c, d} a sends packets to b, c sends packets to d
		-- initialize the devices
		if args.measureLatency then 
			local rxQueues = 2
			txQueues = txQueues + 1
			log:info("configuring device %d with %d tx queues and %d rx queues", deviceNum, txQueues, rxQueues)
			devs[i] = device.config{ port = args.devices[i],
				 		txQueues = txQueues,
				 		rxQueues = rxQueues}
		else
			local rxQueues = 1
			log:info("configuring device %d with %d tx queues and %d rx queues", deviceNum, txQueues, rxQueues)
			devs[i] = device.config{ port = args.devices[i],
				 		txQueues = txQueues,
				 		rxQueues = rxQueues}
		end
		-- configure the connections
		if ( i % 2 == 1) then -- for devices a, c
			connections[i] = i + 1  -- device a transmits to device b, device c transmits to device d 
			log:info("device %d transmits to device %d", args.devices[i], args.devices[connections[i]]);
			if args.bidirectional then
				connections[i + 1] = i  -- device b transmits to device a, device d transmits to device c
				log:info("device %d transmits to device %d", args.devices[connections[i]], args.devices[i]);
			end
		end
	end
	for i, deviceNum in ipairs(args.devices) do 
		if args.vlanIds and args.vlanIds[i] then
			log:info("device %d when transmitting will use vlan ID: [%d]", deviceNum, args.vlanIds[i])
		end
		if not args.srcMacs[i] and connections[i] then
			args.srcMacs[i] = devs[i]:getMacString()
		end
		if args.srcMacs[i] and connections[i] then
			log:info("device %d src MAC: [%s]", deviceNum, args.srcMacs[i])
		end
	end
	for i, deviceNum in ipairs(args.devices) do
		if not args.dstMacs[i] and connections[i] then
			args.dstMacs[i] = args.srcMacs[connections[i]]
		end
		if args.dstMacs[i] and connections[i] then
			log:info("device %d when transmitting will use dst MAC: [%s]", deviceNum, args.dstMacs[i])
		end
	end
	args.srcMacsU48 = parseMacs(args.srcMacs)
	args.dstMacsU48 = parseMacs(args.dstMacs)
	device.waitForLinks()
	
	idx = 1
	local txTasksPerDev = math.ceil(txQueues / args.queuesPerTask)
	local txTaskId = 1
	local txTasks = {}
	local rxTasks = {}
	-- start the load tasks
	for devId, v in ipairs(devs) do
		if connections[devId] then
			printf("Testing %.2f Mfps", args.rate)
			for perDevTaskId = 0, txTasksPerDev - 1 do
				local queueIds = getTxQueues(args.queuesPerTask, txQueues, perDevTaskId, devs, devId)
				txTasks[txTaskId] = moongen.startTask("loadSlave", devs, devId, args, perDevTaskId, queueIds, devs[connections[devId]]:getRxQueue(0))
				txTaskId = txTaskId + 1
			end
			--if args.testType == "latency" or
				--( args.testType == "throughput-latency" and final ) then
				---- latency measurements do not involve a dedicated task for each direction of traffic
				--if not timerTasks[connections[devId]] then
					--local queueIds = getTimerQueues(devs, devId, args)
					--log:info("timer queues: %s", dumpQueues(queueIds))
					--timerTasks[devId] = moongen.startTask("timerSlave", args, queueIds)
				--end
			--end
		end
	end
	-- wait for loadSlaves devices to finish
	local txStats = {}
	local txTaskId = 1
	for devId, v in ipairs(devs) do
		if connections[devId] then
			for perDevTaskId = 0, txTasksPerDev - 1 do
				if perDevTaskId == 0 then
					txStats[devId] = txTasks[txTaskId]:wait()
				else
					txTasks[txTaskId]:wait()
				end
				txTaskId = txTaskId + 1
			end
		end
	end
end

function getTxQueues(txQueuesPerTask, txQueues, taskId, devs, devId)
	local queueIds = {}
	local firstQueueId = taskId * txQueuesPerTask
	local lastQueueId = firstQueueId + txQueuesPerTask - 1
	if lastQueueId > (txQueues - 1) then
		lastQueueId = txQueues - 1
	end
	for queueId = firstQueueId, lastQueueId do
		table.insert(queueIds, devs[devId]:getTxQueue(queueId))
	end
	return queueIds
end

function getTimerQueues(devs, devId, testParams)
	-- build a table of one or more pairs of queues
	local queueIds = { devs[devId]:getTxQueue(txQueues), devs[testParams.connections[devId]]:getRxQueue(testParams.rxQueuesPerDev) }
	-- If this is a bidirectional test, add another queue-pair for the other direction:
	if testParams.connections[testParams.connections[devId]] then
		table.insert(queueIds, devs[testParams.connections[devId]]:getTxQueue(txQueues))
		table.insert(queueIds, devs[devId]:getRxQueue(testParams.rxQueuesPerDev))
	end
	return queueIds
end

function adjustHeaders(devId, bufs, packetCount, args)
	for _, buf in ipairs(bufs) do
		local pkt = buf:getUdpPacket()
		local ethernetPacket = buf:getEthernetPacket()
		local flowId = packetCount % args.nrFlows

		for _,v in ipairs(args.flowMods) do

			if ( v == "srcPort" ) then
				pkt.udp:setSrcPort((args.srcPort + flowId) % 65536)
			end
	
			if ( v == "dstPort" ) then
				pkt.udp:setDstPort((args.srcPort + flowId) % 65536)
			end
	
			if ( v == "srcIp" ) then
				pkt.ip4.src:set(args.srcIps[devId] + flowId)
			end
	
			if ( v == "dstIp" ) then
				pkt.ip4.dst:set(args.dstIps[devId] + flowId)
			end
	
			if ( v == "srcMac" ) then
				addr = args.srcMacsUnsigned[devId] + flowId
				ethernetPacket.eth.src.uint8[5] = bit.band(addr, 0xFF)
				ethernetPacket.eth.src.uint8[4] = bit.band(bit.rshift(addr, 8), 0xFF)
				ethernetPacket.eth.src.uint8[3] = bit.band(bit.rshift(addr, 16), 0xFF)
				ethernetPacket.eth.src.uint8[2] = bit.band(bit.rshift(addr, 24), 0xFF)
				ethernetPacket.eth.src.uint8[1] = bit.band(bit.rshift(addr + 0ULL, 32ULL), 0xFF)
				ethernetPacket.eth.src.uint8[0] = bit.band(bit.rshift(addr + 0ULL, 40ULL), 0xFF)
			end
	
			if ( v == "dstMac" ) then
				addr = args.dstMacsUnsigned[devId] + flowId
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

function getBuffers(devId, args)
	local mem = memory.createMemPool(function(buf)
		local eth_dst
		buf:getUdpPacket():fill{
			pktLength = frame_size_without_crc, -- this sets all length headers fields in all used protocols
			ethSrc = args.srcMacs[devId],
			ethDst = args.dstMacs[devId],
			ip4Dst = args.dstIps[devId],
			udpSrc = args.srcPort,
			udpDst = args.dstPort
		}
	end)
	local bufs = mem:bufArray()
	return bufs
end

function dumpQueues(queueIds)
	local queues = ""
	for _ , queueId in pairs(queueIds)  do
		queues = queues..queueId:__tostring()
	end
	return queues
end

function dumpTable(table, indent)
	local indentString = ""

	for i=1,indent,1 do
		indentString = indentString.."\t"
	end

	for key,value in pairs(table) do
		if type(value) == "table" then
			log:info("%s%s => {", indentString, key)
			dumpTable(value, indent+1)
			log:info("%s}", indentString)
		else
			log:info("%s%s: %s", indentString, key, value)
		end
	end
end

function dumpTestParams(args)
	log:info("args => {")
	dumpTable(args, 1)
	log:info("}")
end

function loadSlave(devs, devId, args, taskId, queueIds, rxQueue)
	local dev = devs[devId]
	local frame_size_without_crc = args.size - 4
	local bufs = getBuffers(devId, args)
	log:info("loadSlave: devId: %d  taskId: %d  rate: %.4f queues: %s", devId, taskId, args.rate, dumpQueues(queueIds))
	if args.runTime > 0 then
		runtime = timer:new(args.runTime)
		log:info("loadSlave test to run for %d seconds", args.runTime)
	else
		log:warn("loadSlave args.runTime is 0")
	end
	
	if taskId == 0 then
		rxStats = stats:newDevRxCounter(rxQueue.dev, "plain")
		txStats = stats:newDevTxCounter(dev, "plain")
	end
	local count = 0
	local pci_id = dev:getPciId()
	if ( args.txMethod == "hardware" ) then
        	if pci_id == PCI_ID_X710 or pci_id == PCI_ID_XL710 then
                	dev:setRate(args.rate * (args.size + 4) * 8)
		else
			local queueId
			for _ , queueId in pairs(queueIds)  do
				queueId:setRateMpps(args.rate / txQueues, args.size)
			end
		end
	end
	local packetCount = 0
	while (args.runTime == 0 or runtime:running()) and moongen.running() do
		bufs:alloc(frame_size_without_crc)
		packetCount = adjustHeaders(devId, bufs, packetCount, args, srcMacs, dstMacs)
		if (args.vlanIds and args.vlanIds[devId]) then
			bufs:setVlans(args.vlanIds[devId])
		end
                bufs:offloadUdpChecksums()
		if ( args.txMethod == "hardware" ) then
			local queueId
			for _ , queueId in pairs(queueIds)  do
				queueId:send(bufs)
			end
		else
			for _, buf in ipairs(bufs) do
				buf:setRate(args.rate)
			end
			local queueId
			for _ , queueId in pairs(queueIds)  do
				queueId:sendWithDelay(bufs)
			end
		end
		if taskId == 0 then
			rxStats:update()
			txStats:update()
		end
	end
        local results = {}
	if taskId == 0 then
        	rxStats:finalize()
		txStats:finalize()
        	results.totalRxFrames = rxStats.total
		results.totalTxFrames = txStats.total
		results.avgMpps = txStats.mpps.avg
	end
        return results
end

function saveSampleLog(file, samples, label)
	log:info("Saving sample log to '%s'", file)
	file = io.open(file, "w+")
	file:write("samples,", label, "\n")
	for i,v in ipairs(samples) do
		file:write(i, ",", v, "\n")
	end
	file:close()
end

function saveHistogram(file, hist, label)
	output = io.open(file, "w")
	output:write("bucket,", label, "\n")
	hist:save(output)
	output:close()
end

function timerSlave(args, queueIds)
	local hist1, hist2, haveHisto1, haveHisto2, timestamper1, timestamper2
	local transactionsPerDirection = 1 -- the number of transactions before switching direction
	local frameSizeWithoutCrc = args.size - 4
	local rateLimit = timer:new(0.001) -- less than 1000 samples per second
	local sampleLog1 = {}
	local sampleLog2 = {}

	-- TODO: adjust headers for flows

	if args.bidirectional then
		log:info("timerSlave: bidirectional testing from %d->%d and %d->%d", queueIds[1].id, queueIds[2].id, queueIds[3].id, queueIds[4].id)
	else
		log:info("timerSlave: unidirectional testing from %d->%d", queueIds[1].id, queueIds[2].id)
	end
	
	hist1 = hist()
	if args.size < 76 then
		log:warn("Latency packets are not UDP due to requested size (%d) less than minimum UDP size (76)", args.size)
		timestamper1 = ts:newTimestamper(queueIds[1], queueIds[2])
	else
		timestamper1 = ts:newUdpTimestamper(queueIds[1], queueIds[2])
	end
	if args.bidirectional then
		if args.size < 76 then
			timestamper2 = ts:newTimestamper(queueIds[3], queueIds[4])
		else
			timestamper2 = ts:newUdpTimestamper(queueIds[3], queueIds[4])
		end
		hist2 = hist()
	end
	-- timestamping starts after and finishes before the main packet load starts/finishes
	moongen.sleepMillis(LATENCY_TRIM)
	if args.runTime > 0 then
		local actualRunTime = args.runTime - LATENCY_TRIM/1000*2
		args.runTimer = timer:new(actualRunTime)
		log:info("Latency test to run for %d seconds", actualRunTime)
	else
		log:warn("Latency args.runTime is 0")
	end
	local timestamper = timestamper1
	local hist = hist1
	local sampleLog = sampleLog1
	local haveHisto = false
	local haveHisto1 = false
	local haveHisto2 = false
	local counter = 0
	local counter1 = 0
	local counter2 = 0
	while (args.runTime == 0 or runTimer:running()) and moongen.running() do
		for count = 0, transactionsPerDirection - 1 do -- inner loop tests in one direction
			rateLimit:wait()
			counter = counter + 1
			local lat = timestamper:measureLatency(args.size);
			if (lat) then
				haveHisto = true;
                		hist:update(lat)
				sampleLog[counter] = lat
			else
				sampleLog[counter] = -1
			end
			rateLimit:reset()
		end
		if args.bidirectional then
			if timestamper == timestamper2 then
				timestamper = timestamper1
				hist = hist1
				sampleLog = sampleLog1
				haveHisto2 = haveHisto
				haveHisto = haveHisto1
				counter2 = counter
				counter = counter1
			else
				timestamper = timestamper2
				hist = hist2
				sampleLog = sampleLog2
				haveHisto1 = haveHisto
				haveHisto = haveHisto2
				counter1 = counter
				counter = counter2
			end
		else
			haveHisto1 = haveHisto
			counter1 = counter
		end
	end
	moongen.sleepMillis(LATENCY_TRIM + 1000) -- the extra 1000 ms ensures the stats are output after the throughput stats
	local histDesc = "Histogram port " .. ("%d"):format(queueIds[1].id) .. " to port " .. ("%d"):format(queueIds[2].id) .. " at rate " .. args.rate .. " Mpps"
	local histFile = "dev:" .. ("%d"):format(queueIds[1].id) .. "-" .. ("%d"):format(queueIds[2].id) .. "_rate:" .. args.rate .. ".csv"
	local headerLabel = "Dev:" .. ("%d"):format(queueIds[1].id) .. "->" .. ("%d"):format(queueIds[2].id) .. " @ " .. args.rate .. " Mpps"
	if haveHisto1 then
		hist1:print(histDesc)
		saveHistogram("latency:histogram_" .. histFile, hist1, headerLabel)
		local hist_size = hist1:totals()
		if hist_size ~= counter1 then
		   log:warn("[%s] Lost %d samples (%.2f%%)!", histDesc, counter1 - hist_size, (counter1 - hist_size)/counter1*100)
		end
		saveSampleLog("latency:samples_" .. histFile, sampleLog1, headerLabel)
	else
		log:warn("no latency samples found for %s", histDesc)
	end
	if args.bidirectional then
		local histDesc = "Histogram port " .. ("%d"):format(queueIds[3].id) .. " to port " .. ("%d"):format(queueIds[4].id) .. " at rate " .. args.rate .. " Mpps"
		local histFile = "dev:" .. ("%d"):format(queueIds[3].id) .. "-" .. ("%d"):format(queueIds[4].id) .. "_rate:" .. args.rate .. ".csv"
		local headerLabel = "Dev:" .. ("%d"):format(queueIds[3].id) .. "->" .. ("%d"):format(queueIds[4].id) .. " @ " .. args.rate .. " Mpps"
		if haveHisto2 then
			hist2:print(histDesc)
			saveHistogram("latency:histogram_" .. histFile, hist2, headerLabel)
			local hist_size = hist2:totals()
			if hist_size ~= counter2 then
			   log:warn("[%s] Lost %d samples (%.2f%%)!", histDesc, counter2 - hist_size, (counter2 - hist_size)/counter2*100) 
			end
			saveSampleLog("latency:samples_" .. histFile, sampleLog2, headerLabel)
		else
			log:warn("no latency samples found for %s", histDesc)
		end
	end
end

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
