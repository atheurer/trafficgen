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
local icmp	= require "proto.icmp"

-- required here because this script creates *a lot* of mempools
-- memory.enableCache()

local PCI_ID_X710 = 0x80861572
local PCI_ID_XL710 = 0x80861583
local LATENCY_TRIM = 2

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

function convertMacs(t)
	local u = {}
	for i, v in ipairs(t) do
		table.insert(u, macToU48(v))
	end
	return u
end

function configure(parser)
	parser:option("--devices", "A comma separated list (no spaces) of one or more Tx/Rx device pairs, for example: 0,1,2,3"):default({0,1}):convert(intsToTable)
	parser:option("--vlanIds", "A comma separated list of one or more vlanIds, corresponding to each entry in deviceList"):default(nil):convert(intsToTable)
	parser:option("--size", "Frame size."):default(64):convert(tonumber)
	parser:option("--rate", "Transmit rate in Mpps"):default(1):convert(tonumber)
	parser:option("--measureLatency", "true or false"):default(true)
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
	parser:option("--queuesPerTask", "The maximum transmit number of queues to use per task"):default(1):convert(tonumber)
	parser:option("--linkSpeed", "The speed in Gbps of the device(s)"):default(10):convert(tonumber)
	parser:option("--maxLossPct", "The maximum frame loss percentage tolerated"):default(0.002):convert(tonumber)
	parser:option("--rateTolerance", "Stop the test if the specified transmit rate drops by this amount, in Mpps"):default(0.25):convert(tonumber)
end

function master(args)
	args.txMethod = "hardware"
	--the number of transmit queues -not- including queues for measuring latency
	local numTxQueues = 1 + math.floor(args.rate / args.mppsPerQueue)
	--the number of receive queues -not- including queues for measuring latency
	--local numRxQueues = 2 --first queue is for traffic that does not match what is sent, second queue is for only packets that aer sent
	local numRxQueues = 2 --first queue is for traffic that does not match what is sent, second queue is for only packets that aer sent
	if args.measureLatency == true then 
		log:info("Adding 1 rx and 1 tx queue to measure latency")
		numRxQueues = numRxQueues + 1
		numTxQueues = numTxQueues + 1
	end
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
		log:info("configuring device %d with %d tx queues and %d rx queues", deviceNum, numTxQueues, numRxQueues)
		if args.measureLatency == true then 
			devs[i] = device.config{ port = args.devices[i],
			 			txQueues = numTxQueues + 1,
			 			rxQueues = numRxQueues + 1}
		else
			devs[i] = device.config{ port = args.devices[i],
			 			txQueues = numTxQueues,
			 			rxQueues = numRxQueues}
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
			log:info("device %d will use vlan ID: [%d]", deviceNum, args.vlanIds[i])
			devs[i]:filterVlan(args.vlanIds[i])
		end
		if not args.srcMacs[i] then
			args.srcMacs[i] = devs[i]:getMacString()
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
	args.srcMacsU48 = convertMacs(args.srcMacs)
	args.dstMacsU48 = convertMacs(args.dstMacs)
	device.waitForLinks()
	
	filterEther = false
	filterTs = false
	filterTuple = false
	for i, deviceNum in ipairs(args.devices) do 
		-- add a filter for the IP address of the receiving device
		if connections[i] then -- if this device transmits
			rxDevId = connections[i]  -- this is the receicing device
			if filterEther == true then
				devs[rxDevId]:l2Filter(0x0800, devs[rxDevId]:getRxQueue(1))
			end
			if filterTs == true then
				devs[rxDevId]:filterUdpTimestamps(devs[rxDevId]:getRxQueue(1))
			end
			if filterTuple == true then
				log:info("filter srcIp: %s", ip4ToString(args.srcIps[i]))
				log:info("filter dstIp: %s", ip4ToString(args.dstIps[i]))
				devs[rxDevId]:fiveTupleFilter({
								dstIp = ip4ToString(args.dstIps[i]),
								srcIp = ip4ToString(args.srcIps[i]),
								srcPort = 1234, dstPort = 1234,
								proto = 0x11}, devs[rxDevId]:getRxQueue(1))
			end
		end
	end
	local txTasksPerDev = math.ceil(numTxQueues / args.queuesPerTask)
	local taskId
	local txTasks = {}
	local rxTasks = {}
	local timerTasks = {}

	-- start the rx tasks
	taskId = 1
	for txDevId, v in ipairs(devs) do
		if connections[txDevId] then
			rxDevId = connections[txDevId]
			for perDevTaskId = 0, numRxQueues - 1 do
				rxTasks[taskId] = moongen.startTask("rx", args, perDevTaskId, devs[rxDevId]:getRxQueue(perDevTaskId))
				taskId = taskId + 1
			end
		end
	end
	-- a little time to ensure rx threads are ready
	moongen.sleepMillis(1000)
	-- start the tx tasks
	taskId = 1
	for txDevId, v in ipairs(devs) do
		if connections[txDevId] then
			rxDevId = connections[txDevId]
			printf("Testing %.2f Mfps", args.rate)
			for perDevTaskId = 0, txTasksPerDev - 1 do
				local txQueues = getTxQueues(args.queuesPerTask, numTxQueues, perDevTaskId, devs[txDevId])
				txTasks[taskId] = moongen.startTask("tx", args, perDevTaskId, txQueues, txDevId)
				taskId = taskId + 1
			end
			if args.measureLatency == true then
				-- latency measurements do not involve a dedicated task for each direction of traffic
				if not timerTasks[connections[txDevId]] then
					local latencyQueues = getTimerQueues(devs, txDevId, args, numTxQueues, numRxQueues, connections)
					log:info("timer queues: %s", dumpQueues(latencyQueues))
					timerTasks[txDevId] = moongen.startTask("timerSlave", args, latencyQueueIds)
				end
			end
		end
	end
	-- wait for tx devices to finish
	local txStats = {}
	taskId = 1
	for txDevId, v in ipairs(devs) do
		if connections[txDevId] then
			for perDevTaskId = 0, txTasksPerDev - 1 do
				if perDevTaskId == 0 then
					txStats[txDevId] = txTasks[taskId]:wait()
				else
					txTasks[taskId]:wait()
				end
				taskId = taskId + 1
			end
		end
	end
	-- give time for the packet to come back
	moongen.sleepMillis(1000)
	moongen.stop()
	local rxStats = {}
	taskId = 1
	for txDevId, v in ipairs(devs) do
		if connections[txDevId] then
			for perDevTaskId = 0, numRxQueues - 1 do
				if perDevTaskId == 0 then
					rxStats[txDevId] = rxTasks[taskId]:wait()
				else
					rxTasks[taskId]:wait()
				end
				taskId = taskId + 1
			end
		end
	end
	for txDevId, v in ipairs(devs) do
		if connections[txDevId] then
			rxTasks[txDevId]:wait()
			if args.measureLatency == true then
				if not timerTasks[connections[txDevId]] then
					timerTasks[txDevId]:wait()
				end
			end
		end
	end
end

function getRxQueues(queuesPerTask, numQueues, taskId, dev)
	local queues = {}
	local firstQueueId = taskId * queuesPerTask
	local lastQueueId = firstQueueId + queuesPerTask - 1
	if lastQueueId > (numQueues - 1) then
		lastQueueId = numQueues - 1
	end
	for queueId = firstQueueId, lastQueueId do
		table.insert(queues, dev:getRxQueue(queueId))
	end
	return queues
end

function getTxQueues(txQueuesPerTask, numTxQueues, taskId, dev)
	local queues = {}
	local firstQueueId = taskId * txQueuesPerTask
	local lastQueueId = firstQueueId + txQueuesPerTask - 1
	if lastQueueId > (numTxQueues - 1) then
		lastQueueId = numTxQueues - 1
	end
	for queueId = firstQueueId, lastQueueId do
		table.insert(queues, dev:getTxQueue(queueId))
	end
	return queues
end

function getTimerQueues(devs, devId, args, txQueueId, rxQueueId, connections)
	-- build a table of one or more pairs of queues
	log:info("txQueueId: %d rxQueueId: %d", txQueueId, rxQueueId)
	local queueIds = { devs[devId]:getTxQueue(txQueueId), devs[connections[devId]]:getRxQueue(rxQueueId) }
	-- If this is a bidirectional test, add another queue-pair for the other direction:
	if connections[connections[devId]] then
		table.insert(queueIds, devs[connections[devId]]:getTxQueue(txQueueId))
		table.insert(queueIds, devs[devId]:getRxQueue(rxQueueId))
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
				addr = args.srcMacsU48[devId] + flowId
				ethernetPacket.eth.src.uint8[5] = bit.band(addr, 0xFF)
				ethernetPacket.eth.src.uint8[4] = bit.band(bit.rshift(addr, 8), 0xFF)
				ethernetPacket.eth.src.uint8[3] = bit.band(bit.rshift(addr, 16), 0xFF)
				ethernetPacket.eth.src.uint8[2] = bit.band(bit.rshift(addr, 24), 0xFF)
				ethernetPacket.eth.src.uint8[1] = bit.band(bit.rshift(addr + 0ULL, 32ULL), 0xFF)
				ethernetPacket.eth.src.uint8[0] = bit.band(bit.rshift(addr + 0ULL, 40ULL), 0xFF)
			end
	
			if ( v == "dstMac" ) then
				addr = args.dstMacsU48[devId] + flowId
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
		
		buf:getUdpPacket():fill{
			pktLength = frame_size_without_crc,
			ethSrc = args.srcMacs[devId],
			ethDst = args.dstMacs[devId],
			ip4Src = args.srcIps[devId],
			ip4Dst = args.dstIps[devId],
			udpSrc = args.srcPort,
			udpDst = args.dstPort
		}
	end)
	local bufs = mem:bufArray()
	return bufs
end

function dumpQueues(queues)
	local queuesStr = ""
	local queue
	for _, queue in ipairs(queues)  do
		queuesStr = queuesStr..queue:__tostring()
	end
	return queuesStr
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

function tx(args, taskId, txQueues, txDevId)
	local txDev = txQueues[1].dev
	local frame_size_without_crc = args.size - 4
	local bufs = getBuffers(txDevId, args)
	log:info("tx: txDev: %s  taskId: %d  rate: %.4f txQueues: %s", txDev, taskId, args.rate, dumpQueues(txQueues))

	if args.runTime > 0 then
		runtime = timer:new(args.runTime)
		log:info("tx test to run for %d seconds", args.runTime)
	else
		log:warn("tx args.runTime is 0")
	end
	
	local count = 0
	local pci_id = txDev:getPciId()
	if ( args.txMethod == "hardware" ) then
        	if pci_id == PCI_ID_X710 or pci_id == PCI_ID_XL710 then
                	txDev:setRate(args.rate * (args.size + 4) * 8)
		else
			local queueId
			for _ , queueId in pairs(txQueues)  do
				queueId:setRateMpps(args.rate / table.getn(txQueues), args.size)
			end
		end
	end
	local packetCount = 0
	while (args.runTime == 0 or runtime:running()) and moongen.running() do
		bufs:alloc(frame_size_without_crc)
		if args.flowMods then
			packetCount = adjustHeaders(txDevId, bufs, packetCount, args, srcMacs, dstMacs)
		end
		if (args.vlanIds and args.vlanIds[txDevId]) then
			bufs:setVlans(args.vlanIds[txDevId])
		end
                bufs:offloadUdpChecksums()
		if ( args.txMethod == "hardware" ) then
			local queueId
			for _, queueId in ipairs(txQueues)  do
				queueId:send(bufs)
			end
		else
			for _, buf in ipairs(bufs) do
				buf:setRate(args.rate)
			end
			local queueId
			for _ , queueId in pairs(txQueues)  do
				queueId:sendWithDelay(bufs)
			end
		end
	end
	log:info("tx: sent %d packets", packetCount)
        local results = {}
        return results
end

function rx(args, perDevTaskId, queue)
	local totalPkts = 0
	local bufs = memory.bufArray(64)
	while moongen.running() do
		local numPkts = queue:recv(bufs)
		for i = 1, numPkts do
			local buf = bufs[i]
			totalPkts = totalPkts + 1
			if totalPkts % 100000 == 0 then
				log:info("Dumping packet number %d", totalPkts)
				local ethPkt = buf:getEthernetPacket()
				local udpPkt = buf:getUdpPacket()
				--log:info("Destination port: %d", udpPkt.udp:getDstPort())
				buf:dump()
			end
		end
		bufs:free(numPkts)
			
	end
	log:info("queue %s total rx packets: %d", queue, totalPkts)
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
		runTimer = timer:new(actualRunTime)
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

-- vtep is the endpoint when MoonGen de-/encapsulates traffic 
-- enc(capsulated/tunneled traffic) is facing the l3 network, dec(apsulated traffic) is facing l2 network
-- remote is where we tx/rx traffic with MoonGen (load-/counterslave)
-- Setup: <interface>:<host>:<interface>
-- :loadgen/sink:decRemote <-----> decVtep:Vtep:encVtep <-----> encRemote:sink/loadgen:
local encVtepEth 	= "90:e2:ba:2c:cb:02" -- vtep, public/l3 side
local encVtepIP		= "10.0.0.1"
local encRemoteEth	= "90:e2:ba:01:02:03" -- MoonGen load/counter slave
local encRemoteIP	= "10.0.0.2"

local VNI 		= 1000

local decVtepEth	= "90:e2:ba:1f:8d:44" -- vtep, private/l2 side
local decRemoteEth	= "90:e2:ba:0a:0b:0c" -- MoonGen counter/load slave

-- can be any proper payload really, we use this etherType to identify the packets
local decEthType 	= 1

local decPacketLen	= 60
local encapsulationLen	= 14 + 20 + 8 + 8 -- Eth, IP, UDP, VXLAN
local encPacketLen 	= encapsulationLen + decPacketLen

function loadSlave(sendTunneled, port, queue)

	local queue = device.get(port):getTxQueue(queue)
	local packetLen
	local mem

	if sendTunneled then
		-- create a with VXLAN encapsulated ethernet packet
		packetLen = encPacketLen
		mem = memory.createMemPool(function(buf)
			buf:getVxlanEthernetPacket():fill{ 
				ethSrc=encRemoteEth, 
				ethDst=encVtepEth, 
				ip4Src=encRemoteIP,
				ip4Dst=encVtepIP,

				vxlanVNI=VNI,

				innerEthSrc=decVtepEth,
				innerEthDst=decRemoteEth,
				innerEthType=decEthType,

				pktLength=encPacketLen 
			}
		end)
	else
		-- create an ethernet packet
		packetLen = decPacketLen
		mem = memory.createMemPool(function(buf)
			buf:getEthernetPacket():fill{ 
				ethSrc=decRemoteEth,
				ethDst=decVtepEth,
				ethType=decEthType,

				pktLength=decPacketLen 
			}
		end)

	end

	local bufs = mem:bufArray()
	local c = 0

	local txStats = stats:newDevTxCounter(queue, "plain")
	while mg.running() do
		-- fill packets and set their size 
		bufs:alloc(packetLen)
		
		-- dump first packet to see what we send
		if c < 1 then
			bufs[1]:dump()
			c = c + 1
		end 
		
		if sendTunneled then
			--offload checksums to NIC
			bufs:offloadUdpChecksums()
		end
		
		queue:send(bufs)
		txStats:update()
	end
	txStats:finalize()
end

--- Checks if the content of a packet parsed as Vxlan packet indeed fits with a Vxlan packet
--- @param pkt A buffer parsed as Vxlan packet
--- @return true if the content fits a Vxlan packet (etherType, ip4Proto and udpDst fit)
function isVxlanPacket(pkt)
	return pkt.eth:getType() == proto.eth.TYPE_IP 
		and pkt.ip4:getProtocol() == proto.ip4.PROTO_UDP 
		and pkt.udp:getDstPort() == proto.udp.PORT_VXLAN
end

function counterSlave(receiveInner, dev)
	rxStats = stats:newDevRxCounter(dev, "plain")
	local bufs = memory.bufArray(1)
	local c = 0

	while mg.running() do
		local rx = dev:getRxQueue(0):recv(bufs)
		if rx > 0 then
			local buf = bufs[1]
			if receiveInner then
				-- any ethernet frame
				local pkt = buf:getEthernetPacket()
				if c < 1 then
					printf(red("Received"))
					buf:dump()
					c = c + 1
				end
			else
				local pkt = buf:getVxlanEthernetPacket()
				-- any vxlan packet
				if isVxlanPacket(pkt) then
					if c < 1 then
						printf(red("Received"))
						buf:dump()
						c = c + 1
					end
				end
			end

			bufs:freeAll()
		end
		rxStats:update()
	end
	rxStats:finalize()
end

function decapsulateSlave(rxDev, txPort, queue)
	local txDev = device.get(txPort)

	local mem = memory.createMemPool(function(buf)
		buf:getRawPacket():fill{ 
			-- we take everything from the received encapsulated packet's payload
		}
	end)
	local rxBufs = memory.bufArray()
	local txBufs = mem:bufArray()

	local rxStats = stats:newDevRxCounter(rxDev, "plain")
	local txStats = stats:newDevTxCounter(txDev, "plain")

	local rxQ = rxDev:getRxQueue(0)
	local txQ = txDev:getTxQueue(queue)
	
	log:info("Starting vtep decapsulation task")
	while mg.running() do
		local rx = rxQ:tryRecv(rxBufs, 0)
		
		-- alloc empty tx packets
		txBufs:allocN(decPacketLen, rx)
		
		for i = 1, rx do
			local rxBuf = rxBufs[i]
			local rxPkt = rxBuf:getVxlanPacket()
			-- if its a vxlan packet, decapsulate it
			if isVxlanPacket(rxPkt) then
				-- use template raw packet (empty)
				local txPkt = txBufs[i]:getRawPacket()
			
				-- get the size of only the payload
				local payloadSize = rxBuf:getSize() - encapsulationLen
				
				-- copy payload
				ffi.copy(txPkt.payload, rxPkt.payload, payloadSize)

				-- update buffer size
				txBufs[i]:setSize(payloadSize)
			end
		end
		-- send decapsulated packet
		txQ:send(txBufs)
		
		-- free received packet                                         
                rxBufs:freeAll()	
		
		-- update statistics
		rxStats:update()
		txStats:update()
	end
	rxStats:finalize()
	txStats:finalize()
end

function encapsulateSlave(rxDev, txPort, queue)	
	local txDev = device.get(txPort)
	
	local mem = memory.createMemPool(function(buf)
		buf:getVxlanPacket():fill{ 
			-- the outer packet, basically defines the VXLAN tunnel 
			ethSrc=encVtepEth, 
			ethDst=encRemoteEth, 
			ip4Src=encVtepIP,
			ip4Dst=encRemoteIP,
			
			vxlanVNI=VNI,}
	end)
	
	local rxBufs = memory.bufArray()
	local txBufs = mem:bufArray()

	local rxStats = stats:newDevRxCounter(rxDev, "plain")
	local txStats = stats:newDevTxCounter(txDev, "plain")
	
	local rxQ = rxDev:getRxQueue(0)
	local txQ = txDev:getTxQueue(queue)
	
	log:info("Starting vtep encapsulation task")
	while mg.running() do
		local rx = rxQ:tryRecv(rxBufs, 0)
		
		-- alloc "rx" tx packets with VXLAN template
		-- In the end we only want to send as many packets as we have received in the first place.
		-- In case this number would be lower than the size of the bufArray, we would have a memory leak (only sending frees the buffer!).
		-- allocN implicitly resizes the bufArray to that all operations like checksum offloading or sending the packets are only done for the packets that actually exist (would crash otherwise)
		txBufs:allocN(encPacketLen, rx)
		
		-- check if we received any packets
		for i = 1, rx do
			-- we encapsulate everything that gets here. One could also parse it as ethernet frame and then only encapsulate on matching src/dst addresses
			local rxPkt = rxBufs[i]:getRawPacket()
			
			-- size of the packet
			local rawSize = rxBufs[i]:getSize()
			
			-- use template VXLAN packet
			local txPkt = txBufs[i]:getVxlanPacket()

			-- copy raw payload (whole frame) to encapsulated packet payload
			ffi.copy(txPkt.payload, rxPkt.payload, rawSize)

			-- update size
			local totalSize = encapsulationLen + rawSize
			-- for the actual buffer
			txBufs[i]:setSize(totalSize)
			-- for the IP/UDP header
			txPkt:setLength(totalSize)
		end
		-- offload checksums
		txBufs:offloadUdpChecksums()

		-- send encapsulated packet
		txQ:send(txBufs)
		
		-- free received packet
		rxBufs:freeAll()
	
		-- update statistics
		txStats:update()
		rxStats:update()
	end
	rxStats:finalize()
	txStats:finalize()
end
