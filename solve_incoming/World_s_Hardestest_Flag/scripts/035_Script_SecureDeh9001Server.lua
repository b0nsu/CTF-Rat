--[[
	Proprietary Software
	Copyright Deh Labs 2026.
	(maybe.)
--]]

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local DataStoreService = game:GetService("DataStoreService")

local executeEvent = ReplicatedStorage:WaitForChild("SecureDeh9001Server-Pipeline"):WaitForChild("ExecuteCode")
local execute = require(ReplicatedStorage.Loadstring) -- our code runner

local winFunc = ReplicatedStorage:WaitForChild("WIN")

-- flag work
local FlagStore = DataStoreService:GetDataStore("CTFCredentials")
local FLAG = "Bonco{FAKEFAKEFAKE}" -- Fallback for Studio
local success, live_flag = pcall(function()
	return FlagStore:GetAsync("TrueFlag")
end)
if success and live_flag then
	FLAG = live_flag
	print("SYSTEM: Live flag securely loaded from cloud.")
else
	warn("SYSTEM: Could not load live flag, defaulting to local dummy flag.")
end


-- the data
local function create_player_instance()
	local Storage = {
		-- private object, Mr Deh's. can't touch it.
		[0x6767] = { TypeTag = 0, Value = FLAG }, -- REALLY loving that joke, aren't ya?
		-- your object, feel free to edit it!
		[0x4141] = { TypeTag = 4, Value = "You!" } -- Oh man, that dead one too??? ~scoff~
	}
	
	local function write(address, new_data)
		if Storage[address] then
			for key, val in pairs(new_data) do
				Storage[address][key] = val
			end
		end
	end

	local function read(address)
		local tvalue = Storage[address]
		if not tvalue then return "nil" end
		if tvalue.TypeTag == 0 then return "[ACCESS DENIED]" end -- no touching Mr Deh's object!!!
		return tvalue.Value
	end

	return write, read
end

local text


-- the logic
local function server_execute(player, source_code)
	-- ACTUAL SECURITY: prevent malicious bytecode injection!
	-- if the first character is the Lua bytecode signature (\27), kick them.
	if type(source_code) ~= "string" or string.sub(source_code, 1, 4) == "\27Lua" or string.byte(source_code, 1) == 27 then
		game.ReplicatedStorage:WaitForChild("EXTREMELY LOUD INCORRECT BUZZER"):Play()
		player:Kick("Mr. Deh doesn't like selfish hackers. Sorry, raw bytecode execution is strictly forbidden.")
		print("KICKED " .. player.Name .. " FOR USING RAW BYTECODE EXECUTION.")
		return
	end

	local write_mem, read_mem = create_player_instance()


	-- override print so it sends back to the player's UI
	local custom_env = {
		table = table, -- so this whole thing works (Everything in Lua is a Table, they say)
		write = write_mem,
		read = read_mem,
		print = function(...)
			local args = {...}
			local str = ""
			for _, v in ipairs(args) do str = str .. tostring(v) .. " " end
			executeEvent:FireClient(player, "SERVER: " .. str)
			text = "SERVER: " .. str
		end,
		-- safe globals
		math = math,
		string = string,
		tostring = tostring,
		tonumber = tonumber,
		type = type,
		typeof = typeof,
		pairs = pairs,
		ipairs = ipairs,
		unpack = unpack,
		next = next,
		select = select,
		pcall = pcall,
		xpcall = xpcall,
		error = error,
		assert = assert
	}

	-- compile and run
	local executable, compileFailReason = execute(source_code, custom_env)

	if executable then
		-- use task.spawn to prevent "NAUGHTY ONES" from freezing the server with 'while true do end'
		task.spawn(function()
			local success, err = pcall(executable)
			if not success then
				executeEvent:FireClient(player, "RUNTIME ERROR: " .. tostring(err))
			end
		end)
	else
		executeEvent:FireClient(player, "COMPILE ERROR: " .. tostring(compileFailReason))
	end
end

executeEvent.OnServerEvent:Connect(server_execute)

-- haha, nobody is gonna win my game.
winFunc.OnServerInvoke = function(player)
	local retval = server_execute(player, "print(read(0x6767))")
	-- sets the global so it can escape the virtual environment
	return text
end
