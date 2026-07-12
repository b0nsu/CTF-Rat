local FnLib = require(game.ReplicatedStorage.FunctionLibrary)

local Players = game:GetService("Players")
local RunService = game:GetService("RunService")
local PhysicsService = game:GetService("PhysicsService")

local LocalPlayer = Players.LocalPlayer
local ls = LocalPlayer:WaitForChild("leaderstats")
local level = ls:WaitForChild("Level")
local lvlPrev = "Start"

local levelsFolder = workspace.Levels

local moneydata = LocalPlayer.moneydata
local currentGoldDoor = nil

local function updateGoldDoor()
	if (currentGoldDoor ~= nil) then
		local goldDoorScript = require(currentGoldDoor:FindFirstChild("GoldDoorScript"))
		goldDoorScript.Update(LocalPlayer)
	end
end

wait()
level.Changed:Connect(function()
	print("Loaded " .. level.Value)
	local l, r = FnLib.splitLvlName(level.Value)
	local hazards = FnLib.getGameFolder(l, r, "Hazards")
	
	-- Activate room's stuff
	for _,obj in hazards:GetDescendants() do
		if (obj.Name == "MovementScript") then
			print("found " .. tostring(obj))
			local movementScript = require(obj)
			movementScript.Initialize()
			movementScript.Play(true)
		end
	end
	
	local gdNoDiv = hazards.Parent:FindFirstChild("GoldDoor")
	if gdNoDiv ~= nil then
		currentGoldDoor = gdNoDiv
	else
		currentGoldDoor = hazards.Parent.Parent:FindFirstChild("GoldDoor")
	end
	updateGoldDoor()

	
	print(lvlPrev)
	
	l, r = FnLib.splitLvlName(lvlPrev)
	hazards = FnLib.getGameFolder(l, r, "Hazards")
	
	for _,obj in hazards:GetDescendants() do
		if (obj.Name == "MovementScript") then
			print("found " .. tostring(obj))
			local movementScript = require(obj)
			movementScript.Stop()
		end
	end
	
	lvlPrev = level.Value
	print(level.Value)
	print(lvlPrev)
	
end)

moneydata.AttributeChanged:Connect(function(att)
	if (att == "Money") then
		updateGoldDoor()
	end
end)-- Runs each time a player spawns
workspace.ChildAdded:Connect(function(c)	
	local humanoidRP = c:WaitForChild("HumanoidRootPart")
	local player = Players:GetPlayerFromCharacter(c)
	print(player)

	local ls = player:WaitForChild("leaderstats")
	local playerLvl = ls:WaitForChild("Level")

	local level, room = FnLib.splitLvlName(playerLvl.Value)
	print(level)
	print(room)
	local checkpoints = FnLib.getGameFolder(level, nil, "Checkpoints")
	print(checkpoints)

	local cpData = ls.Parent.cpdata
	print(cpData:GetAttribute("Checkpoint"))

	for _,obj in checkpoints:GetDescendants() do
		if (tostring(cpData:GetAttribute("Checkpoint")) == string.sub(obj.Name, 11)) then
			print("going to CP" .. obj.Name)
			wait()
			humanoidRP:PivotTo(CFrame.new(obj.Position + Vector3.new(0, 12, 0)))
		end
	end
end)