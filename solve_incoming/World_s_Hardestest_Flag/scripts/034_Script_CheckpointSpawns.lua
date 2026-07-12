local FnLib = require(game.ReplicatedStorage.FunctionLibrary)

local Players = game:GetService("Players")

local checkpointEvent = game.ReplicatedStorage.CheckpointEvent
local levelEvent = game.ReplicatedStorage.LevelEvent

local levelsFolder = workspace.Levels

-- Sets player checkpoint value
checkpointEvent.OnServerEvent:Connect(function(p, part)
	print(p)
	print(part)
	local cpData = p.cpdata
	print(cpData:GetAttribute("Level"))
	print(cpData:GetAttribute("Checkpoint"))
	print(part.Parent.Parent.Parent.Name)
	
	if (string.match(part.Name, "CameraTrigger")) then
		-- For no rooms
		if (part.Parent.Parent.Parent.Name == "Levels") then
			print("NO ROOMS")
			local level = part.Parent.Parent.Name
			cpData:SetAttribute("Level", level)
			p.leaderstats.Level.Value = level
		else
			local room = part.Parent.Parent.Name
			local level = part.Parent.Parent.Parent.Name
			local builtString = (level .. " " .. room)
			cpData:SetAttribute("Level", builtString)
			p.leaderstats.Level.Value = builtString
		end
	
	elseif (string.match(part.Name, "Checkpoint")) then
		print("ACCEPTED CP " .. part.Name)
		cpData:SetAttribute("Checkpoint", tonumber(string.sub(part.Name, 11)))
	end
end)

-- Runs each time a player spawns
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