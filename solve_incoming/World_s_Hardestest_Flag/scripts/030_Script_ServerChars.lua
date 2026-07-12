local Players = game:GetService("Players")
local RunService = game:GetService("RunService")

local updateEvent = game.ReplicatedStorage.PositionUpdate
local requestFunction = game.ReplicatedStorage.RequestChar

local REGULAR_PLAYER_Y = 1.02
local CFRAME_ROTATOR = CFrame.Angles(0,0,math.pi*(-0.5))

local function updatePos(name, coords, humanoid, serverCharObj) -- name, coords, humanoid
	serverCharObj:PivotTo(CFrame.new(coords.X, REGULAR_PLAYER_Y, coords.Z) * CFRAME_ROTATOR)
end

Players.PlayerAdded:Connect(function(player)
	local serverCharObj
	
	player.CharacterAdded:Connect(function(c)
		local humanoidRP = c.HumanoidRootPart
		
		-- clone player object in ServerStorage
		serverCharObj = game.ReplicatedStorage.Char:Clone()
		local name = ("ServerChar" .. player.Name)
		serverCharObj.Name = name
				
		-- place in game
		serverCharObj.Parent = workspace.ServerChars
		
		updateEvent.OnServerEvent:Connect(function(p, charName, coords, humanoid) -- player is default 1st parameter
			if serverCharObj.Name:match(tostring(p)) then
				wait(0.25)
				updatePos(name, coords, humanoid, serverCharObj)
			end
		end)
	end)
	
	player.CharacterRemoving:Connect(function(c)
		serverCharObj:Destroy()
	end)
end)

function requestFunction.OnServerInvoke(p)
	local name = ("ServerChar" .. p.Name)
	return workspace.ServerChars:FindFirstChild(name)
end