local FnLib = require(game.ReplicatedStorage.FunctionLibrary)

local Players = game:GetService("Players")
local LocalPlayer = Players.LocalPlayer
local RunService = game:GetService("RunService")
local PhysicsService = game:GetService("PhysicsService")
local TweenService = game:GetService("TweenService")

-- Locate/configure humanoid parts of newly spawned character
local humanoidRP = script.Parent:WaitForChild("HumanoidRootPart")
local humanoid = humanoidRP.Parent.Humanoid
humanoid.BreakJointsOnDeath = false
humanoid.JumpHeight = 0


-- Delete humanoid accessories, disable touch events on it, and prevent late clothes spawns
wait()
for i, object in humanoidRP.Parent:GetChildren() do
	if object.ClassName == "Accessory" then
		if (object:FindFirstChild("Handle"))  then
			object:FindFirstChild("Handle").Transparency = 1
		end
	elseif object.ClassName == "Part" and not (object.Name == "HumanoidRootPart") then
		if object.Name == "Head" then
			object:FindFirstChildOfClass("Decal"):Destroy()
		end
		object.CanTouch = false
		object.Transparency = 0.5
		object.CustomPhysicalProperties = PhysicalProperties.new(0.01, 1, 1)
	end
end

-- For late spawns: They are probably accessories, try to hide them using some reverse engineering
humanoidRP.Parent.ChildAdded:Connect(function(object)
	if object.ClassName == "Accessory" then
		if (object:WaitForChild("Handle", 1))  then
			object:FindFirstChild("Handle").Transparency = 1
		end
	end
end)

--[[TODO: Transparency value dependent on player setting]]
-- Doesn't do anything to body parts in R15, but we'll keep this intentional