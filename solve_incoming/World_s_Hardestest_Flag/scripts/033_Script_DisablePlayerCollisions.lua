-- Credit: Roblox Documentation
-- Source: https://create.roblox.com/docs/building-and-visuals/physics/collision-filtering

local PhysicsService = game:GetService("PhysicsService")
local Players = game:GetService("Players")


local function onDescendantAdded(descendant)
	-- Set collision group for any part descendant
	if descendant:IsA("BasePart") then
		descendant.CollisionGroup = "Characters"
	end
end

local function onCharacterAdded(character)
	-- Process existing and new descendants for physics setup
	for _, descendant in pairs(character:GetDescendants()) do
		onDescendantAdded(descendant)
	end
	character.DescendantAdded:Connect(onDescendantAdded)
end

Players.PlayerAdded:Connect(function(player)
	-- Detect when the player's character is added
	player.CharacterAdded:Connect(onCharacterAdded)
end)