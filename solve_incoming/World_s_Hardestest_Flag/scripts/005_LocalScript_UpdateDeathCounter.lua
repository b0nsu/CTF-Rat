local Players = game:GetService("Players")
local LocalPlayer = Players.LocalPlayer

--local leaderstats = LocalPlayer:WaitForChild("leaderstats")

local deathCount = script.Parent:WaitForChild("DeathCount")
local deathData = LocalPlayer.deathdata

deathCount.Text = deathData:GetAttribute("Deaths")

deathData.AttributeChanged:Connect(function(att)
	if (att == "Deaths") then
		deathCount.Text = deathData:GetAttribute("Deaths")
	end
end)
