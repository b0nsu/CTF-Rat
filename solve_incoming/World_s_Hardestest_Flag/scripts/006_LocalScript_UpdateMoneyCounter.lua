local Players = game:GetService("Players")
local LocalPlayer = Players.LocalPlayer

--local leaderstats = LocalPlayer:WaitForChild("leaderstats")

local moneyCount = script.Parent:WaitForChild("MoneyCount")
local moneyData = LocalPlayer.moneydata

moneyCount.Text = moneyData:GetAttribute("Money")

moneyData.AttributeChanged:Connect(function(att)
	if (att == "Money") then
		moneyCount.Text = moneyData:GetAttribute("Money")
	end
end)
