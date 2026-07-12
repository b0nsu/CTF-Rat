local Players = game:GetService("Players")

local function leaderboardSetup(player)
	local leaderstats = Instance.new("Folder")
	leaderstats.Name = "leaderstats"
	leaderstats.Parent = player
	local deaths = Instance.new("IntValue")
	deaths.Name = "Deaths"
	deaths.Value = 0
	deaths.Parent = leaderstats
	local level = Instance.new("StringValue")
	level.Name = "Level"
	level.Value = "Start" -- level, room (divergence)
	level.Parent = leaderstats
	
	local deathdata = Instance.new("Configuration")
	deathdata.Name = "deathdata"
	deathdata.Parent = player
	deathdata:SetAttribute("Deaths", 0)
	deathdata:SetAttribute("DeathsTotal", 0)
	
	local cpdata = Instance.new("Configuration")
	cpdata.Name = "cpdata"
	cpdata.Parent = player
	cpdata:SetAttribute("Level", "Start")
	cpdata:SetAttribute("Checkpoint", 0)
	--[[local checkpoint = Instance.new("IntValue")
	checkpoint.Name = "Checkpoint"
	checkpoint.Value = 0
	checkpoint.Parent = cpdata]]
	
	local moneydata = Instance.new("Configuration")
	moneydata.Name = "moneydata"
	moneydata.Parent = player
	moneydata:SetAttribute("Money", 0)
	moneydata:SetAttribute("MoneyTotal", 0)
	--[[local money = Instance.new("NumberValue")
	money.Name = "Money"
	money.Value = 0
	money.Parent = moneydata
	local moneyTotal = Instance.new("IntValue")
	moneyTotal.Name = "MoneyTotal"
	moneyTotal.Value = 0
	moneyTotal.Parent = moneydata]]
	
	local vitals = Instance.new("Configuration")
	vitals.Name = "vitals"
	vitals.Parent = player
	vitals:SetAttribute("AirLoss", 0)
	vitals:SetAttribute("SlideAmt", 0)
	vitals:SetAttribute("ChargeAmt", 0)
	--[[local airLoss = Instance.new("NumberValue")
	airLoss.Name = "AirLoss"
	airLoss.Value = 0
	airLoss.Parent = vitals
	local slideAmt = Instance.new("NumberValue")
	slideAmt.Name = "SlideAmt"
	slideAmt.Value = 0
	slideAmt.Parent = vitals
	local heatAmt = Instance.new("NumberValue")
	heatAmt.Name = "ChargeAmt"
	heatAmt.Value = 0
	heatAmt.Parent = vitals]]
end

-- Connect the "leaderboardSetup()" function to the "PlayerAdded" event
Players.PlayerAdded:Connect(leaderboardSetup)