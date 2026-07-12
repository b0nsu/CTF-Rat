local deathEvent = game.ReplicatedStorage.DeathEvent
local moneyEvent = game.ReplicatedStorage.MoneyEvent

deathEvent.OnServerEvent:Connect(function(p, hazardType)
	local folder = p:FindFirstChild("leaderstats")
	local deaths = folder:FindFirstChild("Deaths")
	deaths.Value += 1
	
	local deathdata = p:FindFirstChild("deathdata")
	
	deathdata:SetAttribute("Deaths", deathdata:GetAttribute("Deaths") + 1)
	deathdata:SetAttribute("DeathsTotal", deathdata:GetAttribute("DeathsTotal") + 1)

end)

moneyEvent.OnServerEvent:Connect(function(p, coinAmt) -- TODO: Another parameter testing =for Old Coin (value div by 100)
	local moneydata = p:FindFirstChild("moneydata")
	
	moneydata:SetAttribute("Money", moneydata:GetAttribute("Money") + coinAmt)
	moneydata:SetAttribute("MoneyTotal", moneydata:GetAttribute("MoneyTotal") + coinAmt)
end)
