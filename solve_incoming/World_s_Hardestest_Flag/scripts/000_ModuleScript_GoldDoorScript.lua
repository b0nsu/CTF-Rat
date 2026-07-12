-- GoldDoor Script
local TweenService = game:GetService("TweenService")

local GoldDoor = {}

local openSound = game.ReplicatedStorage.Door
local coinCount = script.Parent.CoinGateGui.CoinIcon.CoinCount

local doors = {}
table.insert(doors, script.Parent)

local doorSizes = {}
table.insert(doorSizes, script.Parent.Size)

local doorPositions = {}
table.insert(doorPositions, script.Parent.Position)

local function createTween(which, obj, index)
	local goal = {}
	local object = obj
	local easing = Enum.EasingStyle.Quad
	local easingDir = Enum.EasingDirection.Out
	local length = 1
	local reverse = false

	if (which == "open size") then
		object = obj
		goal.Size = doorSizes[index] * Vector3.new(0, 1, 1)
	elseif (which == "close size") then
		object = obj
		goal.Size = doorSizes[index]
	elseif (which == "open pos") then
		object = obj
		goal.Position = doorPositions[index] + Vector3.new(doorSizes[index].X / 2, 0, 0)
	elseif (which == "close pos") then
		object = obj
		goal.Position = doorPositions[index]
	end

	local tweenInfo = TweenInfo.new(length, easing, easingDir, 0, reverse, 0)
	return (TweenService:Create(object, tweenInfo, goal))
end

GoldDoor.Update = function(p)
	local maxCoins = script.Parent.Parent.LevelData:GetAttribute("MaxCoins")
	local collectedCoins = p.moneydata:GetAttribute("Money")
	
	if collectedCoins >= maxCoins then
		GoldDoor.Open()
		coinCount.Text = "Open"
	else
		GoldDoor.Close()
		local builtString = (tostring(maxCoins - collectedCoins))
		coinCount.Text = builtString
	end
	
end

-- only used in update
GoldDoor.Open = function()
	openSound:Play()
	for index = 1, #doors do
		createTween("open size", doors[index], index):Play()
		createTween("open pos", doors[index], index):Play()
		createTween("open detail", doors[index], index):Play()
	end
end

-- only used in update
GoldDoor.Close = function()
	for index = 1, #doors do
		createTween("close size", doors[index], index):Play()
		createTween("close pos", doors[index], index):Play()
		createTween("close detail", doors[index], index):Play()
	end	
end

return GoldDoor