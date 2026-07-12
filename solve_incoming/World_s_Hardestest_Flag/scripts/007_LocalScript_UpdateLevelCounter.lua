local FnLib = require(game.ReplicatedStorage.FunctionLibrary)

local Players = game:GetService("Players")
local LocalPlayer = Players.LocalPlayer
local TweenService = game:GetService("TweenService")

local cpData = LocalPlayer.cpdata

local levelCount = script.Parent:WaitForChild("LevelCount")
local levelPrefix = "Level: "

local divergenceCount = script.Parent:WaitForChild("DivergenceInfoHolder").DivergenceCount
local divergenceIcon = script.Parent:WaitForChild("DivergenceIcon")
local divergencePrefix = "Room: "

local dPersist = false


local function makeTween(which)
	local goal = {}
	if (which == "down") then
		goal.Position = UDim2.new(0.25, 0, 0, 35)
	elseif (which == "up") then
		goal.Position = UDim2.new(0.25, 0, 0, 0)
	end
	
	local length = 1
	local easing = Enum.EasingStyle.Quint

	local tweenInfo = TweenInfo.new(length, easing, Enum.EasingDirection.Out, 0, false, 0)
	return (TweenService:Create(divergenceCount.Parent, tweenInfo, goal))
end

local dcDown = makeTween("down")
local dcUp = makeTween("up")

local function showLevel()
	dcUp:Cancel()
	dcDown:Cancel()
	dcDown:Play()
end

local function updateText()
	local l, r = FnLib.splitLvlName(cpData:GetAttribute("Level"))
	if (r == nil) then
		r = "None"
	end
	levelCount.Text = levelPrefix .. l
	divergenceCount.Text = divergencePrefix .. r
end

updateText()

cpData.AttributeChanged:Connect(function(att)
	if (att == "Level") then
		updateText()
		showLevel()
		wait(1.5)
		if not (dcDown.PlaybackState == Enum.PlaybackState.Playing) then
			dcUp:Play()
		end
	end	
end)

divergenceIcon.Activated:Connect(function()
	updateText()
	showLevel()
	wait(1.5)
	if not (dcDown.PlaybackState == Enum.PlaybackState.Playing) then
		dcUp:Play()
	end
end)
-- Wait parts must be out of the dcUp/dcDown functions