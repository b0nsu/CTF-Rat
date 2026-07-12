local TweenService = game:GetService("TweenService")
local Players = game:GetService("Players")

local LocalPlayer = Players.LocalPlayer

local LocalCamera = workspace.CurrentCamera

local fovEntry = script.Parent.FOVEntry
local fovWarning = script.Parent.FOVWarning
local fovSafetyButton = script.Parent.FOVSafetyButton
fovEntry.Text = LocalCamera.FieldOfView

local musicButton = script.Parent.MusicButton
local music = LocalPlayer.PlayerScripts:WaitForChild("Music")

local pointerButton = script.Parent.PointerButton
local pointerGui = script.Parent.Parent.Parent:WaitForChild("MouseoverPath")

-- Actual settings
-- TODO: DataStore Save
local fovSafetyState = true
local musicState = 1
local pointerState = 1

local function createGuiTween(which, obj, param1, param2, param3, param4)
	local goal = {}
	local object
	local easing = Enum.EasingStyle.Cubic
	local easingDir = Enum.EasingDirection.Out
	local length = 0.5
	local repeatCount = 0
	local reverse = false

	if (which == "fovwarn") then
		goal.TextTransparency = 0
		goal.TextStrokeTransparency = 0
		object = obj --fovWarning
		easing = Enum.EasingStyle.Linear
		length = 0.15
		repeatCount = 2
		reverse = true
	elseif (which == "fovchange") then
		goal.FieldOfView = param1
		object = obj --LocalCamera
		length = 0.75
	elseif (which == "musictween") then
		goal.Volume = param1
		object = obj
	elseif (which == "buttonpress") then
		goal.Position = param1
		goal.BackgroundColor3 = param2
		object = obj
	end
	
	local tweenInfo = TweenInfo.new(length, easing, easingDir, repeatCount, reverse, 0)
	return (TweenService:Create(object, tweenInfo, goal))
end

fovEntry.FocusLost:Connect(function()
	local extremeNumberEntered = false
	if (tonumber(fovEntry.Text) < 10) then
		fovWarning.Text = "WARNING: TOO LOW"
		createGuiTween("fovwarn", fovWarning):Play()
		extremeNumberEntered = true
	elseif ((tonumber(fovEntry.Text) > 15)) then
		fovWarning.Text = "WARNING: TOO HIGH"
		createGuiTween("fovwarn", fovWarning):Play()
		extremeNumberEntered = true
	end
	if not (extremeNumberEntered and fovSafetyState) then
		print("GO CHANGE FOV")
		local fov = tonumber(fovEntry.Text)
		createGuiTween("fovchange", LocalCamera, fov):Play()
	end
end)

fovSafetyButton.Activated:Connect(function()
	if (fovSafetyState) then
		fovSafetyState = false
		fovSafetyButton.Text = "Safety OFF"
		createGuiTween("buttonpress", fovSafetyButton, UDim2.fromScale(0.87, 0.25), Color3.fromRGB(255,0,0)):Play()
	else
		fovSafetyState = true
		fovSafetyButton.Text = "Safety ON"
		createGuiTween("buttonpress", fovSafetyButton, UDim2.fromScale(0.95, 0.25), Color3.fromRGB(55,255,0)):Play()
	end
end)

musicButton.Activated:Connect(function()
	if (musicState == 0) then
		musicState = 1
		createGuiTween("musictween", music, 0.02):Play()
		musicButton.Text = "ON"
		createGuiTween("buttonpress", musicButton, UDim2.fromScale(0.95, 0.4), Color3.fromRGB(55,255,0)):Play()

		
	elseif (musicState == 1) then
		musicState = 0
		createGuiTween("musictween", music, 0):Play()
		musicButton.Text = "OFF"
		createGuiTween("buttonpress", musicButton, UDim2.fromScale(0.79, 0.4), Color3.fromRGB(255,0,0)):Play()
		
	--[[elseif (musicState == 2) then
		
	elseif (musicState == 3) then
		
	else]]

	end
end)

pointerButton.Activated:Connect(function()
	if (pointerState == 0) then
		pointerState = 1
		pointerGui.Enabled = true
		pointerButton.Text = "ON"
		createGuiTween("buttonpress", pointerButton, UDim2.fromScale(0.95, 0.55), Color3.fromRGB(55,255,0)):Play()


	elseif (pointerState == 1) then
		pointerState = 0
		pointerGui.Enabled = false
		pointerButton.Text = "OFF"
		createGuiTween("buttonpress", pointerButton, UDim2.fromScale(0.79, 0.55), Color3.fromRGB(255,0,0)):Play()

	end
end)

--[[
Aint no way discrete math is actually helping here
Extreme	Safety	Result
T		T		F
T		F		T
F		T		T
F		F		T
Equation wanted: !(E && S)
]]