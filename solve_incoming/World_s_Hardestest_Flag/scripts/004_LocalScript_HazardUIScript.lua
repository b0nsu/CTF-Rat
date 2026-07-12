local FnLib = require(game.ReplicatedStorage.FunctionLibrary)

local Players = game:GetService("Players")
local TweenService = game:GetService("TweenService")

local LocalPlayer = Players.LocalPlayer

local leaderstats = LocalPlayer:WaitForChild("leaderstats")
wait()

local airGui = script.Parent.Air
local slideGui = script.Parent.Slide
local superchargeGui = script.Parent.Supercharge

local vitals = LocalPlayer.vitals

local airSound = airGui.WaterSplash
local lowAirSound = airGui.LowAir
local airEntry = true
local airTweenUp
local airTweenDown
local airTweenShake
local airPrev = 0

local slideSound = slideGui.WindWoosh
local slideSoundHigh = slideGui.SlideBeep
local slideSoundMax = slideGui.IceCrack
local slideEntry = true
local slideMax = false
local slideTweenUp
local slideTweenDown
local slideTweenPulse1
local slideTweenPulse2
local slidePrev = 0

local chargeSound = superchargeGui.LightningFlash
local chargeSoundHigh = superchargeGui.ChargeBeep
local chargeSoundMax = superchargeGui.ElectricDischarge
local chargeEntry = true
local chargeMax = false
local chargeTweenUp
local chargeTweenDown
local chargeTweenPulse
local chargePrev = 0

local function createTween(which, direction, num1, num2)
	-- Helper FN: Creates tweens for the hazard GUI move up/down
	local posX
	local targetGui
	local length = 0.25
	local easingStyle = Enum.EasingStyle.Quad
	local reverse = false
	
	if (which == "air") then
		posX = 0.5
		targetGui = airGui
	elseif (which == "slide") then
		posX = 0.3
		targetGui = slideGui
	elseif (which == "charge") then
		posX = 0.7
		targetGui = superchargeGui
	end

	local goal = {}
	if (direction == "up") then
		goal.Position = UDim2.new(posX, 0, 1, -20)
	elseif (direction == "down") then
		goal.Position = UDim2.new(posX, 0, 1, 50)
	elseif (direction == "shake") then
		goal.Position = UDim2.new(posX, num1, 1, -20 - num2)
		length -= 0.2
		easingStyle = Enum.EasingStyle.Linear
		reverse = true
	elseif (direction == "pulse") then
		targetGui = targetGui.RedFX
		goal.ImageTransparency = num1
		length += num2
		easingStyle = Enum.EasingStyle.Linear
		reverse = true
	end
	
	local tweenInfo = TweenInfo.new(length, easingStyle, Enum.EasingDirection.Out, 0, reverse, 0)
	return (TweenService:Create(targetGui, tweenInfo, goal))
end

airTweenUp = createTween("air", "up")
airTweenDown = createTween("air", "down")
airTweenShake = createTween("air", "shake", 1, 1)
slideTweenUp = createTween("slide", "up")
slideTweenDown = createTween("slide", "down")
slideTweenPulse1 = createTween("slide", "pulse", 0.5, 0)
slideTweenPulse2 = createTween("slide", "pulse", 0, 0.75)
chargeTweenUp = createTween("charge", "up")
chargeTweenDown = createTween("charge", "down")
chargeTweenPulse1 = createTween("charge", "pulse", 0.5, 0)
chargeTweenPulse2 = createTween("charge", "pulse", 0, 0.75)

wait()

local function airActions()
	airGui.Value.Text = (tostring(math.round(100 - vitals:GetAttribute("AirLoss"))) .. "%")
	airGui.Bar.Size = UDim2.fromScale(math.round(100 - vitals:GetAttribute("AirLoss")) * 0.01, 1)

	if airEntry and FnLib.isNumberHigher(vitals:GetAttribute("AirLoss"), airPrev) and not (vitals:GetAttribute("AirLoss") == 0 or airPrev <= 0 or airPrev >= 99) then
		airSound:Play()
		airTweenUp:Play()
		--airBorderFlash:Play()
		airEntry = false

		airSound.Ended:Once(function()
			airSound.Volume = 0.25
			if vitals:GetAttribute("AirLoss") == 0 then
				airSound.Volume = 0.5
			end
		end)
	end

	if not (FnLib.isNumberHigher(vitals:GetAttribute("AirLoss"), airPrev)) then
		airEntry = true
	end

	if vitals:GetAttribute("AirLoss") == 0 then
		airTweenDown:Play()
		airSound.Volume = 0.5
	end

	if not airEntry and vitals:GetAttribute("AirLoss") > 75 then
		if not (airTweenShake.PlaybackState == Enum.PlaybackState.Playing) then
			airTweenShake = createTween("air", "shake", (vitals:GetAttribute("AirLoss") - 70.0) * (math.random() - 0.5) / 2, (vitals:GetAttribute("AirLoss") - 70.0) * (math.random()) / 2)
			airTweenShake:Play()
		end
		if not lowAirSound.Playing then
			lowAirSound:Play()
		end
	end

	if vitals:GetAttribute("AirLoss") >= 100 then
		airGui.ImageColor3 = Color3.fromRGB(100, 0, 0)
	end

	airPrev = vitals:GetAttribute("AirLoss")
end

local function slideActions()
	slideGui.Value.Text = (tostring(math.round(vitals:GetAttribute("SlideAmt"))) .. "%")
	slideGui.Bar.Size = UDim2.fromScale(math.round(vitals:GetAttribute("SlideAmt")) * 0.01, 1)

	if slideEntry and FnLib.isNumberHigher(vitals:GetAttribute("SlideAmt"), slidePrev) and not (vitals:GetAttribute("SlideAmt") == 0 or slidePrev <= 0 or slidePrev >= 99) then
		slideSound:Play()
		slideTweenUp:Play()
		--slideBorderFlash:Play()
		slideEntry = false

		slideSound.Ended:Once(function()
			slideSound.Volume = 0.5
			if vitals:GetAttribute("SlideAmt") == 0 then
				slideSound.Volume = 1
			end
		end)
	end

	if not (FnLib.isNumberHigher(vitals:GetAttribute("SlideAmt"), slidePrev)) then
		slideEntry = true
	end

	if vitals:GetAttribute("SlideAmt") == 0 then
		slideTweenDown:Play()
		slideSound.Volume = 1
	end

	if not slideEntry and vitals:GetAttribute("SlideAmt") > 75 then
		if not (slideTweenPulse1.PlaybackState == Enum.PlaybackState.Playing) then
			slideTweenPulse2:Cancel()
			slideGui.RedFX.ImageTransparency = 1
			slideTweenPulse1:Play()
		end
		if not slideSoundHigh.Playing then
			slideSoundHigh:Play()
		end
	end

	if vitals:GetAttribute("SlideAmt") >= 99 then
		if not (slideTweenPulse2.PlaybackState == Enum.PlaybackState.Playing) then
			slideTweenPulse1:Cancel()
			slideGui.RedFX.ImageTransparency = 1
			slideTweenPulse2:Play()
		end
		if not (slideSoundMax.Playing) then
			slideSoundMax:Play()
		end
	else
		slideSoundMax:Stop()
	end

	slidePrev = vitals:GetAttribute("SlideAmt")
end

local function chargeActions()
	superchargeGui.Value.Text = (tostring(math.round(vitals:GetAttribute("ChargeAmt"))) .. "%")
	superchargeGui.Bar.Size = UDim2.fromScale(math.round(vitals:GetAttribute("ChargeAmt")) * 0.01, 1)

	if chargeEntry and FnLib.isNumberHigher(vitals:GetAttribute("ChargeAmt"), chargePrev) and not (vitals:GetAttribute("ChargeAmt") == 0 or chargePrev <= 0 or chargePrev >= 99) then
		chargeSound:Play()
		chargeTweenUp:Play()
		--chargeBorderFlash:Play()
		chargeEntry = false

		chargeSound.Ended:Once(function()
			chargeSound.Volume = 0.25
			if vitals:GetAttribute("ChargeAmt") == 0 then
				chargeSound.Volume = 0.5
			end
		end)
	end

	if not (FnLib.isNumberHigher(vitals:GetAttribute("ChargeAmt"), chargePrev)) then
		chargeEntry = true
	end

	if vitals:GetAttribute("ChargeAmt") == 0 then
		chargeTweenDown:Play()
		chargeSound.Volume = 0.5
	end

	if not chargeEntry and vitals:GetAttribute("ChargeAmt") > 75 then
		if not (chargeTweenPulse1.PlaybackState == Enum.PlaybackState.Playing) then
			chargeTweenPulse2:Cancel()
			superchargeGui.RedFX.ImageTransparency = 1
			chargeTweenPulse1:Play()
		end
		if not chargeSoundHigh.Playing then
			chargeSoundHigh:Play()
		end
	end

	if vitals:GetAttribute("ChargeAmt") >= 99 then
		if not (chargeTweenPulse2.PlaybackState == Enum.PlaybackState.Playing) then
			chargeTweenPulse1:Cancel()
			superchargeGui.RedFX.ImageTransparency = 1
			chargeTweenPulse2:Play()
		end
		if not (chargeSoundMax.Playing) then
			chargeSoundMax:Play()
		end
	else
		chargeSoundMax:Stop()
	end

	chargePrev = vitals:GetAttribute("ChargeAmt")
end

vitals.AttributeChanged:Connect(function(att)
	if (att == "AirLoss") then
		airActions()
	end
	if (att == "SlideAmt") then
		slideActions()
	end
	if (att == "ChargeAmt") then
		chargeActions()
	end
end)