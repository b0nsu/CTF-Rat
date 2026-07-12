local FnLib = require(game.ReplicatedStorage.FunctionLibrary)

local Players = game:GetService("Players")
local RunService = game:GetService("RunService")
local PhysicsService = game:GetService("PhysicsService")
local TweenService = game:GetService("TweenService")
local LocalPlayer = Players.LocalPlayer
local LocalCamera = workspace.CurrentCamera

local updateEvent = game.ReplicatedStorage.PositionUpdate
local deathEvent = game.ReplicatedStorage.DeathEvent
local requestEvent = game.ReplicatedStorage.RequestChar
local checkpointEvent = game.ReplicatedStorage.CheckpointEvent
local moneyEvent = game.ReplicatedStorage.MoneyEvent
local winFunc = game.ReplicatedStorage.WIN

local updateConnection
local charConnection
local touchConnection
local hazardConnection

local swooshSound = game.ReplicatedStorage.Swoosh
local punchSound = game.ReplicatedStorage.Punch
local fallingSound = game.ReplicatedStorage.Falling
local drownSound = game.ReplicatedStorage.Drown
local coinSound = game.ReplicatedStorage.Coin
local saveSound = game.ReplicatedStorage.Save
local keySound = game.ReplicatedStorage.Key
local dehSound = game.ReplicatedStorage.DEH
local dingSound = game.ReplicatedStorage.ElevatorDing

local charHeight = script:WaitForChild("CharHeight")
local CFRAME_ROTATOR = CFrame.Angles(0,0,math.pi*(-0.5))

local spawnTween1
local spawnTween2
local fadeTween
local pitTween

local firstSpawn = true
local canDeath = true
local inTeleport = false

local leaderstats = LocalPlayer:WaitForChild("leaderstats")
local vitals = LocalPlayer:WaitForChild("vitals")

local inWater = false
local inIce = false
local inSupercharger = false
local airLoss
local slideAmt
local chargeAmt
local waterWalkMod = 1
local slideWalkMod = 0
local chargeWalkMod = 1

local cpPrev = "Start"
local camPrev = workspace.Levels.Start.CameraParts.Hider

local blur = Instance.new("BlurEffect")
local color = Instance.new("ColorCorrectionEffect")
blur.Size = 0
blur.Parent = game.Lighting
blur.Enabled = true
color.TintColor = Color3.fromRGB(255,255,255)
color.Parent = game.Lighting
color.Enabled = true



local unsavedCoins = {}
local unsavedKeys = {}
local triggeredEvents = {}

--===========--
-- FUNCTIONS --
--===========--

local function disconnectDestroy(charObj)
	-- Helper FN: Disconnects all in-script event handlers and delete char outline
	updateConnection:Disconnect()
	charConnection:Disconnect()
	touchConnection:Disconnect()
	hazardConnection:Disconnect()
	charObj.Main.Outline:Destroy()
	charObj.Main.Face:Destroy()
end

local function createTween(which, obj1, obj2, obj3)
	-- Helper FN: Creates tweens relevant to this script
	-- There is a lot of tween config stored here!!!
	-- Default values:
	local goal = {}
	local object
	local easing
	local easingDir = Enum.EasingDirection.Out
	local length
	local reverse = false
	
	-- MAIN tweens
	-- Spawning
	if (which == "spawn1") then
		goal.Value = 1.025
		object = obj1
		easing = Enum.EasingStyle.Quad
		length = .5
	elseif (which == "spawn2") then
		goal.Size = Vector3.new(.2, 4, 4)
		object = obj1.Main
		easing = Enum.EasingStyle.Quad
		length = .5
	-- Deaths
	elseif (which == "fade") then
		goal.Transparency = 1
		object = obj1.Main
		easing = Enum.EasingStyle.Linear
		length = 0.5
	elseif (which == "pit") then
		goal.Size = Vector3.new(0, 0, 0)
		object = obj1.Main
		easing = Enum.EasingStyle.Linear
		length = 0.5
	end
	
	-- DYNAMIC tweens
	-- Camera
	if (which == "camera") then
		goal.CFrame = CFrame.lookAt(obj1.Position, obj2.Position)
		object = obj3
		easing = Enum.EasingStyle.Cubic
		length = 0.75
	elseif (which == "hiderPrev") then
		goal.Transparency = 0
		object = obj1
		easing = Enum.EasingStyle.Cubic
		length = 0.5
	elseif (which == "hiderNext") then
		goal.Transparency = 1
		object = obj1
		easing = Enum.EasingStyle.Cubic
		length = 0.5	
	-- Checkpoint part shine
	elseif (which == "shinePart") then
		goal.Color = Color3.new(1,1,1)
		object = obj1
		easing = Enum.EasingStyle.Linear
		length = 0.5
		reverse = true
	-- Deh hit redify
	elseif (which == "dehHit") then
		goal.Size = Vector3.new(0.4,4,4)
		goal.Color = Color3.new(1, 0, 0)
		object = obj1
		easing = Enum.EasingStyle.Quad
		length = 0.25
		reverse = true
	elseif (which == "coinFade") then
		goal.Transparency = 1
		object = obj1
		easing = Enum.EasingStyle.Linear
		length = 0.5
	elseif (which == "coinShow") then
		goal.Transparency = 0
		object = obj1
		easing = Enum.EasingStyle.Linear
		length = 0.5
	end
	
	local tweenInfo = TweenInfo.new(length, easing, easingDir, 0, reverse, 0)
	return (TweenService:Create(object, tweenInfo, goal))
end

local function updatePos(charObj, humanoidRP, humanoid)
	-- FN: Constantly move char to position under humanoid
	charObj:PivotTo(CFrame.new(humanoidRP.CFrame.X, 1.025, humanoidRP.CFrame.Z) * CFRAME_ROTATOR)
	updateEvent:FireServer(charObj.Name, Vector3.new(humanoidRP.CFrame.X, 0, humanoidRP.CFrame.Z), humanoid) -- name, coords, humanoid
end

local function setCamera(obj, camPrev)
	-- FN: Using tweens, move camera to desired orientation
	print(obj)
	print(camPrev)
	local c = obj.Parent.C
	local f = obj.Parent.F
	
	-- Camera Tween
	local ctween = createTween("camera", c, f, LocalCamera)
	ctween:Play()
	LocalCamera.Focus = CFrame.new(f.Position)
	
	-- Hider management
	print(obj.Parent.Hider)
	local t1 = createTween("hiderNext", obj.Parent.Hider)
	local t2 = createTween("hiderPrev", camPrev.Parent.Hider)
	t1:Play()
	t2:Play()
end

local function dehProcedure(which, humanoidRP, charObj, hitObj)
	-- FN: Handles the effects and logic for when DEHs occur
	disconnectDestroy(charObj)
	humanoidRP.Parent.Humanoid.Health = 0
	canDeath = false
	
	print(which)
	deathEvent:FireServer(which)

	if (which == "Dehnemy") then
		dehSound:Play()
		print("deh")
		punchSound:Play()
		fadeTween:Play()
		createTween("dehHit", hitObj):Play() -- red color on enemy
	elseif (which == "Pit") then
		dehSound:Play()
		fallingSound:Play()
		pitTween:Play()
	elseif (which == "Drown") then
		dehSound:Play()
		drownSound:Play()
	end
	
	local coinLoss = 0
	for _,obj in unsavedCoins do
		coinLoss -= obj.BaseValue.Value
		createTween("coinShow", obj):Play()
		createTween("coinShow", obj.Outline):Play()
		createTween("coinShow", obj.Icon):Play()
		obj.IsCollected.Value = false
	end
	moneyEvent:FireServer(coinLoss)
	table.clear(unsavedCoins)
	
	for _,obj in unsavedKeys do
		local thisKey = require(obj.KeyScript)
		thisKey.Close()
		obj.IsCollected.Value = false
	end
	table.clear(unsavedKeys)
	
	for _,obj in triggeredEvents do
		local thisEvent = require(obj.EventScript)
		thisEvent.Stop(LocalPlayer)
		obj.IsCollected.Value = false
	end
	table.clear(triggeredEvents)
end

local function applyHazard(step, charObj, humanoid, humanoidRP)
	humanoid.WalkSpeed = 20 * (waterWalkMod) * (chargeWalkMod)
	-- parts "touching ground"
	for _, part in ipairs(charObj:GetChildren()) do
		if part:IsA("BasePart") and (string.match(part.Name, "Foot")) or (string.match(part.Name, "Foot")) then
			part.CustomPhysicalProperties = PhysicalProperties.new(0.7, (2 - (slideWalkMod)), 0, 100, 1)
		end
	end
	
	--add a blue blur effect to the camera
	blur.Size = 10 * slideWalkMod
	color.TintColor = Color3.fromRGB(255 * (1 - (slideWalkMod / 2)), 255 * (1 - (slideWalkMod / 2)), 255)
	
	
	--humanoidRP.CustomPhysicalProperties = PhysicalProperties.new((2 - (slideWalkMod) + 0.1), 1, 1)

	airLoss = vitals:GetAttribute("AirLoss")
	slideAmt = vitals:GetAttribute("SlideAmt")
	chargeAmt = vitals:GetAttribute("ChargeAmt")

	-- WATER
	if airLoss >= 100 then
		dehProcedure("Drown", humanoidRP, charObj)
	end
	if (inWater and airLoss < 100) then
		airLoss += (step * 10)
		waterWalkMod = 0.6
	elseif airLoss > 0 then
		airLoss -= (step * 15)
		waterWalkMod = 1
	else
		airLoss = 0
		waterWalkMod = 1
	end
	vitals:SetAttribute("AirLoss", airLoss)

	-- ICE
	if (inIce and slideAmt < 100) then
		slideAmt += (step * 15)
	elseif slideAmt > 0 then
		slideAmt -= (step * 10)
	else
		slideAmt = 0
	end
	slideWalkMod = (2 * (math.pow(slideAmt / 100.0, 2)))
	vitals:SetAttribute("SlideAmt", slideAmt)


	-- SUPERCHARGE
	if (inSupercharger and chargeAmt < 100) then
		chargeAmt += (step * 15)
	elseif chargeAmt > 0 then
		chargeAmt -= (step * 10)
	else
		chargeAmt = 0
	end
	chargeWalkMod = 1 + (math.pow(chargeAmt / 100.0, 2))
	vitals:SetAttribute("ChargeAmt", chargeAmt)

end

local function charDetect(charObj, humanoidRP)
	-- FN: Large function controlling hit detection for char
	local touches = charObj.Main.Hitbox:GetTouchingParts()
	--DEBUGprint(touches)
	
	local hazardsFound = {}
	
	for _, obj in ipairs(touches) do
		if not (string.match(obj.Name, "ClearPad") == nil) then
			if not (inTeleport) then
				inTeleport = true
				canDeath = false
				dingSound:Play()
				createTween("shinePart", obj):Play()
				-- Save data stuff goes here...
				wait(2)
				humanoidRP.Parent:PivotTo(CFrame.new(obj.Destination.Value.Position + Vector3.new(0, 12, 0)))
				wait()
				inTeleport = false
				canDeath = true
			end
		
		elseif not (string.match(obj.Name, "WinPad") == nil) then

			print("WIN!!!!!!!")
			local winGui = LocalPlayer.PlayerGui:FindFirstChild("Win")
			winGui.Enabled = true

			-- When the server verifies the win, it sends the flag here
			local flag = winFunc:InvokeServer()
			winGui.WinnerPopup.Flag.Text = "" .. flag
		
		
		elseif not (string.match(obj.Name, "Teleporter") == nil) then
			if not (inTeleport) then
				inTeleport = true
				canDeath = false
				dingSound:Play()
				createTween("shinePart", obj):Play()
				-- Save data stuff goes here...
				wait(1)
				humanoidRP.Parent:PivotTo(CFrame.new(obj.Destination.Value.Position + Vector3.new(0, 12, 0)))
				wait()
				inTeleport = false
				canDeath = true
			end
			
		elseif not (string.match(obj.Name, "Checkpoint") == nil) then
			if not (obj.Name == cpPrev and #unsavedCoins == 0 and #unsavedKeys == 0 and #triggeredEvents == 0) then
				checkpointEvent:FireServer(obj)
				saveSound:Play()
				createTween("shinePart", obj):Play()
				cpPrev = obj.Name
				table.clear(unsavedCoins)
				table.clear(unsavedKeys)
				table.clear(triggeredEvents)
			end
			
		elseif (obj.Name == "CameraTrigger") then
			if not (obj.Parent.C == camPrev) then
				setCamera(obj, camPrev)
				checkpointEvent:FireServer(obj)
				camPrev = obj.Parent.C
			end
			
		elseif not (string.match(obj.Name, "Key") == nil) then
			if not obj.IsCollected.Value then
				obj.IsCollected.Value = true
				keySound:Play()
				local thisKey = require(obj.KeyScript)
				thisKey.Open()
				table.insert(unsavedKeys, obj)
			end
			
		elseif obj.Name == "Coin" then
			if not obj.IsCollected.Value then
				obj.IsCollected.Value = true
				local coinTotalValue = 0.0
				coinTotalValue = obj.BaseValue.Value
				if (obj.IsRepeat.Value) then
					coinTotalValue /= 100.0
				end
				coinSound:Play()
				moneyEvent:FireServer(coinTotalValue)
				createTween("coinFade", obj):Play()
				createTween("coinFade", obj.Outline):Play()
				createTween("coinFade", obj.Icon):Play()
				table.insert(unsavedCoins, obj)
			end
			
		elseif not (string.match(obj.Name, "Event") == nil) then
			if not obj.IsCollected.Value then
				obj.IsCollected.Value = true
				local thisEvent = require(obj.EventScript)
				thisEvent.Play(LocalPlayer)
				table.insert(triggeredEvents, obj)
			end
			
		elseif obj.Name == "Dehnemy" then
			if (canDeath) then
				dehProcedure("Dehnemy", humanoidRP, charObj, obj)
				break
			end
			
		elseif obj.Name == "Water" then
			inWater = true
			table.insert(hazardsFound, "Water")
		elseif obj.Name == "Ice" then
			inIce = true
			table.insert(hazardsFound, "Ice")
		elseif obj.Name == "Supercharger" then
			inSupercharger = true
			table.insert(hazardsFound, "Supercharger")
		end
	end
	
	if (table.find(hazardsFound, "Water") == nil) then
		inWater = false
	end
	if (table.find(hazardsFound, "Ice") == nil) then
		inIce = false
	end
	if (table.find(hazardsFound, "Supercharger") == nil) then
		inSupercharger = false
	end
end

local function touchDetect(charObj, humanoidRP, otherPart)
	-- FN: Hit detection for humanoid (pits)
	if otherPart.Name == "Pit" then
		if (canDeath) then
			dehProcedure("Pit", humanoidRP, charObj)
		end
	end
end

function setupChar(c)
	-- FN: Setup all aspects of the Char object
	wait()

	-- Re-enable all debounces
	canDeath = true

	-- Locate/configure humanoid parts of newly spawned character
	local humanoidRP = c:WaitForChild("HumanoidRootPart")
	local humanoid = humanoidRP.Parent:WaitForChild("Humanoid")

	-- Clone "char" object in ServerStorage - this is the player core
	local charObj = game.ReplicatedStorage.Char:Clone()
	local name = ("Char" .. LocalPlayer.Name)
	charObj.Name = name

	-- Place char in game (locally)
	charObj.Parent = humanoidRP.Parent

	-- Hide server char
	local serverChar = requestEvent:InvokeServer(LocalPlayer)
	--DEBUGprint(serverChar)
	serverChar.Main.Transparency = 1
	serverChar.Main.Outline.Transparency = 1
	serverChar.Main.Face.Transparency = 1

	-- Create main tweens for this life
	spawnTween1 = createTween("spawn1", charHeight)
	spawnTween2 = createTween("spawn2", charObj)
	fadeTween = createTween("fade", charObj)
	pitTween = createTween("pit", charObj)

	-- Force vitals to 0
	vitals:SetAttribute("AirLoss", 0)
	vitals:SetAttribute("SlideAmt", 0)
	vitals:SetAttribute("ChargeAmt", 0)
	waterWalkMod = 1
	chargeWalkMod = 1

	-- Initialize movement and hit detection engines
	updateConnection = RunService.Heartbeat:Connect(function(step)
		updatePos(charObj, humanoidRP, humanoid)
	end)
	charConnection = RunService.Heartbeat:Connect(function(step)
		charDetect(charObj, humanoidRP)
	end)
	touchConnection = humanoidRP.Touched:Connect(function(otherPart)
		touchDetect(charObj, humanoidRP, otherPart)
	end)
	hazardConnection = RunService.Heartbeat:Connect(function(step)
		applyHazard(step, charObj, humanoid, humanoidRP)
	end)

	-- Spawn animation
	charHeight.Value = 100.025
	charObj.Main.Size = Vector3.new(0.2, 10, 10)
	spawnTween1:Play()
	spawnTween2:Play()
	swooshSound:Play()
end


--=======--
-- LOGIC --
--=======--

-- FIRST SPAWN LOGIC: runs once
-- Make music
local audioClone = game.ReplicatedStorage.WHG4:Clone()
audioClone.Parent = script.Parent
audioClone.Name = "Music"
audioClone:Play()

-- Perform setup each time each time player spawns
LocalPlayer.CharacterAdded:Connect(function(c)
	setupChar(c)
end)

-- If dying in some unexpected way, try to stop everything for that life
LocalPlayer.CharacterRemoving:Connect(function(c)
	pcall(disconnectDestroy)
end)

-- new transparenter
for _,v in workspace:GetDescendants() do
	if v.Name == "p1" or v.Name == "p2" or v.Name == "Center" then
		v.Transparency = 1
	end
end
