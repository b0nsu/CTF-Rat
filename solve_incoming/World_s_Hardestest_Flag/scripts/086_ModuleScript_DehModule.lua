local TweenService = game:GetService("TweenService")

local DehModule = {}

--[[ SLIDING DEHNEMIES ]]
DehModule.InitializeSlide = function(folder, mainPart, outline, p1, p2, moveTime)
	--[[WHAT IS PASSED IN FROM MOVEMENTSCRIPT
	local folder = script.Parent
	local mainPart = folder.Dehnemy
	local outline = mainPart.Outline
	local p1 = folder.p1
	local p2 = folder.p2
	local moveTime = script.Parent.MoveTime]]

	local StartingPos = p1.Position

	mainPart.Position = p1.Position
	outline.Position = p1.Position
	p1.Transparency = 1
	p2.Transparency = 1

	local goal = {}
	goal.Position = p2.Position

	local tweenInfo = TweenInfo.new(moveTime.Value, Enum.EasingStyle.Linear, Enum.EasingDirection.Out, -1, true, 0)
	
	local TweenMain = TweenService:Create(mainPart, tweenInfo, goal)
	local TweenOut = TweenService:Create(outline, tweenInfo, goal)
	
	return StartingPos, TweenMain, TweenOut
end


DehModule.PlaySlide = function(resetArr, TweenMain, TweenOut)
	if not (resetArr == nil) then
		resetArr[1].Position = resetArr[2].Position
	end
	TweenMain:Play()
	TweenOut:Play()
end

DehModule.PauseSlide = function(TweenMain, TweenOut)
	TweenMain:Pause()
	TweenOut:Pause()
end

DehModule.StopSlide = function(TweenMain, TweenOut)
	TweenMain:Cancel()
	TweenOut:Cancel()
end

--[[ FOUR POINT SLIDING DEHNEMIES ]]
DehModule.InitializeFourSlide = function(folder, mainPart, outline, p1, p2, p3, p4, moveTime, delayTime)
	--[[WHAT IS PASSED IN FROM MOVEMENTSCRIPT
	local folder = script.Parent
	local mainPart = folder.Dehnemy
	local outline = !!! nil !!!
	local p1 = folder.p1
	local p2 = folder.p2
	local p3 = folder.p3
	local p4 = folder.p4
	local moveTime = script.Parent.MoveTime]]

	local StartingPos = mainPart.Position
	
	-- NOTE: p1 IS NOT THE STARTINGPOS IN FOUR POINTS
	--mainPart.Position = p1.Position
	p1.Transparency = 1
	p2.Transparency = 1
	p3.Transparency = 1
	p4.Transparency = 1

	local goal1 = {}
	goal1.Position = p2.Position
	local goal2 = {}
	goal2.Position = p3.Position
	local goal3 = {}
	goal3.Position = p4.Position
	local goal4 = {}
	goal4.Position = p1.Position

	local tweenInfo = TweenInfo.new(moveTime.Value, Enum.EasingStyle.Linear, Enum.EasingDirection.Out, 0, false, delayTime.Value)

	local Tween1 = TweenService:Create(mainPart, tweenInfo, goal1)
	local Tween2 = TweenService:Create(mainPart, tweenInfo, goal2)
	local Tween3 = TweenService:Create(mainPart, tweenInfo, goal3)
	local Tween4 = TweenService:Create(mainPart, tweenInfo, goal4)

	return StartingPos, Tween1, Tween2, Tween3, Tween4
end

DehModule.PlayFourSlide = function(resetArr, TweenSlide1, TweenSlide2, TweenSlide3, TweenSlide4, force)
	if not (resetArr == nil) then
		resetArr[1].Position = resetArr[2] -- different from rotation, which passes p1 in the array
	end

	local TweenConnection1 = TweenSlide1.Completed:Connect(function() TweenSlide2:Play() end)
	local TweenConnection2 = TweenSlide2.Completed:Connect(function() TweenSlide3:Play() end)
	local TweenConnection3 = TweenSlide3.Completed:Connect(function() TweenSlide4:Play() end)
	local TweenConnection4 = TweenSlide4.Completed:Connect(function() TweenSlide1:Play() end)


	if (force == nil or force == 1) then
		TweenSlide1:Play()
	elseif (force == 2) then
		TweenSlide2:Play()
	elseif (force == 3) then
		TweenSlide3:Play()
	elseif (force == 4) then
		TweenSlide4:Play()
	end

	return TweenConnection1, TweenConnection2, TweenConnection3, TweenConnection4
end

DehModule.PauseFourSlide = function(TweenSlide1, TweenSlide2, TweenSlide3, TweenSlide4, 
	TweenConnection1, TweenConnection2, TweenConnection3, TweenConnection4)
	TweenConnection1:Disconnect()
	TweenConnection2:Disconnect()
	TweenConnection3:Disconnect()
	TweenConnection4:Disconnect()
	if (TweenSlide1.PlaybackState == 2 --[[Enum.Playing]]) then
		TweenSlide1.Pause()
		return 1
	elseif (TweenSlide2.PlaybackState == 2 --[[Enum.Playing]]) then
		TweenSlide2.Pause()
		return 2
	elseif (TweenSlide3.PlaybackState == 2 --[[Enum.Playing]]) then
		TweenSlide3.Pause()
		return 3
	elseif (TweenSlide4.PlaybackState == 2 --[[Enum.Playing]]) then
		TweenSlide4.Pause()
		return 4
	end
end

DehModule.StopFourSlide = function(TweenSlide1, TweenSlide2, TweenSlide3, TweenSlide4,
	TweenConnection1, TweenConnection2, TweenConnection3, TweenConnection4)
	TweenConnection1:Disconnect()
	TweenConnection2:Disconnect()
	TweenConnection3:Disconnect()
	TweenConnection4:Disconnect()
	TweenSlide1:Cancel()
	TweenSlide2:Cancel()
	TweenSlide3:Cancel()
	TweenSlide4:Cancel()
end



--[[ ROTATING DEHNEMIES ]]
DehModule.InitializeRotation = function(folder, mainPart, outline, p1, center, moveTime, reverse)
	--[[WHAT IS PASSED IN FROM MOVEMENTSCRIPT
	local folder = script.Parent
	local mainPart = folder.Dehnemy
	local outline = mainPart.Outline
	local p1 = folder.p1
	local center = folder.center
	local moveTime = script.Parent.MoveTime
	local reverse = script.Parent.Reverse]]

	local StartingPos = p1.Position

	mainPart.Position = p1.Position
	outline.Position = p1.Position
	p1.Transparency = 1
	center.Transparency = 1

	local goal1 = {}
	goal1.CFrame = center.CFrame * CFrame.Angles(0, math.rad(90 + 180 * reverse.Value), 0)

	local goal2 = {}
	goal2.CFrame = center.CFrame * CFrame.Angles(0, math.rad(180), 0)

	local goal3 = {}
	goal3.CFrame = center.CFrame * CFrame.Angles(0, math.rad(270 - 180 * reverse.Value), 0)
	
	local goal4 = {}
	goal4.CFrame = center.CFrame * CFrame.Angles(0, math.rad(360), 0)

	local tweenInfo = TweenInfo.new(moveTime.Value, Enum.EasingStyle.Linear, Enum.EasingDirection.Out, 0, false, 0)
	local TweenRot1 = TweenService:Create(center, tweenInfo, goal1)
	local TweenRot2 = TweenService:Create(center, tweenInfo, goal2)
	local TweenRot3 = TweenService:Create(center, tweenInfo, goal3)
	local TweenRot4 = TweenService:Create(center, tweenInfo, goal4)

	return StartingPos, TweenRot1, TweenRot2, TweenRot3, TweenRot4
end


DehModule.PlayRotation = function(resetArr, TweenRot1, TweenRot2, TweenRot3, TweenRot4, force)
	if not (resetArr == nil) then
		resetArr[1].Position = resetArr[2].Position
	end
	
	local TweenConnection1 = TweenRot1.Completed:Connect(function() TweenRot2:Play() end)
	local TweenConnection2 = TweenRot2.Completed:Connect(function() TweenRot3:Play() end)
	local TweenConnection3 = TweenRot3.Completed:Connect(function() TweenRot4:Play() end)
	local TweenConnection4 = TweenRot4.Completed:Connect(function() TweenRot1:Play() end)

	
	if (force == nil or force == 1) then
		TweenRot1:Play()
	elseif (force == 2) then
		TweenRot2:Play()
	elseif (force == 3) then
		TweenRot3:Play()
	elseif (force == 4) then
		TweenRot4:Play()
	end
		
	return TweenConnection1, TweenConnection2, TweenConnection3, TweenConnection4
end

DehModule.PauseRotation = function(TweenRot1, TweenRot2, TweenRot3, TweenRot4, 
								   TweenConnection1, TweenConnection2, TweenConnection3, TweenConnection4)
	TweenConnection1:Disconnect()
	TweenConnection2:Disconnect()
	TweenConnection3:Disconnect()
	TweenConnection4:Disconnect()
	if (TweenRot1.PlaybackState == 2 --[[Enum.Playing]]) then
		TweenRot1.Pause()
		return 1
	elseif (TweenRot2.PlaybackState == 2 --[[Enum.Playing]]) then
		TweenRot2.Pause()
		return 2
	elseif (TweenRot3.PlaybackState == 2 --[[Enum.Playing]]) then
		TweenRot3.Pause()
		return 3
	elseif (TweenRot4.PlaybackState == 2 --[[Enum.Playing]]) then
		TweenRot4.Pause()
		return 4
	end
end

DehModule.StopRotation = function(TweenRot1, TweenRot2, TweenRot3, TweenRot4,
								  TweenConnection1, TweenConnection2, TweenConnection3, TweenConnection4)
	TweenConnection1:Disconnect()
	TweenConnection2:Disconnect()
	TweenConnection3:Disconnect()
	TweenConnection4:Disconnect()
	TweenRot1:Cancel()
	TweenRot2:Cancel()
	TweenRot3:Cancel()
	TweenRot4:Cancel()
end

return DehModule