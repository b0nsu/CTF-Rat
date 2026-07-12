-- RotatingDehnemy MovementScript
local TweenService = game:GetService("TweenService")

local DehModule = require(game.ReplicatedStorage.DehModule)

local movements = {}

movements.StartingPos = nil

movements.TweenRot1 = nil
movements.TweenRot2 = nil
movements.TweenRot3 = nil
movements.TweenRot4 = nil

movements.TweenConnection1 = nil
movements.TweenConnection2 = nil
movements.TweenConnection3 = nil
movements.TweenConnection4 = nil

movements.PauseState = 0

movements.Initialize = function()
	local folder = script.Parent
	local mainPart = folder.Dehnemy
	local outline = mainPart.Outline
	local p1 = folder.p1
	local center = folder.center
	local moveTime = script.Parent.MoveTime
	local reverse = script.Parent.Reverse
	
	local sp, tr1, tr2, tr3, tr4 = DehModule.InitializeRotation(folder, mainPart, outline, p1, center, moveTime, reverse)
	
	movements.StartingPos = sp
	movements.TweenRot1 = tr1
	movements.TweenRot2 = tr2
	movements.TweenRot3 = tr3
	movements.TweenRot4 = tr4
end

movements.Play = function(reset)
	local tc1 = nil
	local tc2 = nil
	local tc3 = nil
	local tc4 = nil
	
	if (reset) then
		tc1, tc2, tc3, tc4 = DehModule.PlayRotation({script.Parent.Dehnemy, script.Parent.p1}, 
													 movements.TweenRot1, movements.TweenRot2, 
													 movements.TweenRot3, movements.TweenRot4, nil)
	else
		tc1, tc2, tc3, tc4 = DehModule.PlayRotation(nil, movements.TweenRot1, movements.TweenRot2, movements.TweenRot3, 
													movements.TweenRot4, movements.PauseState)
	end
	
	movements.TweenConnection1 = tc1
	movements.TweenConnection2 = tc2
	movements.TweenConnection3 = tc3
	movements.TweenConnection4 = tc4
end

movements.Pause = function()
	local ps = DehModule.PauseRotation(movements.TweenRot1, movements.TweenRot2, 
									   movements.TweenRot3, movements.TweenRot4,
									   movements.TweenConnection1,	movements.TweenConnection2, 
									   movements.TweenConnection3, movements.TweenConnection4)
	movements.PauseState = ps
end

movements.Stop = function()
	DehModule.StopRotation(movements.TweenRot1, movements.TweenRot2, 
						   movements.TweenRot3, movements.TweenRot4,
						   movements.TweenConnection1,	movements.TweenConnection2, 
						   movements.TweenConnection3, movements.TweenConnection4)
	movements.PauseState = 0
end

return movements