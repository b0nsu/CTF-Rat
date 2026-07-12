-- SlidingDehnemy MovementScript
local TweenService = game:GetService("TweenService")

local DehModule = require(game.ReplicatedStorage.DehModule)

local movements = {}

movements.StartingPos = nil

movements.TweenMain = nil
movements.TweenOut = nil

movements.Initialize = function()
	local folder = script.Parent
	local mainPart = folder.Dehnemy
	local outline = mainPart.Outline
	local p1 = folder.p1
	local p2 = folder.p2
	local moveTime = script.Parent.MoveTime
	
	local sp, tm, to = DehModule.InitializeSlide(folder, mainPart, outline, p1, p2, moveTime)
	
	movements.StartingPos = sp
	movements.TweenMain = tm
	movements.TweenOut = to
end

movements.Play = function(reset)
	if (reset) then
		DehModule.PlaySlide({script.Parent.Dehnemy, script.Parent.p1}, movements.TweenMain, movements.TweenOut)
	else
		DehModule.PlaySlide(nil, movements.TweenMain, movements.TweenOut)
	end
	
end

movements.Pause = function()
	DehModule.PauseSlide(movements.TweenMain, movements.TweenOut)
end

movements.Stop = function()
	DehModule.StopSlide(movements.TweenMain, movements.TweenOut)
end

return movements