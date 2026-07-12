local TweenService = game:GetService("TweenService")

local levelsFolder = workspace.Levels

local FunctionLibrary = {}

FunctionLibrary.splitLvlName = function(str)
	-- Helper FN: Split a string into "level" and "room" component
	local split = string.split(str, " ")
	local level = split[1]
	local room = split[2]
	return level, room
end

FunctionLibrary.getGameFolder = function(level, room, folderName)
	-- Helper FN: Returns the folder for a given level (or room, if parameter supplied)
	local lvlF = levelsFolder:FindFirstChild(level, true)

	if (room == nil) then
		return lvlF:FindFirstChild(folderName)
	else
		return lvlF:FindFirstChild(room):FindFirstChild(folderName)
	end
end

FunctionLibrary.isNumberHigher = function(value, prev)
	-- Helper FN: Test whether param 1 is a higher number than param 
	if (value > prev) then
		return true
	else
		return false
	end
end

return FunctionLibrary