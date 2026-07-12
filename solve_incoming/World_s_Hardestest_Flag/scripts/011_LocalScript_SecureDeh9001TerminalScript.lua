local TweenService = game:GetService("TweenService")
local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")

local LocalPlayer = Players.LocalPlayer

-- "Secure Deh-9001 Server channel"
local executeEvent = ReplicatedStorage:WaitForChild("SecureDeh9001Server-Pipeline")
	:WaitForChild("ExecuteCode") 
-- "Secure Deh-9001 Server channel"

local textEntry = script.Parent.TextEntry
local errorLog = script.Parent.Errors
local submitButton = script.Parent.SubmitButton
local clearButton = script.Parent.ClearButton

local buzz = script.Parent["EXTREMELY LOUD INCORRECT BUZZER"]

errorLog.Text = "This terminal accepts a subset of Lua code. It will be run on the Secure Deh-9001 Server, which is a bit limited. \n" ..
	"You can separate commands/lines with semicolons, even though they aren't required in Lua.\n\n" ..
	"[HELP] Type 'help' for some inspiration. \n" ..
	"[BANS] !!! BANNED WORDS BY DEHMASTER: position, humanoid, destroy, name, typetag, flag !!!"

	--[[ //// relic of the past. man, that brings back memories. ////
	
	"--> If you use print(), use F9 to open the console and see the results. <--\n\n" ..
	"Snippets: \n" ..
	"List children of the workspace -> for _,v in ipairs(workspace:GetChildren()) do print(v.Name) end\n" ..
	"Change the name of something -> local obj = {object}; obj.Name = {newName}\n" ..
	"Teleport -> local hrp = workspace.{modelName}.HumanoidRootPart; hrp.Position = hrp.Position + Vector3.new({x},{y},{z})\n" ]]

local first = true

local bannedWords = {"position", "humanoid", "destroy", "name", "typetag", "flag"} -- why those last 2 ones???

local function killPlayer()
	local character = Players.LocalPlayer.Character or Players.LocalPlayer.CharacterAdded:Wait()
	local humanoid = character:FindFirstChildOfClass("Humanoid")
	if humanoid then
		buzz:Play()
		humanoid.Health = 0
	end
end


local function containsBannedWords(input)
	for _, word in bannedWords do
		if string.find(string.lower(input), word) then
			return true
		end
	end
	return false
end



submitButton.Activated:Connect(function()
	local code = textEntry.Text
	
	if code == "help" then
		errorLog.Text = "List children of an object -> for _,v in ipairs({path.to.object}) do print(v.Name) end\n" ..
			"Change the property of an object -> local obj = {object}; obj.{Property} = {newPropertyValue}\n" ..
			""
		return
	end
	
	if first then
		errorLog.Text = ""
		first = false
	end
	
	if containsBannedWords(code) then
		killPlayer()
		errorLog.Text = "AHA! GOT YOU!!!"
		return
	end
	
	if code ~= "" then -- check if the code is not empty
		
		-- if it passes the filter, send it to the server
		executeEvent:FireServer(code)
		
		--[[ //// more relics. Mr. Deh, are you sure you didn't just steal someone's work? ////
		
		local success, error = pcall(lsModule(code)) -- EXECUTE
		if success then
			errorLog.Text = errorLog.Text .. "\nSuccess."
		else
			errorLog.Text = errorLog.Text .. "\nError: " .. error
		end
		]]
	else
		errorLog.Text = errorLog.Text .. "\nNo code to execute!"
	end
end)


-- listen for the server's print output to display in the UI
executeEvent.OnClientEvent:Connect(function(output)
	errorLog.Text = errorLog.Text .. "\n" .. output
end)


clearButton.Activated:Connect(function()
	errorLog.Text = ""
end)
