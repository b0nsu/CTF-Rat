local TweenService = game:GetService("TweenService")

local LocalCamera = workspace.CurrentCamera

local button = script.Parent.TerminalButton
local frame = script.Parent.Parent.SecureDehTerminal

local open = false

button.Activated:Connect(function()
	if (open) then
		--print("Hide " .. frame.Parent:GetFullName())
		open = false
		TweenService:Create(frame, TweenInfo.new(0.5, Enum.EasingStyle.Cubic, Enum.EasingDirection.In, 0, false, 0), 
			{Position = UDim2.new(2.0, 0, 1.0, 0)}):Play()
	else
		--print("Show " .. frame.Parent:GetFullName())
		open = true
		TweenService:Create(frame, TweenInfo.new(0.5, Enum.EasingStyle.Cubic, Enum.EasingDirection.Out, 0, false, 0), 
			{Position = UDim2.new(1.0, 0, 1.0, 0)}):Play()
	end
end)