local TweenService = game:GetService("TweenService")

local button = script.Parent.MouseButton
local frame = script.Parent.Parent.RoundifiedFrame

local enabled = true

button.Activated:Connect(function()
	if (enabled) then
		--print("Hide " .. frame.Parent:GetFullName())
		enabled = false
		TweenService:Create(frame, TweenInfo.new(0.5, Enum.EasingStyle.Cubic, Enum.EasingDirection.In, 0, false, 0), 
			{Size = UDim2.new(0, 0, 0, 0)}):Play()
	else
		--print("Show " .. frame.Parent:GetFullName())
		enabled = true
		TweenService:Create(frame, TweenInfo.new(0.5, Enum.EasingStyle.Cubic, Enum.EasingDirection.Out, 0, false, 0), 
			{Size = UDim2.new(.25, 0, .05, 0)}):Play()
	end
end)