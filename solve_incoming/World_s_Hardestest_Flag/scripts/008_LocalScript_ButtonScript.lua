local TweenService = game:GetService("TweenService")

local LocalCamera = workspace.CurrentCamera

local button = script.Parent.SettingsButton
local frame = script.Parent.Parent.SettingsMenu

local blur = Instance.new("BlurEffect")
blur.Name = "SettingsBlur"
blur.Parent = LocalCamera
blur.Size = 0

local open = false

button.Activated:Connect(function()
	if (open) then
		blur.Size = 15
		open = false
		TweenService:Create(frame, TweenInfo.new(0.5, Enum.EasingStyle.Cubic, Enum.EasingDirection.In, 0, false, 0), 
			{Position = UDim2.new(0.5, 0, 1.5, 0)}):Play()
		TweenService:Create(blur, TweenInfo.new(0.5, Enum.EasingStyle.Cubic, Enum.EasingDirection.In, 0, false, 0), 
			{Size = 0}):Play()

	else
		blur.Size = 0
		open = true
		TweenService:Create(frame, TweenInfo.new(0.5, Enum.EasingStyle.Cubic, Enum.EasingDirection.Out, 0, false, 0), 
			{Position = UDim2.new(0.5, 0, 0.5, 0)}):Play()
		TweenService:Create(blur, TweenInfo.new(0.5, Enum.EasingStyle.Cubic, Enum.EasingDirection.Out, 0, false, 0), 
			{Size = 15}):Play()
	end
end)