-- Adapted from SCOUT

local TweenService = game:GetService("TweenService")
local Players = game:GetService("Players")
local UserInputService = game:GetService("UserInputService")
local LocalPlayer = Players.LocalPlayer
local mouse = LocalPlayer:GetMouse()

local container = script.Parent.RoundifiedFrame

local containerInfo1 = TweenInfo.new(0.5, Enum.EasingStyle.Cubic, Enum.EasingDirection.Out, 0, false, 0)
local containerInfo2 = TweenInfo.new(0.5, Enum.EasingStyle.Cubic, Enum.EasingDirection.In, 0, false, 0)

local state = false

-- CREDIT: https://devforum.roblox.com/t/how-to-use-mousetarget/585791
mouse.Move:Connect(function()
	local screenWidth = workspace.CurrentCamera.ViewportSize.X
	container.Position = UDim2.new(0, mouse.X, 0, mouse.Y)
	
	if mouse.X > screenWidth / 2 then
		container.AnchorPoint = Vector2.new(1, 0)
	else
		container.AnchorPoint = Vector2.new(0, 0)
	end
		
	local t = mouse.Target
	-- nil check first to prevent error
	if t == nil then
		container.Visible = false
		container.Path.Text = "nil"
		return
	else
		container.Visible = true	
		container.Path.Text = t:GetFullName()
		return
	end
end)
