local Players = game:GetService("Players")
local RunService = game:GetService("RunService")

local player = Players.LocalPlayer
local camera = workspace.CurrentCamera

camera.CameraType = Enum.CameraType.Scriptable
camera.FieldOfView = 12


--[[local CAMERA_DEPTH = 5
local HEIGHT_OFFSET = 2

local function updateCamera()
	local character = player.Character
	if character then
		local root = character:FindFirstChild("HumanoidRootPart")
		if root then
			local rootPosition = root.Position + Vector3.new(0, HEIGHT_OFFSET, 0)
			local cameraPosition = rootPosition + Vector3.new(-3, CAMERA_DEPTH, 5)
			camera.CFrame = CFrame.lookAt(cameraPosition, rootPosition)
		end
	end
end

local function moveCamera(c, f)
	camera.CFrame = CFrame.lookAt(c.Position, f.Position)
end

RunService:BindToRenderStep("CharCamera", Enum.RenderPriority.Camera.Value + 1, updateCamera]]