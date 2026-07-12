local descendants = workspace.Levels:GetDescendants()

-- Loop through all of the descendants of the Workspace 
-- to hide camera related parts and shift down hiders
for _, descendant in pairs(descendants) do
	if descendant:IsA("BasePart") and (descendant.Name == "C" or descendant.Name == "F" or descendant.Name == "CameraTrigger") then
		descendant.Transparency = 1
	end
	if descendant.Name == "Hider" then
		descendant.Position = Vector3.new(descendant.Position.X, descendant.Position.Y - 100, descendant.Position.Z)
	end
end