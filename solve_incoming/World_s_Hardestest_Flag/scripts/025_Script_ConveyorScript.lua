script.Parent.Velocity = script.Parent.CFrame.LookVector * script.Parent:GetAttribute("Speed")
script.Parent.Attachment0.Beam.TextureSpeed = (script.Parent:GetAttribute("Speed") / 5)
script:Remove()