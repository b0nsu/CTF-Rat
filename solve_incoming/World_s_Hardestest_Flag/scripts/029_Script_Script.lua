local materials = {256, 272, 288, 512, 528, 784, 800,
	816, 832, 848, 864, 880, 1040, 1056, 1072, 1088,
	1280, 1296, 1312, 1536, 1568, 1584}

while true do
	script.Parent.Material = materials[math.random(1, #materials)]
	wait(0.05)
end