#!/usr/bin/env python3

alphabet = "ADFGVX"
key = "SUGAR"
ciphertext = "GVXXFVXVAFXFXVGADAFF"

grid = {
    "A": "B3MRLI",
    "D": "A6F082",
    "F": "C7SEUH",
    "G": "Z9DXKV",
    "V": "1QYW5P",
    "X": "NJT4GO",
}

lookup = {
    row + col: grid[row][i]
    for row in alphabet
    for i, col in enumerate(alphabet)
}

width = len(key)
height = len(ciphertext) // width

columns = {}
offset = 0
for index, _ in sorted(enumerate(key), key=lambda item: (item[1], item[0])):
    columns[index] = ciphertext[offset:offset + height]
    offset += height

fractionated = "".join(
    columns[col][row]
    for row in range(height)
    for col in range(width)
)

plaintext = "".join(
    lookup[fractionated[i:i + 2]]
    for i in range(0, len(fractionated), 2)
)

print(plaintext)
