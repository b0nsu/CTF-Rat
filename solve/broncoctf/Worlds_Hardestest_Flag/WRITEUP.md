# World's Hardestest Flag

## Meta

- Category: pwn/rev
- Challenge ID: 23
- Attachment: `mrdeh-hardestest.rbxl`
- Live game: `https://www.roblox.com/games/105471062200103/Worlds-Hardestest-Flag`
- Status: exploit path recovered; live flag must be read in Roblox Player.

## Summary

The `.rbxl` file is a binary Roblox place with zstd-compressed chunks. Extracting
the `Script.Source` chunks reveals a terminal UI that sends user code to:

```lua
ReplicatedStorage["SecureDeh9001Server-Pipeline"].ExecuteCode
```

The client bans these lowercase substrings:

```text
position, humanoid, destroy, name, typetag, flag
```

On the server, the custom environment exposes `write`, `read`, and `print`.
The live flag is loaded from Roblox DataStore and then stored at address `0x6767`:

```lua
local FlagStore = DataStoreService:GetDataStore("CTFCredentials")
local FLAG = "Bonco{FAKEFAKEFAKE}" -- Fallback for Studio
local success, live_flag = pcall(function()
    return FlagStore:GetAsync("TrueFlag")
end)
if success and live_flag then
    FLAG = live_flag
end
```

The memory table then stores:

```lua
[0x6767] = { TypeTag = 0, Value = FLAG }
```

`read(0x6767)` returns `[ACCESS DENIED]` while `TypeTag == 0`, but `write` can
mutate that table. The banlist only blocks the contiguous string `typetag`, so
constructing the key dynamically bypasses it.

I checked the public Roblox page and unauthenticated asset delivery endpoints.
The page only exposes the description/universe metadata, and asset delivery for
place version downloads returns authentication required. CTFd's solution endpoint
is hidden. Without a Roblox Player session, the remaining concrete oracle is the
in-game RemoteEvent path.

## Payload

Enter this in the live game's Secure Deh terminal:

```lua
write(0x6767,{["Type".."Tag"]=4});print(read(0x6767))
```

The server should print the live DataStore flag in the terminal output.
