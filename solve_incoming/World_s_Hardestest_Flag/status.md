# Status

## Current State
- Challenge fetched from CTFd: `World's Hardestest Flag`, ID `23`, category `Pwn`.
- Local attachment analyzed: `mrdeh-hardestest.rbxl`.
- Roblox place chunks extracted to `chunks/`.
- Lua sources extracted to `scripts/`.
- Core vulnerability identified in `scripts/035_Script_SecureDeh9001Server.lua`.

## Confirmed
- The flag is stored in server memory at `Storage[0x6767]`.
- `read(0x6767)` denies access only when `TypeTag == 0`.
- Exposed sandbox function `write()` can overwrite `Storage[0x6767].TypeTag`.
- Client banned-word filter can be bypassed with string concatenation.
- Payload does not contain the banned substrings:

```lua
write(0x6767,{["Type".."Tag"]=4});print(read(0x6767))
```

## Remaining
- Open the live Roblox game with a Roblox account.
- Open the `SecureDeh9001` terminal in-game.
- Submit the payload above.
- Copy the `SERVER: ...` output and submit the flag manually to CTFd.

## Important Files
- `run.json`: CTFd manifest.
- `mrdeh-hardestest.rbxl`: original challenge attachment.
- `scripts/011_LocalScript_SecureDeh9001TerminalScript.lua`: client terminal and banned-word filter.
- `scripts/035_Script_SecureDeh9001Server.lua`: server sandbox, flag storage, read/write primitive.
