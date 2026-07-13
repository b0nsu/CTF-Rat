# Deep Port

## Meta

- Category: pwn
- Target: `10.112.0.12:42177`
- Binary: `deep_port`
- Flag: `grodno{ef4f0eb8-b6ea-441e-a150-cfd3825975f2}`

## Summary

`release_shipment` frees a manifest but leaves the shipment pointer intact, so `edit_shipment`, `view_shipment`, and `replace_shipment` keep operating on a freed chunk. The exploit uses this UAF to poison tcache and make a later `malloc(0x50)` return `harbor->dispatch_hook`.

A single freed chunk is not enough because the tcache count drops to zero after the first allocation. Freeing two same-size chunks gives count 2, so after poisoning the head chunk's `next`, the second allocation returns the forged target.

## Steps

1. Create two `0x50` manifests.
2. View them to leak:
   - `standby` callback for code base/function offset
   - heap manifest pointers for the harbor object and safe-linking key
3. Free both manifests, leaving stale shipment pointers.
4. Edit the second freed chunk and set its tcache `next` to `harbor + 0x20` (`dispatch_hook`).
5. Replace slot `1` to consume the real freed chunk.
6. Replace slot `0`; this allocation lands on `dispatch_hook`.
7. Write `print_flag` and restore `route` as `flag.txt` in the same write.
8. Dispatch to print the flag.

## Exploit

See `exploit.py` in this directory. It handles the downloadable PIE build and the remote fixed build by selecting the correct `standby -> print_flag` delta.
