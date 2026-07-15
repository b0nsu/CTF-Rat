# Grandma's Secret

## Summary
The letter gives the full recipe: ADFGVX cipher, keyword `SUGAR`, and an ADFGVX square.

The ciphertext is:

```text
GVXX FVXV AFXF XVGA DAFF
```

Using standard ADFGVX decryption:

1. Split the ciphertext into columns in alphabetical keyword order (`A`, `G`, `R`, `S`, `U` from `SUGAR`).
2. Restore the original column order (`S`, `U`, `G`, `A`, `R`) and read rows to get coordinate pairs.
3. Decode the coordinate pairs through the handwritten square.

The recovered WiFi password is:

```text
JELLYDONUT
```

## Verification
Run:

```sh
./solve.py
```

Expected output:

```text
JELLYDONUT
```

No flag was submitted automatically.
