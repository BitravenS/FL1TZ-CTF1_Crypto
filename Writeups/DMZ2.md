# DMZ 2: Power Grid

## Description

> We're past the gate, but it's only the beginning... We need to get the power back online, but the system is locked down tight.

- **Points**: 750
- **Remote**

## Goal of the challenge

In the theme of ECDSA, this one exploits another vulnerability called **Signature Malleability** which enables a signature {r,s} to derive another valid signature {r,-s} due to the nature of elliptic curves being symmetric in relation to the $x$ axis.

---

## Solution Walkthrough

The signature is DER encoded which is supposed to protect the system against signature malleability attacks, but as hinted in the challenge *it is not strictly enforced*!

All we have to do is retrive the signature with the *Jumpstart* function, extract s, compute $-s \mod BrainPool384r1_{order}$   and forge a signature with the same *r* and the forged s.

## Solver

```python
from pwn import *
import ecdsa
import base64
from ecdsa.util import sigdecode_der, sigencode_der

HOST = "ctf.fl1tz.me"
PORT = 1008

io = remote(HOST, PORT)

curve = ecdsa.curves.BRAINPOOLP320r1

# Step 1: Jump start to get a valid signature
io.sendline(b"3")
io.recvuntil(b"generated: ")
sig = io.recvline().strip().decode()
print(f"Signature: {sig}")

# Decode the base64 signature
signature_bytes = base64.b64decode(sig)
print(f"Signature bytes: {signature_bytes.hex()}")

# Decode the DER signature to get r and s
r, s = sigdecode_der(signature_bytes, curve.order)
print(f"Original r: {r}")
print(f"Original s: {s}")

# Compute the malleable s value
n = curve.order  # Order of the curve
s_malleable = (-s) % n  # Compute -s mod n
print(f"Malleable s: {s_malleable}")

# Re-encode the malleable signature in DER format
malleable_signature = sigencode_der(r, s_malleable, n)
print(f"Malleable Signature (DER encoded): {malleable_signature.hex()}")

# Base64 encode the malleable signature
payload = base64.b64encode(malleable_signature).decode()
print(f"Payload: {payload}")

io.sendline(b"1")
io.sendline(payload.encode())
io.interactive()

```

## Solution:

FL1TZ{D1dn't_kn0w_s1Gn4tur3s_h4d_TH3m_51CK_m0v3S}
