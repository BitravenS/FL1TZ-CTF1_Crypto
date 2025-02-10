# DMZ 1: Breach

## Description

> *The year is 2051. After a brutal nuclear war, the world has been left in shambles, ravaged by radiation and chaos.*
> 
> You are the last remaining survivor of a group who took refuge in a bunker. But as supplies and hope starts running low, you decide to put an end to this maddness all on your own.
> 
> There used to be a research facility, called *TerraGroup*, that was rumored to have a cure for the radiation. But the facility was abandoned and left to rot. **Can you find the cure and save the world?**

- **Points**: 500 ->150
- **Remote**
- **Given Files:** initially none but then the *solver xd*

## Goal of the challenge

The entire **DMZ** series was supposed to be an interactive and fun walkthrough to get the player more familiar with **Elliptic Curve** signatures and encryptions. Unfortunately, I underestimated their difficulty and all 4 DMZ challenges remained pretty much unsolved *(except for **Taha** who solved DMZ 2 on his own, you're **Goated**!)*.

This first DMZ challenge is an intro to one of the most common ECDSA vulnerabilities, which is the **weak nonce**, more specifically a *low nonce*.

---

## Solution Walkthrough

Throughout all of the DMZ challenges, the only way to solve it is to submit a **valid signature**, which is done differently in each challenge. Secondly, each challenge has an info section *(Firmware info, system settings...)* which is supposed to give the player the context behind the challenge *(Curve, Public key, Signature format and a hint at the vulnerability)*.

I've hinted that the nonce is weak, more specifically that $k<2^{16}$, which is reasonably bruteforceable within a couple of seconds. Retrieving k essentially gives you the private key which lets you forge any valid signature you want.

## Solver

```python
from pwn import *
import ecdsa
import base64
from Crypto.Util.number import bytes_to_long

HOST = "ctf.fl1tz.me"
PORT = 1006

io = remote(HOST, PORT)

curve = ecdsa.curves.NIST192p
io.sendline(b"3")
sent_message = b"literally anything"
io.sendline(sent_message)
io.recvuntil(b"signature: ")
sig = io.recvline().strip()
print(f"Signature: {sig}")

signature_bytes = base64.b64decode(sig)
# decode signature
s = bytes_to_long(signature_bytes[24:])
r = bytes_to_long(signature_bytes[:24])

print(f"r: {r}")
print(f"s: {s}")
G = curve.generator
n = curve.order

message = sent_message
H_m = int(hashlib.md5(message).hexdigest(), 16)

# Brute-force k
for k in range(1, 2**16):
    # Compute r = (k * G).x mod n
    kG = k * G
    r_candidate = kG.x() % n

    if r_candidate == r:
        print(f"Found k: {k}")
        # Recover private key d
        k_inv = pow(k, -1, n)
        d = (pow(r, -1, n) * (s * k - H_m)) % n
        print(f"Recovered private key d: {d}")
        break
else:
    print("No valid k found.")

priv_key = ecdsa.SigningKey.from_secret_exponent(d, curve)
message = b"literally anything else"
signature = priv_key.sign(message, hashfunc=hashlib.md5)
print(f"Signature: {signature.hex()}")
print(f"len signature: {len(signature)}")


forged_sig = base64.b64encode(signature)
io.recvuntil(b"$~ ")
io.sendline(b"1")
io.sendline(message)
io.sendline(forged_sig)
io.interactive()

```

## Solution:

FL1TZ{J3sS3_I_4M_Th3_1_wh0_N0nc3}
