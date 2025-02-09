# X Gon Give it to Ya

## Description

> DMX ain't giving you anything for free, but I might.
> Can you outsmart the randomness? Or will X leave you in the dust, *wondering where it all went wrong?*

- **Points**: 300
- **Given Files:** Output.txt & source code

## Goal of the challenge

Truly understand the mathematical properties of the **xor** operation, especially the fact that it's **commutative**.

---

### Output

Here are your blocks: [
 b"37bcbc36",
 b"21c7cba1",
 b"9ec95c67",
 b"3b13325b",
 b"7c8757f5",
 b"f7e180b9",
 b"37ef5a6f",
]

### Source Code

```python
#!/usr/bin/env python3

import os
from Crypto.Util.number import long_to_bytes, bytes_to_long
from pwn import xor
from binascii import hexlify

FLAG = "FL1TZ{?????????????????????}"

assert len(FLAG) == 28


# -----Ultra Secure Random Number Generator
class Random:
    def __init__(self, seed):
        self.state = seed

    def next(self):
        self.state = (self.state * 1103515245 + 12345) & 0xFFFFFFFF
        return long_to_bytes(self.state)


generator = Random(bytes_to_long(os.urandom(4)))
Xi = [generator.next() for _ in range(7)]

blocks = [FLAG[i : i + 4].encode() for i in range(0, len(FLAG), 4)]

for i in range(len(blocks)):
    for j in range(i + 1):
        blocks[i] = xor(blocks[i], Xi[j])
    blocks[i] = hexlify(blocks[i])

print(f"Here are your blocks: {blocks}")
```

## Solution Walkthrough

The first XOR value can be retrieved by xoring the first 4 characters of the flag format with the first block of the ciphertext.

Next, we create regenerate the keystream the same way as in the source code.

Finally, we xor the encrypted blocks in the same order as in the source code *(b0^X0, b1^X0^X1...)*

## Solver

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
from pwn import xor

enc = [
    b"37bcbc36",
    b"21c7cba1",
    b"9ec95c67",
    b"3b13325b",
    b"7c8757f5",
    b"f7e180b9",
    b"37ef5a6f",
]


flag = ["FL1T"]
enc = [bytes.fromhex(x.decode()) for x in enc]


class Random:
    def __init__(self, seed):
        self.state = seed

    def next(self):
        self.state = (self.state * 1103515245 + 12345) & 0xFFFFFFFF
        return long_to_bytes(self.state)


Xi = [bytes_to_long(xor(flag[0].encode(), enc[0]))]
gen = Random(Xi[0])
Xi = [long_to_bytes(Xi[0])]
for i in range(1, 7):
    Xi.append(gen.next())

f = enc
for i in range(len(enc)):
    for j in range(i + 1):
        f[i] = xor(f[i], Xi[j])

flag = "".join(a.decode() for a in f)
print(flag)
```

## Solution:

FL1TZ{x0rr_a1n't_4_th3_w3ak}
