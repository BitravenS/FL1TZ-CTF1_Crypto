# RS Ayyooo?!

## Description

> Factoring out big numbers might be hard, but factoring out the truth is even harder.
> 
> Can you find the pattern in the **chaos**?

- **Points**: 1000
- **Remote Task**

## Goal of the challenge

This challenge is heavily inspired from anothre one i played on picoCTF where each character of the flag is encrypted individually, with the flag being the concatenation of each encrypted character. I wanted to implement that element of pattern recognition with a bit of extra Xor knowledge.

---

## Solution Walkthrough

That long ciphertext is frightening isn't it? Isni't the ciphertext supposed to be$\mod n$ ? so why is it longer than n?

If you begin testing, you'll find that **a** gives a cipher $ca$ and **aa** bives $ca0$, **b** gives $cb$ but **ab** gives $caSOMETHING$. If you do some analysis on that *something* as you should in crypto, you'll find that it's $ca \ xor \ cb$.

With that knowledge, you can calcualte $cX$ for each ascii character and reverse the xor operation.

## Solver

```python
from pwn import *
from string import ascii_letters, digits, punctuation

HOST = "ctf.fl1tz.me"
PORT = 1003

io = remote(HOST, PORT)

io.recvuntil(b"> ")
enc = io.recvline().strip().decode()
io.recvuntil(b"e: ")
e = int(io.recvline().strip().decode())
io.recvuntil(b"n: ")
n = int(io.recvline().strip().decode())
io.recvuntil(b"try? ")
io.sendline(b"256")

charset = ascii_letters + digits + punctuation
mapping = {}
io.recvuntil(b"exit\n")
for p in charset:
    io.recvuntil(b"> ")
    io.sendline(p.encode())
    en = io.recvuntil(b"\n\n").decode().split("\n")[1]
    mapping[p] = en
char = "F"
flag = char
enc = enc[len(mapping["F"]) :]
for _ in range(50):
    for k, v in mapping.items():
        print(f"Trying {k}")
        test = hex(int(mapping[k], 16) ^ int((mapping[char]), 16))[2:]
        if enc.startswith("0"):
            flag += char
            enc = enc[1:]
            print(flag)
            break
        if enc.startswith(test):
            char = k
            flag += char
            enc = enc[len(test) :]
            print(flag)
            break
    if char == "}":
        break

```

## Solution:

FL1TZ{A_2nD_X0R_h1t_th3_Ctf!!}
