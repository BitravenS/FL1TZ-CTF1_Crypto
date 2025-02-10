# DMZ 3: LABS

## Description

> As we get closer to the cure, the guardrails get raised even higher. We need to get to access the labs, *but how?*

- **Points**: 1000
- **Remote**

## Goal of the challenge

Now going back in the basics of ECDSA, but in a slightly *twisted* way. Instead of showing a blantantly obvious nonce reuse, it is hidden in the logs where one out of the 30 scientists used the same signature to enter and exit. This is supposed to sharpen the player's attention to detail and get them more combortable with ECDSA in general.

Unfortunately, this challenge remained unsolved for the entirety of the ctf despite releasing the source code with made the vulnerability quite obvious in my opinion.

---

## Solution Walkthrough

We need to remember the goal, which is **to forge a valid signature**. In this case, the only way to forge a signature is to exploit vulnerabilities in preexisting signatures. And how many signatures do we have? *A bunch of of them!* 60 to be exact, 2 for each of the 30 scientists.

Now, what can we deduce from this? For starters, we can try one of the previous vulnerabilities *(small nonce and signature malleability)* but you'll soon find than none of them yield the flag.

We need to look for another vulnerability to exploit, and one of the most common that you'll find when reading about ECDSA is the **nonce reuse attack**!

This could be spotted by examining every signature and spotting ones with the same prefix-*i.e: the same **r** value*.

I made it easier by encoding the signature by Raw concatenation, but keeping it complicated enough by sending 60 signatures.

Extracting each oner of them and their corresponding message *(ENTRY/EXIT AT {TIME})*  we could compute the hash of the message as weel as comparing *r values*.

Parsing all 60 signatures will yield 2 signatures with a reused nonce.

### Given two signatures:

For two messages \( m_1 \) and \( m_2 \), signed with the same nonce \( k \), the signatures are:

$$
s_1 = k^{-1} (m_1 + r d) \mod n
$$

$$
s_2 = k^{-1} (m_2 + r d) \mod n
$$

where:

- \( r \) is the \( x \)-coordinate of the ephemeral public key \( R \),
- \( s_1, s_2 \) are the two signature components,
- \( d \) is the private key,
- \( k \) is the nonce (same for both signatures),
- \( n \) is the order of the elliptic curve group.

### Step 1: Eliminate \( k \)

Rewriting the equations:

$$
k = (m_1 + r d) s_1^{-1} \mod n
$$

$$
k = (m_2 + r d) s_2^{-1} \mod n
$$

Since \( k \) is the same in both cases, we equate:

$$
(m_1 + r d) s_1^{-1} \equiv (m_2 + r d) s_2^{-1} \pmod{n}
$$

### Step 2: Solve for \( d \)

Rearrange the equation:

$$
m_1 s_1^{-1} + r d s_1^{-1} \equiv m_2 s_2^{-1} + r d s_2^{-1} \pmod{n}
$$

$$
r d s_1^{-1} - r d s_2^{-1} \equiv m_2 s_2^{-1} - m_1 s_1^{-1} \pmod{n}
$$

Factor out \( d \):

$$
r d (s_1^{-1} - s_2^{-1}) \equiv m_2 s_2^{-1} - m_1 s_1^{-1} \pmod{n}
$$

Solve for \( d \):

$$
d \equiv \frac{m_2 s_2^{-1} - m_1 s_1^{-1}}{r (s_1^{-1} - s_2^{-1})} \pmod{n}
$$

$d$ here is the public key, which we can use to forge the signature for the given message "ENTRY AT {Time}"

## Solver

```python
from pwn import *
import ecdsa
import base64
import hashlib
from Crypto.Util.number import bytes_to_long

HOST = "ctf.fl1tz.me"
PORT = 1010

io = remote(HOST, PORT)

curve = ecdsa.curves.SECP256k1

io.sendline(b"2")
io.recvuntil(b"$")

# Retrieve logs and parse them to get names, messages and signatures
logs = io.recvuntil(b"$").decode()
logs = logs.split("\n")
logs = [l for l in logs if l.startswith("\t") or l.startswith("[")]
entries = [l for l in logs if l.startswith("[")]
messages = [l.split('"')[1] for l in logs if l.startswith("\t")]
signatures = [l.split(" ")[-1] for l in logs if l.startswith("\t")]

# Parsing the names and storing them in a list
names = []
for entry in entries:
    parts = entry.split("] ")
    action = parts[1]

    if "entered the LABS" in action:
        name = action.split(" entered the LABS")[0]
        names.append(name)
    else:
        name = action.split(" left the LABS")[0]
        names.append(name)


print("Looking for reused nonces")


# Looking for reused nonces
def disass_signature(sig):
    sig = base64.b64decode(sig)
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    return r, s


# Initaializing our target variables
target = ""
hashed = []
target_r = 0
target_s = []
found = False
for i, sig1 in enumerate(signatures):
    r1, s1 = disass_signature(sig1)
    for j, sig2 in enumerate(signatures):
        r2, s2 = disass_signature(sig2)
        if r1 == r2 and i != j:
            target = names[i]
            hashed = [messages[i], messages[j]]
            target_r = r1
            target_s = [s1, s2]
            print(f"Reused nonce found for {target}")
            found = True
            break
    if found:
        break

# Compute the private key from the reused nonce
hashed = [bytes_to_long(hashlib.sha256(h.encode()).digest()) for h in hashed]
s1 = target_s[0]
s2 = target_s[1]
z1 = hashed[0]
z2 = hashed[1]
n = curve.order

s_diff = (s1 - s2) % n
k = ((z1 - z2) * pow(s_diff, -1, n)) % n
r_inv = pow(target_r, -1, n)
d = ((k * s1 - z1) * r_inv) % n
print(f"Private key: {d}")

# Deriving a signing key from the private key
priv_key = ecdsa.SigningKey.from_secret_exponent(d, curve=curve)
io.sendline(b"1")
io.sendline(target.encode())

# Forge a signature as the target for the given message
message = io.recvuntil(b'" :').decode().split('"')[1]
print(f"Message: {message}")
forged_signature = priv_key.sign(message.encode(), hashfunc=hashlib.sha256)
forged_signature = base64.b64encode(forged_signature).decode()
print(f"Forged signature: {forged_signature}")
io.sendline(forged_signature.encode())
io.interactive()
```

## Solution:

FL1TZ{Try_th4t_1t_T4Rk0V_LABS}
