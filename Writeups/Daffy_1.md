# Daffy 1

## Description

> Would you be the *Diffie*  to my *Hellman*  🥺👉👈

- **Points**: 400
- **Given Files:** Output & source code

## Goal of the challenge

Step away from the used and abused RSA encryption to other public key encryption schemes. This one is supposed to geth the player familiar with the **Diffie Hellman** encryption by intrducing a basic *small order attack*.

---

### Output

```markdown
p = 335828589845279
g = 11
A = 105184740584178
B = 257292025029694
enc = 'ab624c529eb96fe0b9ece0d7e646c7d6e9e6e49f026d579d42f1a85b7ec67525c620c4d5a2124ae57e638eef84fbf985'
```



### Source Code

```python
from sage.all import *
from Crypto.Util.number import getPrime, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def generate_small_prime_modulus():
    p = getPrime(48)
    return 2 * p + 1


def diffie_hellman_public_key(p, g, private_key):
    return pow(g, private_key, p)


p = generate_small_prime_modulus()
while True:
    try:
        g = primitive_root(p)
        break
    except ValueError:
        p = generate_small_prime_modulus()

private_key_a = randint(1, p)
private_key_b = randint(1, p)
A = diffie_hellman_public_key(p, g, private_key_a)
B = diffie_hellman_public_key(p, g, private_key_b)
S = diffie_hellman_public_key(p, A, private_key_b)

FLAG = b"FL1TZ{?????????????????????????}"
cipher = AES.new(pad(long_to_bytes(S), 16)[:16], AES.MODE_ECB)
enc = cipher.encrypt(pad(FLAG, 16))

output = f"p = {p}\ng = {g}\nA = {A}\nB = {B}\nenc = '{enc.hex()}'"
print(output)

```

---

## Solution Walkthrough

When the modulus is small in RSA, it is prone to being factored, but in **DH**, it is prone to a vulnerability we call **the discrete logarithm**.

To give you some insight, we have a value *g* which is the generator, and a value *p* which is the order of the cyclic group (like *n* in RSA).

Next, each side of the communication we generate a secret value *a < p* called the **private key**. It becomes the exponent to the generator to get the public key *A*.

If the other side generated their own private key *b* and public key *B*, sending it to the otehr party enable a secure key exchange called the **Diffie Hellman key exchange**, because if a *man in the middle* intercepts A and B, he has no idea about the secret key $S = A^b[p]=B^a[p]$ which both sides of the communication Know.

Now back to the challenge, all we have to do is to compute the discrete log of A with respect to g in the finite field $\mathbb{F}_p$. This will give us the private key *a* which can enable us to retrieve S and decrypt the flag.

## Solver

```python
p = 335828589845279
g = 11
A = 105184740584178
B = 257292025029694
enc = "ab624c529eb96fe0b9ece0d7e646c7d6e9e6e49f026d579d42f1a85b7ec67525c620c4d5a2124ae57e638eef84fbf985"


from sage.all import *
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from binascii import unhexlify

R = GF(p)
A = R(A)
G = R(g)

n = discrete_log(A, G)
print(f"n = {n}")
S = pow(B, n, p)
key = pad(long_to_bytes(S), 16)[:16]

cipher = AES.new(key, AES.MODE_ECB)
flag = cipher.decrypt(unhexlify(enc))
print(flag)

```

## Solution:

b"FL1TZ{w3're_4ll_34r5_4nd_0n3s_4nd_z3r05}\x08\x08\x08\x08\x08\x08\x08\x08"
