# Daffy 2

## Description

> **Divide and conquer**, like the good ol' days

- **Points**: 400
- **Given Files:** Output & source code

## Goal of the challenge

Another **Diffie Hellman** challenge where the goal is to find a small subgroup of P, enabling a faster discrete log solution.

---

### Output

```markdown
p = 6656718232458761459
g = 2935108384184395490
A = 3105620703593928166
B = 3336228556894758347
enc = 136590391974ffef5a78fad686e0cae4ff3b12e64bdff6d8ed258d72efda7f35

```

### Source Code

```python
from sage.all import *
from Crypto.Util.number import getPrime, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def generate_vulnerable_modulus():
    while True:
        small_prime = random_prime(2**16)
        r = getPrime(48)
        q = r * small_prime
        p = 2 * q + 1
        if is_prime(p):
            return p, small_prime, r


def find_vulnerable_generator(p, small_prime):
    G = Integers(p)
    order = p - 1

    while True:
        h = G.random_element()
        if h.is_unit():
            g = power_mod(int(h), 2 * (order // (2 * small_prime)), p)
            if g != 1:
                g_elem = G(g)
                if g_elem.multiplicative_order() == small_prime:
                    return int(g)


p, small_prime, r = generate_vulnerable_modulus()
g = find_vulnerable_generator(p, small_prime)

private_key_a = randint(2, p - 1)
private_key_b = randint(2, p - 1)

A = power_mod(g, private_key_a, p)
B = power_mod(g, private_key_b, p)
S = power_mod(A, private_key_b, p)

FLAG = b"FL1TZ{????????????????????}"
key = long_to_bytes(S)[:16]
cipher = AES.new(pad(key, 16), AES.MODE_ECB)
enc = cipher.encrypt(pad(FLAG, 16))

output = f"""p = {p}
g = {g}
A = {A}
B = {B}
enc = {enc.hex()}"""

print(output)

```

---

## Solution Walkthrough

Like the other one, this one requires a *discrete log calculation* which is supposed to be harder with the bigger prime, making a small subgroup attack the only solution, *theoretically*.

Unfortunately, I made this challenge in a rush as it was part of the second wave of challenges, and I later realized that the primes weren't big enough and that this one could practically solved using the solver from *Daffy 1* xd.

## Solver

```python
from sage.all import *
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import pad

p = 6656718232458761459
g = 2935108384184395490
A = 3105620703593928166
B = 3336228556894758347
enc = "136590391974ffef5a78fad686e0cae4ff3b12e64bdff6d8ed258d72efda7f35"


def find_small_order():
    G = Integers(p)
    g_elem = G(g)
    return g_elem.multiplicative_order()


def solve_discrete_log(base, target, order, modulus):
    G = Integers(modulus)
    return discrete_log(G(target), G(base), ord=order)


def decrypt_flag(shared_secret, encrypted_data):
    key = pad(long_to_bytes(shared_secret), 16)[:16]

    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(bytes.fromhex(encrypted_data))


def main():
    small_order = find_small_order()
    print(f"[+] Found generator order: {small_order}")

    try:
        priv_key_b = solve_discrete_log(g, B, small_order, p)
        print(f"[+] Found private key b mod {small_order}: {priv_key_b}")
    except ValueError as e:
        print(f"[-] Error solving discrete log: {e}")
        return

    S = power_mod(A, priv_key_b, p)
    print(f"[+] Calculated shared secret: {S}")

    try:
        decrypted = decrypt_flag(S, enc)
        print(f"[+] Decrypted flag: {decrypted}")
    except Exception as e:
        print(f"[-] Error decrypting: {e}")


if __name__ == "__main__":
    main()

```

## Solution:

[+] Decrypted flag: b"FL1TZ{ducK's_1n_7h3_m1ddL3_!}\x03\x03\x03"
