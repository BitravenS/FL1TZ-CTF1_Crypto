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
