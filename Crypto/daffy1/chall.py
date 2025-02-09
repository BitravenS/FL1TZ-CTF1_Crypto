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
