from Crypto.Util.number import getPrime, bytes_to_long
from math import gcd

p, q = getPrime(512), getPrime(512)

e = 65537
phi = (p - 1) * (q - 1)
while gcd(e, phi) != 1:
    p, q = getPrime(512), getPrime(512)
    phi = (p - 1) * (q - 1)

d = pow(e, -1, phi)
n = p * q
HINT = phi * p

FLAG = "FL1TZ{??????????????????????}"

m = bytes_to_long(FLAG.encode())
ct = pow(m, e, n)
print(f"{n = }\n\n{ct = }\n\n{HINT = }")
