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
