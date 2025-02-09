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
