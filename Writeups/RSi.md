# RSEEE

## Description

> A group of scientist just discovered a breakthrogh in the field of public key encryption. By using the power of complex numbers, they were able to supass the security of **2048-bit RSA** with a **52-bit Complex key**. Can you prove them wrong?

- **Points**: 750
- **Given Files:** Output & source code

## Goal of the challenge

During my search for a creative idea, I recalled a bitcoin puzzle I participated in a few weeks prior where i followed afake lead using *complex numbers* and stuff, so i thought of cool ways to incorporate complex numbers in crypto challenges.

To my surprise, **all RSA properties work in the complex number plane!**

This is intended to make the player more vigil when faced with unfamiliar twists to familiar schemes, and to make them truly understand the mathematical properties that make RSA *RSA!*

---

### Output

```
n: 8730899982339406121989621835457*I - 3712381100155683307088523093020

Encrypted flag: [1233338029200489896637139594528*I - 1070796367993161315391239676281,
 1372344260315429169123388069334*I + 2686762584715604836306469168454,
 -282291658691867831207444215720*I - 3238506002711154190022050829295,
 -4034394468793877364674172212928*I - 530934400531020604653696597205,
 2528773627660911742407855541153*I + 3217517986460866119597510311817,
 -2829025903203263159924729177463*I + 5405682305299103765077091336449]
```

### Source Code

```python
from sage.all import *
from Crypto.Util.number import getRandomInteger, bytes_to_long, long_to_bytes
from pprint import pprint


def pad_bytes(data, block_size):
    padding_length = block_size - len(data) % block_size
    padded_data = data.ljust(len(data) + padding_length, b"\x00")
    return padded_data


FLAG = pad_bytes(b"FL1TZ{??????????????????????????}", 8)

ZI = GaussianIntegers()


class Complex_RSA:
    def __init__(self, bits):
        self.p = gen_gaussian_prime(bits)
        self.q = gen_gaussian_prime(bits)
        self.phi = euler_totient(self.p, self.q)
        self.e = 0x10001
        while gcd(self.e, self.phi) != 1:
            self.p = gen_gaussian_prime(bits)
            self.q = gen_gaussian_prime(bits)
            self.phi = euler_totient(self.p, self.q)
        self.n = ZI(self.p * self.q)
        self.d = inverse_mod(self.e, self.phi)

    def encrypt(self, m):
        if m.norm() >= self.n.norm():
            raise ValueError("Message is too large")
        return gaussian_powmod(m, self.e, self.n)

    def decrypt(self, c):
        return gaussian_powmod(c, self.d, self.n)


def gen_gaussian_prime(bits):
    limit = bits
    for _ in range(10):
        a = getRandomInteger(bits)
        b = getRandomInteger(bits)
        for i in range(-limit + a, limit + 1 + a):
            for j in range(-limit + b, limit + 1 + b):
                z = i + j * I
                if is_gaussian_prime(z):
                    return ZI(z)
    raise ValueError("Failed to generate a Gaussian prime")


def gaussian_powmod(z, exponent, modulus):
    result = ZI(1)
    z = ZI(z)
    modulus = ZI(modulus)

    while exponent > 0:
        if exponent % 2 == 1:
            result = gaussian_mod(result * z, modulus)
        z = gaussian_mod(z * z, modulus)
        exponent = exponent // 2

    return result


def gaussian_mod(a, b):
    quotient = (a * b.conjugate()) / (b.norm())
    q_real = quotient.real().round()
    q_imag = quotient.imag().round()
    q = q_real + q_imag * I
    remainder = a - q * b
    return remainder


def is_gaussian_prime(z):
    if z == 0:
        return False
    a, b = z.real(), z.imag()
    if a == 0:
        return is_prime(ZZ(b)) and b.norm() % 4 == 3
    if b == 0:
        return is_prime(ZZ(a)) and a.norm() % 4 == 3
    return is_prime(ZZ(z.norm()))


def euler_totient(p, q):
    return (p.norm() - 1) * (q.norm() - 1)


def message_to_complex(m):
    return ZI(bytes_to_long(m[: len(m) // 2]) + bytes_to_long(m[len(m) // 2 :]) * I)


def complex_to_message(m):
    return long_to_bytes(int(m.real())) + long_to_bytes(int(m.imag()))


def main():
    rsa = Complex_RSA(52)
    print(f"n: {rsa.n}\n")

    enc = []
    blocks = [FLAG[i : i + 8] for i in range(0, len(FLAG), 8)]

    for b in blocks:
        m = message_to_complex(b)
        c = rsa.encrypt(m)
        enc.append(c)

    print(f"Encrypted flag: ", end="")
    pprint(enc)
    dec = []
    for c in enc:
        m = rsa.decrypt(c)
        dec.append(complex_to_message(m))
        print(dec)
    print((b"".join(dec)).decode())


if __name__ == "__main__":
    main()
```

#### PS: The source code initially had some obfuscated functions, but as no one solved it initially I had to expose the full code.

---

## Solution Walkthrough

Seeing complex numbers has surely stuck some fear in people! But all you have to do is to treat this just like bormal RSA!

We notice that the modulus *n* is approximately equivalent to a **100 bit** integer. And if this was normal RSA we'd factor that small modulus, and that's what we do here!

In complexe numbers thoug, we have what are called **gaussian primes** which are equivalent to prime factors in real numbers, and writing functions for that is relatively easy to do in python. 

Once factored, we compute d and phi, *just like in RSA* and proceed with the decryption.

## Solver

```python
from sage.all import *
from Crypto.Util.number import getRandomInteger, bytes_to_long, long_to_bytes


ZI = GaussianIntegers()


def factor_gaussian_integer(n):
    return n.factor()


def gaussian_powmod(z, exponent, modulus):
    result = ZI(1)
    z = ZI(z)
    modulus = ZI(modulus)

    while exponent > 0:
        if exponent % 2 == 1:
            result = gaussian_mod(result * z, modulus)
        z = gaussian_mod(z * z, modulus)
        exponent = exponent // 2

    return result


def gaussian_mod(a, b):
    quotient = (a * b.conjugate()) / (b.norm())
    q_real = quotient.real().round()
    q_imag = quotient.imag().round()
    q = q_real + q_imag * I
    remainder = a - q * b
    return remainder


def euler_totient(p, q):
    return (p.norm() - 1) * (q.norm() - 1)


def complex_to_message(m):
    return long_to_bytes(int(m.real())) + long_to_bytes(int(m.imag()))


def message_to_complex(m):
    return ZI(bytes_to_long(m[: len(m) // 2]) + bytes_to_long(m[len(m) // 2 :]) * I)


def main():
    n = ZI(8730899982339406121989621835457 * I - 3712381100155683307088523093020)
    enc = [
        1233338029200489896637139594528 * I - 1070796367993161315391239676281,
        1372344260315429169123388069334 * I + 2686762584715604836306469168454,
        -282291658691867831207444215720 * I - 3238506002711154190022050829295,
        -4034394468793877364674172212928 * I - 530934400531020604653696597205,
        2528773627660911742407855541153 * I + 3217517986460866119597510311817,
        -2829025903203263159924729177463 * I + 5405682305299103765077091336449,
    ]

    enc = [ZI(c) for c in enc]
    fac = list(factor_gaussian_integer(n))
    p, q = ZI(fac[0][0]), ZI(fac[1][0])
    phi = euler_totient(p, q)
    d = inverse_mod(0x10001, phi)
    print(f"p: {p}\nq: {q}\nd: {d}\n")
    m = [complex_to_message(gaussian_powmod(c, d, n)) for c in enc]
    print(b"".join(m))


if __name__ == "__main__":
    main()
```

## Solution:

FL1TZ{s0m3BOdy_g3T_G4USS_0ut_of_my_H34D!!!}
