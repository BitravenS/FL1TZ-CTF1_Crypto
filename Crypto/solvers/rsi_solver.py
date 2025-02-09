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
