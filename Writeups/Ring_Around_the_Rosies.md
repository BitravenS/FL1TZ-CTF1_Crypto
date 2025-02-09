# Ring Around the Rosies

## Description

> Toujours en **avant**, jamais en arrière
> 
> Ciphertext: KR1BI{CAhbs_4fW_MkrLC_Xg_kTu}

- **Points**: 250

## Goal of the challenge

A custom cipher which won't be decoded right away using online tools. It will require more thinking and trial and error.

---

## Solution Walkthrough

Comparing the ciphertext to the flag format, we'll notice that the first character is shifted by 5 positions, the next one by 6 and so on...

Reversing that rotation while accomodating for the fact that **shifts wrap around** (Z shifted forward becomes A) gets us the flag.

---

## Solver

```python
def rotate_char(c, shift):

    if c.isalpha():
        shift %= 26
        base = ord("a") if c.islower() else ord("A")
        return chr((ord(c) - base + shift) % 26 + base)
    return c


def decrypt(encrypted_message, shift):

    decrypted_message = ""
    for i, char in enumerate(encrypted_message):
        decrypted_message += rotate_char(char, -(shift + i))
    return decrypted_message


if __name__ == "__main__":
    message = "KR1BI{CAhbs_4fW_MkrLC_Xg_kTu}"
    shift = 5

    decrypted = decrypt(message, shift)
    print(f"Decrypted: {decrypted}")

```

## Solution:

Decrypted: FL1TZ{ROund_4nD_RouND_We_gOo}
