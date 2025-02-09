def rotate_char(c, shift):

    if c.isalpha():
        shift %= 26
        base = ord("a") if c.islower() else ord("A")
        return chr((ord(c) - base + shift) % 26 + base)
    return c


def encrypt(message, shift):

    encrypted_message = ""
    for i, char in enumerate(message):
        encrypted_message += rotate_char(char, shift + i)
    return encrypted_message


if __name__ == "__main__":
    message = "FL1TZ{ROund_4nD_RouND_We_gOo}"
    shift = 5

    encrypted = encrypt(message, shift)
    print(f"Encrypted: {encrypted}")
