# Frou5 Li Tnagguez

## Description

> The FBI cracked down on a dangerous cybercrime organization that used to go by the name of *'Frou5 Li Tnagguez'.*
> 
> This organization was two steps ahead though, and got rid of all the evidence before the FBI could get to it, **except for a single poster** that was left behind.

- **Points**: 750
- **Given Files:** picture & ciphertext

## Goal of the challenge

The goal here is to understand the steps it took to create a cipher, and to reverse the steps in a particular manner while leveraging knowledge and general understanding of the challenge.

---

### Markdown

```markdown
# Frou5 Li Tnagguez

## Ciphertext

OXCCTQVOVHFHAJUKETHNYITZBVWZRUGSOPDCBTZPLNNJPFSVDSVFCZFDYQSXYQDXBWNTGLMYTRUOMQDUQFXUWPONLJMMACUWPNDNRVXDTVDUAGKROABCAWMOCYGFJDGQNFPMUHFTFLOLKUXKHCJUFMITIEGIMNSIRZUUYFPQWRDFQPTGJDSOYGYGBRHIKLHKNTOXFBLEWBQZQUMVPOLYBBKFVDULCHXJFJICQHYRBPDDTSASWOPPEMQAXNGFSFCJTXWXVUSTZFYZKFMGLKZNMAEHHLGHYSLZHTZRSGAVZHFTMXTCMWBNYSKUCNSWHMBLUUPSFOBAARGCRDCJYCEYUZLPLRJSQT

## Rules Reminder

- Numbers are spelled out (example: 8 -> EIGHT)
- _ becomes UNDRSCR
- } Becomes CLSBRCKT
- { becomes OPNBRCKT
```

### Picture

Can be found in the challenge folder

![a](/home/bitraven/Documents/FL1TZ-CTF1_Crypto/Crypto/frou5_li_tnagguez/flt.png)

---

## Solution Walkthrough

This is insiperd by a challenge called **Let's Play Scrabble 1** in ringzer0ctf, but with a twist, *literally*.

You could recreate the encryption scheme in python and, since the keyword is an english word, you could generate all alphabet keys and find the one which decodes the flag. You'll know it since it is unbelievably unlikely for 2 keys to have the same decoded word in the plaintext., basically find one that has the string **FLONETZOPNBRCKT**

## Solver

```python
import json
import os
import string

# Get the directory of the current script
script_dir = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(script_dir, "words_dictionary.json")

with open(file_path, "r") as f:
    words = json.load(f).keys()

flag = "FL1TZ{B0RN_2_N4GU3Z_4ND_W1LL_4LW4Y5_N4GU3Z_B4BY}"


class Hopper:
    def __init__(self, keyword):
        self.alpha = string.ascii_uppercase
        self.keyword = keyword.upper()
        self.initialAlpha()

    def initialAlpha(self):
        for i in self.keyword:
            self.shuffle(i)
        self.initial = self.alpha

    def shuffle(self, letter):
        i = 0
        try:
            i = self.alpha.index(letter)
        except Exception as e:
            print(f"{letter}: {e}")
        self.alpha = self.alpha[:i][::-1] + self.alpha[i] + self.alpha[i + 1 :][::-1]

    def encrypt(self, plaintext):
        self.alpha = self.initial
        plaintext = plaintext.upper()
        ciphertext = ""
        for i in plaintext:
            pos = string.ascii_uppercase.index(i)
            ciphertext += self.alpha[pos]
            self.shuffle(i)
        return ciphertext

    def decrypt(self, ciphertext):
        self.alpha = self.initial
        plaintext = ""
        for i in ciphertext:
            pos = self.alpha.index(i)
            corLet = string.ascii_uppercase[pos]
            plaintext += corLet
            self.shuffle(corLet)
        return plaintext


def flag_format(f):
    ret = ""
    for letter in f:
        if letter.isalpha():
            ret += letter
        else:
            match letter:
                case "0":
                    ret += "ZERO"
                case "1":
                    ret += "ONE"
                case "2":
                    ret += "TWO"
                case "3":
                    ret += "THREE"
                case "4":
                    ret += "FOUR"
                case "5":
                    ret += "FIVE"
                case "6":
                    ret += "SIX"
                case "7":
                    ret += "SEVEN"
                case "8":
                    ret += "EIGHT"
                case "9":
                    ret += "NINE"
                case "_":
                    ret += "UNDRSCR"
                case "{":
                    ret += "OPNBRCKT"
                case "}":
                    ret += "CLSBRCKT"
                case _:
                    raise ValueError(f"Invalid character: {letter}")
    return ret


def flag_unformat(f):
    ret = ""
    temp = f
    while temp:
        if temp.startswith("ZERO"):
            ret += "0"
            temp = temp[4:]
        elif temp.startswith("ONE"):
            ret += "1"
            temp = temp[3:]
        elif temp.startswith("TWO"):
            ret += "2"
            temp = temp[3:]
        elif temp.startswith("THREE"):
            ret += "3"
            temp = temp[5:]
        elif temp.startswith("FOUR"):
            ret += "4"
            temp = temp[4:]
        elif temp.startswith("FIVE"):
            ret += "5"
            temp = temp[4:]
        elif temp.startswith("SIX"):
            ret += "6"
            temp = temp[3:]
        elif temp.startswith("SEVEN"):
            ret += "7"
            temp = temp[5:]
        elif temp.startswith("EIGHT"):
            ret += "8"
            temp = temp[5:]
        elif temp.startswith("NINE"):
            ret += "9"
            temp = temp[4:]
        elif temp.startswith("UNDRSCR"):
            ret += "_"
            temp = temp[7:]
        elif temp.startswith("OPNBRCKT"):
            ret += "{"
            temp = temp[8:]
        elif temp.startswith("CLSBRCKT"):
            ret += "}"
            temp = temp[8:]
        else:
            ret += temp[0]
            temp = temp[1:]
    return ret


def main():
    cipher = "OXCCTQVOVHFHAJUKETHNYITZBVWZRUGSOPDCBTZPLNNJPFSVDSVFCZFDYQSXYQDXBWNTGLMYTRUOMQDUQFXUWPONLJMMACUWPNDNRVXDTVDUAGKROABCAWMOCYGFJDGQNFPMUHFTFLOLKUXKHCJUFMITIEGIMNSIRZUUYFPQWRDFQPTGJDSOYGYGBRHIKLHKNTOXFBLEWBQZQUMVPOLYBBKFVDULCHXJFJICQHYRBPDDTSASWOPPEMQAXNGFSFCJTXWXVUSTZFYZKFMGLKZNMAEHHLGHYSLZHTZRSGAVZHFTMXTCMWBNYSKUCNSWHMBLUUPSFOBAARGCRDCJYCEYUZLPLRJSQT"
    for word in words:
        hopper = Hopper(word)
        decipher = hopper.decrypt(cipher)
        if "FLONETZOPNBRCKT" in decipher:
            print(f"KEY: {word}")
            print(f"FLAG: {flag_unformat(decipher)}")
            break


if __name__ == "__main__":
    main()
```

## Solution:

THEREISANONGOINGRACETOPUSHTHEBITCOINENCRYPTIONTOITSLIMITSCALLEDTHE32BTCCHALLENGE **FL1TZ{B0RN_2_N4GU3Z_4ND_W1LL_4LW4Y5_N4GU3Z_B4BY}** ITWENTUPTOALMOST1000BTCFORANY1BRAVEENOUGHTOGIVEITATRYANDYOUREDAMNRIGHTFROU5LITNAGGUEZWILLBEONTHEFRONTLINES
