# Colorblind

## Description

> The colors Mason, what do they mean?

- **Points**: 300
- **Given Files:** Output & source code

## Goal of the challenge

The goal is to sharpen the player's pattern recognitions skills and attention to detail when faced with an ambiguous situation.

---

### Output

Can be found in the challenge folder

![n =](/home/bitraven/Documents/FL1TZ-CTF1_Crypto/Crypto/colorblind/colorblind.png)

---

## Solution Walkthrough

All we have is the brightness of each square, so what it brightness in pixel value? it's the average of the r,g,b values in the RGB color space.

Since in 8-bit color mode (which is the most common), RGB values range between 0 and 255, we know that ASCII values also range between 0 and 255.

All we have to do is to map the R (or G or B) values of each square and convert it to an ascii character.

## Solver

```python
from PIL import Image


def decode_image_to_string(image_path, square_size=5):
    image = Image.open(image_path).convert("RGB")
    width, height = image.size

    num_squares = width // square_size
    decoded_string = ""

    for i in range(num_squares):
        left = i * square_size
        top = 0
        right = left + square_size
        bottom = top + square_size

        square = image.crop((left, top, right, bottom))

        r, g, b = square.getpixel((0, 0))

        ascii_value = r

        decoded_string += chr(ascii_value)

    return decoded_string


def main():
    image_path = "/home/bitraven/Documents/FL1TZ-CTF1/Crypto/colorblind/colorblind.png"

    square_size = 20
    decoded_string = decode_image_to_string(image_path, square_size)

    print(f"Decoded string: {decoded_string}")


if __name__ == "__main__":
    main()
```

## Solution:

Decoded string: FL1TZ{C4ll_4N_4MbulAnc3_but_n0t_f0r_m3}
