# Aneurysm

## Description

> I'm convinced that my 5-year-old nephew is secretly an alien. He drew this on napkin and I'm trying to make sense of it.
> 
> Either I'm insane or he its, which one is it?
> 
> Format: FL1TZ{WHATEVER_YOU_FIND}

- **Points**: 350
- **Given Files:** picture

## Goal of the challenge

We go further from encryptions and closer to classic encoding. The goal is for the player to get familiar with **Cryptograms**, you know, those puzzles you find in the back of magazines!

---

### Picture

Can be found in the challenge folder

![o](/home/bitraven/Documents/FL1TZ-CTF1_Crypto/Crypto/aneurysm/aneurysm.png)

---

## Solution Walkthrough

That looks like total jibberish, what can we make of it? Reverse searching these symbols yields nothing *because I madde them myself ;)*, so.. what do we know?

We know that this is supposed to be an english sentence, so how do we map it to that sentence? We first map each symbol to a specific letter in the english alphabet. **IT DOESN' MATTER WHICH ONE!** As long as they are placed exactly where their corresponding symbol is placed, we're good.

We'll obtain something like this: *ABCDEC FG HDICJKH FL H MKCHN* or ZYXWVX UT SWRXQPS UO S NPXSM or **literally anythin, as long as the letters are repeated accordingly and words have the same number of characters!** Try to shift these, they'll still work!

Next, we solver the cryptogram. My favourite tool is [quipquip](https://quipqiup.com/), decoding it there gives us the sentence.

## Solution:

 TWELVE IN ALGEBRA IS A DREAM
