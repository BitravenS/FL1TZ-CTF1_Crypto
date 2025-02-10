# RSEEE

## Description

> We all know what happens when e is small. So you won't need it, *right?*
> 
> Wrap whatever you find in **FL1TZ{}***

- **Points**: 400
- **Given Files:** Output & source code

## Goal of the challenge

The initial goal of the challenge was to make the player think smartly about the upper bounds of the bruteforce, but as it remained unsolved for hours I had to hint that e < 15, which made it feasible to let it run for a bit then manually increment e.

---

### Output

n = 97127064200566540941928678594867636803398339677296908159077174895749191256799557351118036403508090866875498452714025619485895754802360340694285870549792955221439057386006929730315481568817059312364553914087684084487261722012727425926234514741860807367636771201908481073590517580414773610725772307291721042623

ct = 48245654321634701455895626304137847336996478297713840323661725059931579994616044368900079069592410947349116320004205830982263945363378614707701788128068692459565222022474760276489584283877823711904548049874221945723734099832204867825444694649757841525189302154560568102716182029919362349113976190626358050904

### Source Code

```python
from Crypto.Util.number import getPrime, bytes_to_long
from math import gcd

p, q = getPrime(512), getPrime(512)

e = 5
phi = (p - 1) * (q - 1)
while gcd(e, phi) != 1:
    e += 2

d = pow(e, -1, phi)
n = p * q

FLAG = "????????????"
assert len(FLAG) == 12

m = bytes_to_long(FLAG.encode())
ct = pow(m, e, n)
print(f"{n = }\n\n{ct = }") 
```

---

## Solution Walkthrough

We know that  $c = m^e\mod n$ is equivalent to saying $m^e = c +k*n \ for \ k \ in \ \mathbb{N} $. We don't know *e* but we know that it isn't that far from 5.

Since we have to bruteforce k and e at the same time, an upper bound for k has to be set. What is that upper bound? It's **the ascii string that could be represented as the largest integer** - ct divided by n, approximatey.

so our upper bound is ${(255255...255^{current\_e\_value}-ct)}/n$. If the bound is reached, we increment e by 2 and calculate the $eth \ root$ of $ct+n*i$ for i in range(upper_bound)

In hindsight, this wan't a well implemented challenge as there is a much easier solution which is to just set up a resonably high bound and increment when it's reached :/

## Solver

```python
import gmpy2
from Crypto.Util.number import long_to_bytes


def is_perfect_nth_root(number, exp):
    if number < 0:
        # Negative numbers cannot have even roots
        return False

    # Compute the integer nth root
    root, exact = gmpy2.iroot(gmpy2.mpz(number), exp)
    return root, exact  # True if it's a perfect nth root, False otherwise


n = 97127064200566540941928678594867636803398339677296908159077174895749191256799557351118036403508090866875498452714025619485895754802360340694285870549792955221439057386006929730315481568817059312364553914087684084487261722012727425926234514741860807367636771201908481073590517580414773610725772307291721042623

ct = 48245654321634701455895626304137847336996478297713840323661725059931579994616044368900079069592410947349116320004205830982263945363378614707701788128068692459565222022474760276489584283877823711904548049874221945723734099832204867825444694649757841525189302154560568102716182029919362349113976190626358050904


e = 5
found = False
i = 0
while not found:
    for i in range(10**7):
        if i % 100000 == 0:
            print(f"e: {e}, i: {i}")
        pt, exact = is_perfect_nth_root(ct + n * i, e)
        if exact:
            try:
                print(f"Flag found: {long_to_bytes(pt).decode()}")
                found = True
            except UnicodeDecodeError:
                continue
    e += 2
```

## Solution:

FL1TZ{e's_Ea5y_bR0}
