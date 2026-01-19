---
title: "GDUCTF 2025"
description: "Writeup for Crypto & Reverse Challenge"
summary: "Writeup for Crypto & Reverse Challenge"
categories: ["Writeup"]
tags: ["Crypto", "Reverse", "Vietnamese"]
#externalUrl: ""
date: 2025-06-29
draft: false
authors:
  - ducnocrypt
cover: "/images/post_covers/gductf-2025.png"
---


## Cycles


### Mục tiêu
Tìm flag bằng cách thu hồi lại giá trị `a` từ phương trình:
$hint = g^a \pmod{p}$
Sau đó dùng `a` làm key AES để giải mã `ciphertext`.

###  Thông tin thu được
Từ các file `main.py` và `cycles.txt`, ta có:
- `g = 3`
- `p` là một số nguyên tố lớn
- `hint = 1`
- `ciphertext`: 48 bytes, mã hóa bằng AES ECB
- **Mã hóa AES**:
    ```python
    key = long_to_bytes(a)[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(pad(flag, AES.block_size))
    ```
    👉 AES sử dụng 16 byte đầu tiên của `a` làm key.

###  Phân tích kỹ thuật
:::info
**Dòng quan trọng:** `$hint = \text{pow}(g, a, p)$`
- Biết rằng: `hint = 1`
- → Tức là: $g^a \equiv 1 \pmod{p}$
:::

###  Phân tích toán học
**Mục tiêu**: Giải phương trình rời rạc $3^a \equiv 1 \pmod{p}$.
- **Khi nào $g^a \equiv 1 \pmod{p}$?**
Điều này xảy ra khi `a` là bội của cấp của `g` trong modulo `p`.
$a \equiv 0 \pmod{\text{ord}_p(g)}$
- Tức là: $a = k \times \text{ord}_p(g)$
- Vì `g = 3` và `p` là số nguyên tố lớn → theo **Định lý Fermat nhỏ**: $g^{(p-1)} \equiv 1 \pmod{p}$.
- Nếu `g` là phần tử nguyên thủy modulo `p` thì $\text{ord}_p(g) = p - 1$.
- => **Khi `hint = 1` → suy ra: $a = k \times (p - 1)$**
- → Giá trị `a` là một bội số của `(p - 1)`.

###  Quy trình giải

1.  **Nhận ra cấu trúc**
    - `hint` = $g^a \pmod{p} = 1$
    - Suy ra $a = k \times (p - 1)$ với $k \in [1, N]$.
    - → Ta có thể brute-force các giá trị `k` nhỏ.
2.  **Tạo AES key từ `a`**
    - Convert `a` sang bytes.
    - Lấy `key` là 16 bytes đầu tiên của `a`.
    - Dùng AES ECB để giải mã:
        ```python
        cipher = AES.new(key, AES.MODE_ECB)
        pt = unpad(cipher.decrypt(ciphertext), AES.block_size)
        ```
3.  **Kiểm tra kết quả**
    - Nếu `plaintext` có thể decode UTF-8 và có dạng flag hợp lệ → **Thành công!**

### Script Solve
```python
#!/usr/bin/env python3
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Public parameters from challenge
g = 3
p = 121407847840823587654648673057258513248172487324370407391241175652533523276605532412599555241774504967764519702094283197762278545483713873101436663001473945726106157159264352878998534133035299601861808839807763182625559052896295039354029361792893109774218584502647139466059910154701304129191164513825925289381

ciphertext = b'\xd1R\xb2\xb1\x1f\x9d\xbe\xfd\xe94\x84\x8c;\xcc\xc2\x95\xe3:\xf8 \x9d\xbfT\xba\xf8H<n\xdb\x86l\x10\xfdD\xb8\x1f\x12E1\xd4\xda\xe4\xa0\xd7\xda\t\x90f'

def try_decrypt_with_a(a):
    raw = long_to_bytes(a)
    if len(raw) < 16:
        return None
    key = raw[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    pt = cipher.decrypt(ciphertext)
    try:
        return unpad(pt, AES.block_size)
    except ValueError:
        return None

print("[*] Brute-forcing a = k*(p-1) …")
for k in range(1, 10000):
    a = k * (p - 1)
    pt = try_decrypt_with_a(a)
    if pt is not None:
        print(f"[+] Success with k = {k}")
        print(f"[+] a = {a}")
        print(f"[+] AES key (hex): {long_to_bytes(a)[:16].hex()}")
        print(f"[+] Plaintext (raw): {pt!r}")
        try:
            print(f"[+] Flag (utf-8): {pt.decode()}")
        except UnicodeDecodeError:
            print("[!] Could not decode as UTF-8. Try manual inspection.")
        break
else:
    print("[-] Didn't find a valid k up to 10000. Increase bound if needed.")
   ```

![image](https://hackmd.io/_uploads/rkxYCoIHWx.png)

> Flag: CTF{1t_4lw4ys_c0m3s_b4ck_t0_1_21bcd6}

###  Lỗ hổng chính
- Việc chọn `a` sao cho $g^a \equiv 1 \pmod{p}$ khiến bài toán **mất tính một chiều** của bài toán discrete log.
- Không cần dùng các thuật toán Discrete Log mạnh như:
    - `Baby-Step Giant-Step`
    - `Pollard’s Rho`
- Thay vào đó, chỉ cần brute-force với $a = k \times (p - 1)$!

## Anakensec

### Tổng quan về Thuật toán




Đây là một thuật toán mã hóa khối tùy chỉnh. Thuật toán này mã hóa một thông điệp văn bản bằng cách:

- **Chuẩn bị**: Chuyển chữ cái thành số, đệm thêm ký tự `'x'` cho đủ độ dài, rồi chia thành các khối 12 ký tự.
- **Biến đổi khối thành ma trận**: Mỗi khối 12 ký tự được chuyển thành một ma trận 6x6 chứa các "trit" (giá trị 0, 1, hoặc 2).
- **Xáo trộn ma trận**: Ma trận trit này được xáo trộn nhiều lần dựa trên các ký tự của khóa bí mật. Mỗi ký tự khóa chọn một phép hoán vị và một phép cộng đặc biệt.
- **Trích xuất khối mã hóa**: Từ ma trận đã xáo trộn, ta đọc ra 12 ký tự mã hóa mới.
- **Hoán vị cuối cùng**: Tất cả các khối 12 ký tự mã hóa được ghép lại, sau đó trải qua một phép hoán vị cột cuối cùng dựa trên khóa.

Giải mã là thực hiện chính xác các bước ngược lại.



### Các bước MÃ HÓA

#### 1. Mở đầu (Chuẩn bị thông điệp)

##### Ánh xạ ký tự → số
- Chuyển mỗi chữ cái thường (`a-z`) thành một số từ 1 đến 26.
- Công thức: `$số = \text{ord}(\text{chữ cái}) - 96$`.
- *Ví dụ: `'a' → 1`, `'b' → 2`, ..., `'z' → 26`*.

##### Đệm (Padding)
- Thêm các ký tự `'x'` vào cuối thông điệp gốc cho đến khi tổng độ dài của nó chia hết cho 12.

##### Chia khối (Blocking)
- Chia thông điệp đã đệm thành các khối, mỗi khối có đúng 12 ký tự.

#### 2. Xây dựng ma trận "trit" 6x6 từ mỗi khối 12 ký tự
Mỗi khối 12 ký tự (gọi là $L_0L_1…L_{11}$) sẽ được chuyển thành một ma trận `blockM` kích thước 6x6 chứa các "trit".

##### Chuyển đổi ký tự thành 3 trit
Mỗi ký tự (đã được ánh xạ thành số từ 1-26) được biểu diễn bằng 3 trit (giá trị `0`, `1`, hoặc `2`) trong hệ cơ số 3. Nếu `value` là giá trị số của ký tự:
- $q_0 = \text{value} \ // \ 9$ (phần nguyên khi chia `value` cho 9)
- $q_1 = (\text{value} \ \% \ 9) \ // \ 3$ (phần nguyên khi chia (phần dư của `value` chia 9) cho 3)
- $q_2 = \text{value} \ \% \ 3$ (phần dư khi chia `value` cho 3)

:::info
**Ví dụ:** Ký tự `'m'` có `value=13`.
- $q_0 = 13 \ // \ 9 = 1$
- $q_1 = (13 \ \% \ 9) \ // \ 3 = 4 \ // \ 3 = 1$
- $q_2 = 13 \ \% \ 3 = 1$
Vậy `'m'` $\rightarrow (1, 1, 1)$.
:::

##### Điền vào ma trận `blockM` (6x6)
- **Nửa trên ma trận (Hàng 0, 1, 2):**
    - Lấy 6 ký tự đầu tiên của khối ($L_0$ đến $L_5$).
    - Với mỗi ký tự $L_i$, ba trit $(q_0, q_1, q_2)$ của nó sẽ điền vào **cột** $i$ của ma trận.
    ```
    blockM[0, i] = q₀(Lᵢ)
    blockM[1, i] = q₁(Lᵢ)
    blockM[2, i] = q₂(Lᵢ)
    ```
- **Nửa dưới ma trận (Hàng 3, 4, 5):**
    - Lấy 6 ký tự tiếp theo của khối ($L_6$ đến $L_{11}$).
    - Với mỗi ký tự $L_{6+i}$, ba trit của nó sẽ điền vào **cột** $i$ của nửa dưới ma trận.
    ```
    blockM[3, i] = q₀(L₆₊ᵢ)
    blockM[4, i] = q₁(L₆₊ᵢ)
    blockM[5, i] = q₂(L₆₊ᵢ)
    ```
**Kết quả:** `blockM` là một ma trận 6x6 chứa đầy các trit.

#### 3. "Xáo trộn" ma trận `blockM`
Bước này dùng khóa bí mật (ví dụ: $k_0k_1…k_{m-1}$) để làm rối ma trận `blockM`.

##### Chuẩn bị từ khóa
Với mỗi ký tự $k_j$ trong khóa:
- `keyNum` = $\text{ord}(k_j) - 97$ (cho ra số từ 0-25).
- `permuteIndex` = $(\text{keyNum} \ // \ 5) \ \% \ 5$ (ra số từ 0-4, để chọn 1 trong 5 phép hoán vị A,B,C,D,E).
- `addIndex` = `keyNum` $\% \ 5$ (ra số từ 0-4, để chọn 1 trong 5 quy tắc cộng).

##### Quá trình xáo trộn lặp lại
Lặp qua từng ký tự của khóa, từ trái sang phải. Với mỗi ký tự khóa, thực hiện:

1.  **Hoán vị (Permute):** Áp dụng phép hoán vị `permuteIndex` đã chọn lên toàn bộ 36 ô của `blockM`. Các trit sẽ đổi chỗ cho nhau theo một trong 5 mẫu (A,B,C,D,E).
2.  **Cộng (Add) modulo 3:** Áp dụng quy tắc cộng `addIndex` đã chọn cho các trit trong `blockM`. Tất cả phép cộng đều là **mod 3**.

| `addIndex` | Quy tắc cộng (modulo 3) |
|:---:|:---|
| `0` | Cộng `1` (mod 3) vào mọi ô `blockM[i,j]` nếu `(i + j)` là số chẵn. |
| `1` | Khối 3x3 **dưới-phải** `+=` khối 3x3 **trên-trái**. |
| `2` | Khối 3x3 **trên-trái** `+=` khối 3x3 **dưới-phải**. |
| `3` | Khối 3x3 **dưới-trái** `+=` khối 3x3 **trên-phải**. |
| `4` | Khối 3x3 **trên-phải** `+=` khối 3x3 **dưới-trái**. |

Sau khi xử lý hết các ký tự trong khóa, `blockM` đã bị xáo trộn.

#### 4. Trích xuất 12 ký tự mã hóa từ `blockM`
Từ ma trận `blockM` đã xáo trộn, ta đọc ra 12 ký tự mới theo hàng.

- **Với mỗi hàng `i` (từ 0 đến 5):**
    - **Ký tự thứ nhất từ hàng `i`:**
        - Lấy 3 trit đầu tiên của hàng: `blockM[i,0]`, `blockM[i,1]`, `blockM[i,2]`.
        - Tính giá trị số: `num` = $9 \times \text{blockM}[i,0] + 3 \times \text{blockM}[i,1] + 1 \times \text{blockM}[i,2]$.
        - Nếu `num == 0`, ký tự là `'0'`. Ngược lại, ký tự là `chr(num + 96)`.
    - **Ký tự thứ hai từ hàng `i`:**
        - Lấy 3 trit tiếp theo của hàng: `blockM[i,3]`, `blockM[i,4]`, `blockM[i,5]`.
        - Tính giá trị số tương tự.
        - Chuyển `num` thành ký tự (`'0'` hoặc `a-z`).

**Kết quả:** 6 hàng, mỗi hàng 2 ký tự → tổng cộng 12 ký tự mã hóa cho khối này. Gọi chuỗi này là `resultLetters`.

#### 5. Phép hoán vị cột cuối cùng

1.  **Ghép nối:** Nối tất cả các chuỗi `resultLetters` (12 ký tự/khối) từ tất cả các khối lại thành một chuỗi dài `R`.
2.  **Chuẩn bị khóa cho hoán vị:**
    - `keyNums` = `[ord(k) – 97 for k in key]`.
    - `reducedKeyNums`: Tạo danh sách mới bằng cách loại bỏ các giá trị trùng lặp khỏi `keyNums` (chỉ giữ lại lần xuất hiện đầu tiên).
    - `N` = độ dài của `reducedKeyNums`.
3.  **Hoán vị cột:**
    - Chuẩn bị `N` "hộp" (cột) rỗng.
    - Phân phối các ký tự của chuỗi `R` vào `N` hộp này theo kiểu round-robin (chia lần lượt):
        - `R[0]` vào hộp 0, `R[1]` vào hộp 1, ..., `R[N-1]` vào hộp N-1.
        - `R[N]` vào lại hộp 0, `R[N+1]` vào hộp 1, ...
    - **Xuất kết quả:** Nối nội dung của các hộp lại với nhau. Thứ tự nối các hộp được quyết định bằng cách **sắp xếp các giá trị trong `reducedKeyNums` theo thứ tự tăng dần**.

:::success
Chuỗi cuối cùng thu được chính là **bản mã**.
:::



### Các bước GIẢI MÃ
Giải mã là thực hiện ngược lại toàn bộ quá trình mã hóa.

#### A. Hoán vị cột ngược (Đảo ngược bước 5)
1.  **Tính toán lại từ khóa:** Tính `keyNums` và `reducedKeyNums` (với `N` là độ dài) từ khóa bí mật, y như lúc mã hóa.
2.  **Xác định kích thước các "hộp":**
    - Bản mã có độ dài `L`.
    - Hộp thứ `j` (trong số `N` hộp, `j` từ 0 đến `N-1`) sẽ chứa $\lceil \frac{L - j}{N} \rceil$ ký tự. ($\lceil x \rceil$ là làm tròn `x` lên số nguyên gần nhất).
3.  **Đổ lại vào các hộp:**
    - Đọc các ký tự của bản mã.
    - Đổ đầy các hộp theo thứ tự của `reducedKeyNums` đã được **sắp xếp tăng dần**.
4.  **Tái tạo chuỗi `R`:**
    - Đọc lại các ký tự từ các hộp theo kiểu round-robin (hộp 0, hộp 1, ..., hộp N-1, rồi lặp lại) để lấy lại chuỗi `R` ban đầu.

#### B. Tái tạo `blockM` từ các khối 12 ký tự (Đảo ngược bước 4)
1.  **Chia chuỗi `R`** đã khôi phục thành các khối 12 ký tự ($C_0…C_{11}$).
2.  **Với mỗi khối:**
    - Tạo ma trận `M` (6x6) rỗng.
    - **Nửa cột trái của `M` (cột 0,1,2):**
        - Với `i` từ 0 đến 5 (tương ứng ký tự $C_i$): Chuyển $C_i$ thành 3 trit và điền vào `M[i,0]`, `M[i,1]`, `M[i,2]`.
    - **Nửa cột phải của `M` (cột 3,4,5):**
        - Với `i` từ 6 đến 11 (tương ứng ký tự $C_i$): Chuyển $C_i$ thành 3 trit và điền vào `M[i-6, 3]`, `M[i-6, 4]`, `M[i-6, 5]`.

#### C. Đảo ngược quá trình xáo trộn (Đảo ngược bước 3)
- Lặp qua từng ký tự của khóa, nhưng theo **thứ tự ngược lại** (từ cuối về đầu).
- **Với mỗi ký tự khóa:**
    1.  Tính `permuteIndex` và `addIndex` như lúc mã hóa.
    2.  **Áp dụng `inverse_add(M, addIndex)`:** Thực hiện phép **trừ (mod 3)** tương ứng để đảo ngược phép cộng.
    3.  **Áp dụng `inverse_permute(M, permuteIndex)`:** Áp dụng phép hoán vị ngược của phép hoán vị đã dùng lúc mã hóa.

#### D. Đọc lại 12 chữ cái ban đầu từ `blockM` (Đảo ngược bước 2)
Sau khi `blockM` (hay `M`) đã được "un-scrambled":
- **6 ký tự đầu tiên ($L_0…L_5$):**
    - Với mỗi cột `i` (0-5): Lấy 3 trit từ nửa trên của cột (`M[0,i]`, `M[1,i]`, `M[2,i]`), chuyển thành giá trị số, rồi thành chữ cái $L_i$.
- **6 ký tự tiếp theo ($L_6…L_{11}$):**
    - Với mỗi cột `i` (0-5): Lấy 3 trit từ nửa dưới của cột (`M[3,i]`, `M[4,i]`, `M[5,i]`), chuyển thành giá trị số, rồi thành chữ cái $L_{6+i}$.
Kết quả là 12 chữ cái của khối bản rõ ban đầu.

#### E. Hoàn tất (Đảo ngược bước 1)
1.  Ghép tất cả các khối 12 chữ cái đã giải mã lại.
2.  Loại bỏ các ký tự đệm `'x'` ở cuối để thu được **thông điệp gốc**.


### Script Solve:
```python
import numpy as np

# --- copy in the same five 6×6 permutation arrays A–E from encrypt.py ---
A = np.array([[1,  7, 13, 19, 25, 31],
              [2,  8, 14, 20, 26, 32],
              [3,  9, 15, 21, 27, 33],
              [4, 10, 16, 22, 28, 34],
              [5, 11, 17, 23, 29, 35],
              [6, 12, 18, 24, 30, 36]])
B = np.array([[36, 30, 24, 18, 12,  6],
              [35, 29, 23, 17, 11,  5],
              [34, 28, 22, 16, 10,  4],
              [33, 27, 21, 15,  9,  3],
              [32, 26, 20, 14,  8,  2],
              [31, 25, 19, 13,  7,  1]])
C = np.array([[31, 25, 19, 13,  7,  1],
              [32, 26, 20, 14,  8,  2],
              [33, 27, 21, 15,  9,  3],
              [34, 28, 22, 16, 10,  4],
              [35, 29, 23, 17, 11,  5],
              [36, 30, 24, 18, 12,  6]])
D = np.array([[ 7,  1,  9,  3, 11,  5],
              [ 8,  2, 10,  4, 12,  6],
              [19, 13, 21, 15, 23, 17],
              [20, 14, 22, 16, 24, 18],
              [31, 25, 33, 27, 35, 29],
              [32, 26, 34, 28, 36, 30]])
E = np.array([[ 2,  3,  9,  5,  6, 12],
              [ 1, 11, 15,  4, 29, 18],
              [ 7, 13, 14, 10, 16, 17],
              [20, 21, 27, 23, 24, 30],
              [19,  8, 33, 22, 26, 36],
              [25, 31, 32, 28, 34, 35]])
permutes = [A, B, C, D, E]

def inverse_permute(mat, count):
    P = permutes[count]
    inv = np.zeros_like(mat)
    for i in range(6):
        for j in range(6):
            idx = int(P[i,j] - 1)
            r,c = divmod(idx,6)
            inv[r,c] = mat[i,j]
    return inv

def inverse_add(mat, count):
    M = mat.copy()
    if count == 0:
        for i in range(6):
            for j in range(6):
                if (i+j)%2 == 0:
                    M[i,j] = (M[i,j] - 1) % 3

    elif count == 1:
        M[3:,3:] = (M[3:,3:] - M[:3,:3]) % 3

    elif count == 2:
        M[:3,:3] = (M[:3,:3] - M[3:,3:]) % 3

    elif count == 3:
        M[3:,:3] = (M[3:,:3] - M[:3,3:]) % 3

    else:  # count == 4
        M[:3,3:] = (M[:3,3:] - M[3:,:3]) % 3

    return M

def undo_columnar(ctext, key):
    keyNums = [ord(c)-97 for c in key]
    # unique in order
    reduced = []
    for x in keyNums:
        if x not in reduced:
            reduced.append(x)
    n = len(reduced)
    L = len(ctext)
    # compute each column's length
    col_lens = [(L - j + n - 1)//n for j in range(n)]
    # reading order = indices of columns in ascending reduced[]
    order = sorted(range(n), key=lambda i: reduced[i])
    # slice out each box in the order it was emitted
    boxes = [None]*n
    idx = 0
    for col in order:
        ln = col_lens[col]
        boxes[col] = list(ctext[idx:idx+ln])
        idx += ln

    # put them back into the flat result by i % n
    flat = []
    for i in range(L):
        c = i % n
        flat.append( boxes[c].pop(0) )
    return ''.join(flat)

def decrypt(ctext, key):
    flat = undo_columnar(ctext, key)
    # break into 12‐char blocks
    blocks = [flat[12*i:12*(i+1)] for i in range(len(flat)//12)]
    keyNums = [ord(c)-97 for c in key]
    plain = []


    for blk in blocks:
        # rebuild M from the 12 cipher‐letters
        M = np.zeros((6,6), dtype=int)
        # first 6 letters => row i, columns 0–2
        for i,ch in enumerate(blk[:6]):
            v = 0 if ch=='0' else (ord(ch)-96)
            M[i,0] = v//9
            M[i,1] = (v%9)//3
            M[i,2] = v%3
        # next 6 => row i, columns 3–5
        for i,ch in enumerate(blk[6:]):
            v = 0 if ch=='0' else (ord(ch)-96)
            M[i,3] = v//9
            M[i,4] = (v%9)//3
            M[i,5] = v%3

        # undo all (permute→add) in reverse
        for kn in reversed(keyNums):
            a = kn % 5
            p = (kn//5) % 5
            M = inverse_add(M, a)
            M = inverse_permute(M, p)

        # *** HERE IS THE FIX ***
        # original blockM was built with plaintext letters
        # in columns, not rows:
        #   letter 0–5 came from col i of rows 0–2
        #   letter 6–11 came from col i of rows 3–5
        for i in range(6):
            num = 9*M[0,i] + 3*M[1,i] + M[2,i]
            plain.append('?' if num==0 else chr(num+96))
        for i in range(6):
            num = 9*M[3,i] + 3*M[4,i] + M[5,i]
            plain.append('?' if num==0 else chr(num+96))
    return ''.join(plain).rstrip('x')
if __name__ == '__main__':
    key        = 'orygwktcjpb'
    ciphertext = 'cnpiaytjyzggnnnktjzcvuzjexxkvnrlfzectovhfswyphjt'
    pt = decrypt(ciphertext, key)
    print("Decrypted plaintext:", pt)
    print("Flag: CTF{" + pt + "}")

```
![image](https://hackmd.io/_uploads/BkMpAiIrWl.png)

> Flag: CTF{revisreallythestartingpointformostcategoriesiydk}

## Hidden Password

### I: PHÂN TÍCH BINARY

#### 1.1 Sử dụng Ghidra để decompile
- Mở file nhị phân trong Ghidra.
- Decompile để xem pseudocode của các hàm.
![Ảnh chụp màn hình 2025-06-27 024240](https://hackmd.io/_uploads/BkN2Qx3Vxx.png)

#### 1.2 Hiểu luồng chương trình
- Hàm `main()` gọi `verify_password()`, sau đó gọi `decrypt_flag()`.  
- Luồng logic:
  1. Nhập password từ người dùng.  
  2. `verify_password()`: XOR từng byte của password với `0x42` và so sánh với hai hằng:
     - `local_38 = 0x673a257671212f28;`
     - `local_30 = 0x3131122d140d2d2d;`
  3. Nếu so sánh đúng → gọi `decrypt_flag()` để giải mã flag (XOR với key).



### II: REVERSE PASSWORD

#### 2.1 Phân tích hàm `verify_password()`
![1](https://hackmd.io/_uploads/r1hAmlhVxg.png)

- Password nhập vào sau khi XOR với `0x42` phải khớp với:
  ```python
  local_38 = 0x673a257671212f28
  local_30 = 0x3131122d140d2d2d
- Tách thành mảng byte target:
    ```python
    target = [
        0x28, 0x2f, 0x21, 0x71,
        0x76, 0x25, 0x3a, 0x67,
        0x2d, 0x2d, 0x0d, 0x14,
        0x2d, 0x12, 0x31, 0x31
    ]
#### 2.2 Tạo script reverse XOR
```python
target = [
    0x28, 0x2f, 0x21, 0x71,
    0x76, 0x25, 0x3a, 0x67,
    0x2d, 0x2d, 0x0d, 0x14,
    0x2d, 0x12, 0x31, 0x31
]

password = ""
for byte_val in target:
    password += chr(byte_val ^ 0x42)

print(f"Password: {password}")
```


Thực ra tới đây sau khi tìm được Password là ra flag rồi
![Ảnh chụp màn hình 2025-06-27 174234](https://hackmd.io/_uploads/BkWnSlnNlg.png)
> CTF{9xnH2VcnsjM0rLjMI8FJ}

#### 2.3 Phân tích hàm decrypt_flag
![Ảnh chụp màn hình 2025-06-27 174033](https://hackmd.io/_uploads/rJ38Be3Nxl.png)

- Biến:
```python
uint local_c;
```

> Biến đếm (local_c) dùng để lặp qua từng byte trong chuỗi encrypted_flag.

-  Dòng:
```python
printf("Decrypted flag: ");
```

> In ra dòng báo hiệu bắt đầu hiển thị flag đã được giải mã.

- Vòng lặp:
`for (local_c = 0; (int)local_c < 0x1f; local_c = local_c + 1)`
> 
> Lặp từ local_c = 0 đến local_c = 30 (0x1f = 31) → tổng cộng 31 byte.

Đây có thể là độ dài của flag sau khi được giải mã.

- Dòng chính để giải mã:
```python
putchar((uint)(*(byte *)((long)&key + (ulong)(local_c & 3)) ^ encrypted_flag[(int)local_c]));
```

> + encrypted_flag[(int)local_c]: là một byte của flag bị mã hóa.
> + local_c & 3: lấy 2 bit cuối của chỉ số (giá trị từ 0 đến 3), tương đương lặp lại mỗi 4 ký tự.
> + &key + (local_c & 3): trỏ tới byte thứ 0–3 trong khóa key.
> + *(byte *)...: đọc 1 byte trong key tại vị trí vừa nói.
> + Cuối cùng: XOR giữa byte từ key và byte mã hóa → giải mã ra ký tự gốc.
> + putchar(...): in ra ký tự giải mã.


## Obscuratron


### I: Phân tích chức năng hàm `FUN_00101179`
![Ảnh chụp màn hình 2025-06-29 213746](https://hackmd.io/_uploads/r1rAJC0Nxg.png)

Chức năng chính của hàm `FUN_00101179` là thực hiện một thuật toán mã hóa đơn giản dựa trên chuỗi (stream cipher).

1.  **Khởi tạo**: In ra các câu chào mừng và hướng dẫn người dùng.
2.  **Xử lý byte đầu tiên**:
    -   Đọc 1 byte từ `stdin`: `local_c = fgetc(stdin);`
    -   XOR byte đó với `0xAB`: `local_c = local_c ^ 0xab;`
    -   In ra byte đã được mã hóa: `putchar(local_c);`
3.  **Vòng lặp xử lý các byte tiếp theo**:
    -   Đọc byte kế tiếp: `local_10 = fgetc(stdin);`
    -   XOR byte vừa đọc với byte đã mã hóa ngay trước đó: `local_c = local_10 ^ local_c;`
    -   In ra kết quả `local_c`.
    -   Vòng lặp tiếp tục cho đến khi gặp ký tự kết thúc file (EOF), tức là `local_10 == -1`.

### II. Phân tích thuật toán mã hoá

Bản chất của thuật toán mã hóa được sử dụng là một dạng **stream cipher** đơn giản, tương tự như cơ chế XOR trong chế độ CBC (Cipher Block Chaining).

:::info
**Quy trình mã hóa:**
-   **Byte đầu tiên ($B_0$)**: $C_0 = B_0 \oplus 0xAB$
-   **Byte thứ `i` ($B_i$) trở đi**: $C_i = B_i \oplus C_{i-1}$

Trong đó:
-   `B` là byte gốc (plaintext).
-   `C` là byte đã mã hóa (ciphertext).
-   $C_{i-1}$ là byte đã được mã hóa ở bước ngay trước đó.
:::

### III. Giải mã `memo.pdf.enc`

Để giải mã file, chúng ta cần thực hiện quy trình ngược lại.

1.  Đọc byte đã mã hóa đầu tiên ($enc_0$).
2.  Giải mã byte đầu tiên: $dec_0 = enc_0 \oplus 0xAB$.
3.  Với mỗi byte đã mã hóa tiếp theo ($enc_i$):
Thực hiện giải mã: $dec_i = enc_i \oplus enc_{i-1}$.

![Ảnh chụp màn hình 2025-06-29 214007](https://hackmd.io/_uploads/SyfclR0Egl.png)

### IV. Thực thi giải mã

Chạy code và giải mã lại file PDF:
solve.py:

```python 
def decrypt(filename_enc, filename_out):
    with open(filename_enc, 'rb') as f:
        data = f.read()

    decrypted = bytearray()
    
    if len(data) == 0:
        print("File is empty!")
        return
    
    # First byte
    decrypted.append(data[0] ^ 0xAB)
    
    # From second byte
    for i in range(1, len(data)):
        decrypted.append(data[i] ^ data[i-1])

    with open(filename_out, 'wb') as f:
        f.write(decrypted)

    print(f"Decryption complete! Output: {filename_out}")

decrypt('memo.pdf.enc', 'memo_decrypted.pdf')
```

>  solve.py memo.pdf.enc > memo.pdf

*File thực thi giải mã, file memo.pdf.enc phải được đặt chung trong một thư mục.*

## rev0x1337
Mở file trong IDA và chuyển đến hàm `main`. Ta thấy chuỗi `The encrypted flag is:` và biến `unk_40082B` chứa flag đã được mã hóa.

![image](https://hackmd.io/_uploads/HyFiuoUBbl.png)

Trích xuất encrypted flag

Vào biến `unk_40082B` và copy giá trị của nó. Đây chính là flag đã được mã hóa:
```python
encry_flag = [
    0x6d, 0x78, 0x61, 0x6c, 0xdd, 0x7e, 0x65, 0x7e,
    0x47, 0x6a, 0x4f, 0xcc, 0xf7, 0xca, 0x73, 0x68,
    0x55, 0x42, 0x53, 0xdc, 0xd7, 0xd4, 0x6b, 0xec,
    0xdb, 0xd2, 0xe1, 0x1c, 0x6d, 0xde, 0xd1, 0xc2
]
```

Phân tích thuật toán mã hóa

Tiếp theo, vào hàm `sub_400620` để xem pseudocode và hiểu rõ thuật toán. Ta nhận thấy thuật toán thực hiện:

1. **XOR** encrypted flag với `xor_key`
2. **Dịch phải (shift right)** kết quả với `1`

Trong đó, `xor_key` được tính từ công thức: `(i % 0xFF) | 0xA0`

![image](https://hackmd.io/_uploads/SklkKi8Hbe.png)
```python
xor_key = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf
]
```


Sử dụng [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Hex('0x%20with%20comma')XOR(%7B'option':'Hex','string':'0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,0xb0,0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,0xb8,0xb9,0xba,0xbb,0xbc,0xbd,0xbe,0xbf'%7D,'Standard',false)OR(%7B'option':'Hex','string':'1'%7D)Bit_shift_right(1,'Logical%20shift')&input=MHg2ZCwweDc4LDB4NjEsMHg2YywweGRkLDB4N2UsMHg2NSwweDdlLDB4NDcsMHg2YSwweDRmLDB4Y2MsMHhmNywweGNhLDB4NzMsMHg2OCwweDU1LDB4NDIsMHg1MywweGRjLDB4ZDcsMHhkNCwweDZiLDB4ZWMsMHhkYiwweGQyLDB4ZTEsMHgxYywweDZkLDB4ZGUsMHhkMSwweGMy) để thực hiện các thao tác giải mã theo thứ tự:

1. From Hex
2. XOR với key
3. OR với 0x1
4. Bit shift right 1

![image](https://hackmd.io/_uploads/HJDgYi8rWl.png)


```
Flag: malwar3-3ncryp710n-15-Sh17
```
