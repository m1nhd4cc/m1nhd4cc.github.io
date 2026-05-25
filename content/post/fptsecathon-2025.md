---
title: "FPTU Secathon 2025"
description: "Writeup for Crypto Challenge"
summary: "Writeup for Crypto Challenge"
categories: ["Writeup"]
tags: ["Crypto", "Vietnamese"]
#externalUrl: ""
date: 2025-07-27
draft: false
authors:
  - ducnocrypt
cover: "/images/post_covers/fptsecathon-2025.jpg"
---

# CryptoGraphy


![My_Solve](/images/fptsecathon2025/1.png)

Tuần vừa rồi mình có tham gia giải FPTU Secathon 2025 và cũng may mắn clear gần full mảng mà mình enjoy trong CTF là Cryptography (còn bài cuối mình khong solve được)....

*just 300 points btw i don't say it's crypto* 😃 

## ECB Shuffle
```
You're given an encrypted file. It was encrypted using a block cipher, and you suspect the developer made a mistake.

Your mission: Recover the original message and extract the flag.

File: output.enc
Flag format: No format hint – look for something suspicious in the plaintext!
```

Nhiệm vụ của thử thách này là tìm ra flag được giấu trong file [output.enc](https://drive.google.com/file/d/1yWxrvOfbqqT4r-bFHfNC1vxvJmewVOk0/view?usp=sharing). File này đã được mã hóa bằng thuật toán **AES-128-ECB**.

Ban đầu mình nghĩ bài này sử dụng thuật toán AES để giải mã file `enc` ra 1 file ảnh. Nhưng sau 1 hồi mày mò.. vì bí ý tưởng nên mình quyết định unlock hint của đề bài:
- **Key**: `This_is_a_keyxxx`, trong đó `xxx` là một số có 3 chữ số, chạy từ `000` đến `999`.

Vậy thì mục tiêu của chúng ta là:
>  Tìm ra key chính xác.
 Giải mã ciphertext để thu hồi flag.


### Thông tin thu được

Dựa trên các file và thông tin được cung cấp, ta có:
- **Chế độ mã hóa**: `AES-128-ECB`.
- **Không gian Key**: `This_is_a_key000` đến `This_is_a_key999`
- **Ciphertext**: Nội dung của file `output.enc`.
- **Định dạng Flag**: `FUSec2025{…}`.


###  Phân tích kỹ thuật

#### 1. Điểm yếu của AES-ECB
Chế độ **Electronic Codebook (ECB)** là chế độ hoạt động đơn giản nhất của AES. Điểm yếu nghiêm trọng của nó là:
> Các khối plaintext giống hệt nhau, khi được mã hóa bằng cùng một key, sẽ luôn tạo ra các khối ciphertext giống hệt nhau.

Điều này không che giấu được các mẫu dữ liệu, khiến nó dễ bị tấn công nếu plaintext có cấu trúc lặp lại. Mặc dù trong bài này chúng ta không tấn công vào điểm yếu đó, nhưng đây là một kiến thức bảo mật quan trọng cần ghi nhớ.
[Mình tham khảo ở đây](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_(ECB))


#### 2. Không gian Key (Key Space)
Key có cấu trúc `This_is_a_keyxxx`. Điều này làm cho việc **brute-force** đơn giản hơn khi giới hạn không gian tìm kiếm chỉ còn 1000 khả năng

#### 3. Padding
Ciphertext có thể được đệm (padded) theo chuẩn **PKCS#7** để đảm bảo khối cuối cùng đủ 16 bytes. Khi giải mã, chúng ta cần xử lý padding này để khôi phục lại plaintext gốc.


### Exploit

#### 1. Brute-force Key:

Viết một script lặp qua tất cả 1000 key, từ `This_is_a_key000` đến `This_is_a_key999`.
Với mỗi key, sử dụng thư viện mã hóa để giải mã file `output.enc` bằng [AES-128-ECB](https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-aes)

#### 2. Kiểm tra Plaintext:

Sau mỗi lần giải mã, kiểm tra xem plaintext kết quả có chứa chuỗi định dạng flag (`b"FUSec2025{"`) hay không.

#### 3. Result:
Khi tìm thấy plaintext hợp lệ, script sẽ dừng lại và in ra key đã tìm thấy cùng với flag đầy đủ.
![Ảnh chụp màn hình 2025-07-28 060115](/images/fptsecathon2025/2.png)


Solution của mình:

```python
from Crypto.Cipher import AES
import os

ciphertext_file = "output.enc"
with open(ciphertext_file, "rb") as f:
    ciphertext = f.read()
# Function to decrypt
def decrypt_aes_ecb(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)
# Brute-force keys
for i in range(1000):
    key = f"This_is_a_key{str(i).zfill(3)}".encode()
    try:
        # Decrypt the ciphertext
        plaintext = decrypt_aes_ecb(ciphertext, key)
        # Check for flag format ("FUSec2025{...}")
        if b"FUSec2025{" in plaintext:
            print(f"Key found: {key.decode()}")
            print(f"Plaintext: {plaintext.decode(errors='ignore')}")
            break
    except Exception as e:
        pass
```
> Flag: FUSec2025{C0nGr4t**ECB$$WinN3r&&}



## CTR Reuse Oracle

```
Goal
----
Recover the flag from `ciphertext.bin`.

Scenario
--------
A developer mistakenly **reuses the same nonce** for AES‑CTR encryption.
You have two powers:
1. A ciphertext (`ciphertext.bin`) that contains a secret message with the flag.
2. An **encryption oracle** (`oracle.py`) that will encrypt *any plaintext you supply* using **the same key and the SAME nonce**.

Because AES‑CTR is a stream cipher (keystream XOR), reusing the nonce leaks the keystream.
By querying the oracle with chosen plaintexts, you can reconstruct the keystream and decrypt `ciphertext.bin`.

Flag format: FUSec2025{...} (already inside the message).

Files
-----
* `ciphertext.bin` – secret ciphertext
* `oracle.py`      – Flask server providing `/encrypt` endpoint
* `README.txt`     – this guide

Quick Start
-----------
```bash
pip install flask pycryptodome requests

# Terminal 1 – start oracle
python oracle.py

# Terminal 2 – example usage
python - <<'PY'
import requests, sys, os
ct = bytes.fromhex(open("ciphertext.bin","rb").read().hex())
# Step 1: ask oracle to encrypt zeros of same length → gives keystream
zeros = b'\x00'*len(ct)
ks_hex = requests.post("http://127.0.0.1:5000/encrypt", json={"data": zeros.decode('latin1')}).json()['ciphertext']
keystream = bytes.fromhex(ks_hex)
pt = bytes(a ^ b for a,b in zip(ct, keystream))
print("Decrypted:", pt.decode())

That script prints the original message along with the flag.
Good luck!
```



### Mục tiêu

Nhiệm vụ của thử thách là khôi phục lại flag từ file [ciphertext.bin](https://drive.google.com/file/d/1vGx5IyYwn-oK1uLWO9JmOX06JTn_SayA/view?usp=sharing). Chúng ta được cung cấp một **encryption oracle**, và mấu chốt của bài toán nằm ở việc nhà phát triển đã **sử dụng lại cùng một nonce** cho tất cả các hoạt động mã hóa AES-CTR.

### Thông tin thu được

- **`ciphertext.bin`**: File chứa ciphertext của một tin nhắn bí mật, bên trong có flag.
- **`oracle.py`**: Một server Flask đóng vai trò là oracle, cung cấp endpoint `/encrypt`. Oracle này sẽ mã hóa bất kỳ dữ liệu nào chúng ta gửi lên bằng **cùng một KEY và NONCE** đã dùng để tạo ra `ciphertext.bin`.
- **`README.txt`**: Hướng dẫn và mô tả về thử thách.
- **Lỗ hổng**: Tái sử dụng Nonce trong chế độ mã hóa luồng AES-CTR.
- **Định dạng Flag**: `FUSec2025{...}`.

###  Phân tích lỗ hổng: CTR Nonce Reuse

Chế độ **Counter (CTR)** biến một mật mã khối (như AES) thành một mật mã luồng (stream cipher). Quá trình mã hóa và giải mã đều thực hiện bằng cách XOR dữ liệu với một **keystream** (dòng khóa).

- **Mã hóa**: $Ciphertext = Plaintext \oplus Keystream$
- **Giải mã**: $Plaintext = Ciphertext \oplus Keystream$

Keystream được tạo ra bằng cách mã hóa một chuỗi các giá trị counter tuần tự, bắt đầu bằng một giá trị khởi tạo gọi là **Nonce**.

$$Keystream = AES_{Encrypt}(Key, Nonce) \ || \ AES_{Encrypt}(Key, Nonce+1) \ || \ ...$$

Điểm yếu chí mạng xảy ra khi **cùng một cặp (Key, Nonce) được sử dụng lại** để mã hóa hai bản tin khác nhau.

Giả sử ta có:
- $C_1 = P_1 \oplus Keystream$
- $C_2 = P_2 \oplus Keystream$

Nếu chúng ta có $C_1$ và có khả năng tạo ra $C_2$ bằng cách chọn $P_2$ (thông qua oracle), chúng ta có thể phá vỡ hệ thống.

Cụ thể, nếu chúng ta XOR hai ciphertext với nhau:
$C_1 \oplus C_2 = (P_1 \oplus Keystream) \oplus (P_2 \oplus Keystream) = P_1 \oplus P_2$

Bằng cách chọn một $P_2$ đã biết, ta có thể khôi phục $P_1$.

Trong bài này, chúng ta sẽ sử dụng một kỹ thuật đơn giản hơn: **khôi phục trực tiếp keystream**.
Nếu chúng ta yêu cầu oracle mã hóa một bản tin $P_{zeros}$ chứa toàn byte `0` (`\x00`), ta sẽ có:

$C_{zeros} = P_{zeros} \oplus Keystream = 0 \oplus Keystream = Keystream$

Như vậy, ciphertext mà oracle trả về chính là **keystream** mà chúng ta cần. Sau khi có được keystream, ta chỉ cần XOR nó với `ciphertext.bin` để lấy lại plaintext gốc.

$Plaintext_{original} = Ciphertext_{original} \oplus Keystream$

### Quy trình giải quyết

-  **Đọc `ciphertext.bin`**: Lấy nội dung ciphertext mục tiêu và xác định độ dài của nó.
-  **Tạo Plaintext giả**: Tạo một chuỗi byte `0` có cùng độ dài với ciphertext.
-  **Truy vấn Oracle**: Gửi chuỗi byte `0` này đến endpoint `/encrypt` của oracle.
-  **Nhận Keystream**: Ciphertext nhận về từ oracle chính là keystream đã được sử dụng để mã hóa flag.
-  **Giải mã**: XOR ciphertext từ `ciphertext.bin` với keystream vừa nhận được để khôi phục plaintext và flag.

### Solution

Trước hết ta chạy cần file [oracle.py](https://drive.google.com/file/d/1IuyKZVDoDK-MgruZ0Xhslo55K9K3irGe/view?usp=sharing) để chạy oracle:
![Ảnh chụp màn hình 2025-07-29 220210](/images/fptsecathon2025/3.png)

Sau đó chạy script exploit:


```python
import requests
import os
try:
    with open("ciphertext.bin", "rb") as f:
        ct_bytes = f.read()
except FileNotFoundError:
    print("[!] Lỗi: Không tìm thấy file 'ciphertext.bin'.")
    exit()
print(f"[*] Ciphertext (hex): {ct_bytes.hex()}")
print(f"[*] Chiều dài Ciphertext: {len(ct_bytes)} bytes")

zeros_plaintext = b'\x00' * len(ct_bytes)
print(f"[*] Đã tạo plaintext gồm {len(zeros_plaintext)} byte 0.")
print("[*] Đang gửi plaintext đến oracle...")
try:
    response = requests.post(
        "[http://127.0.0.1:5000/encrypt](http://127.0.0.1:5000/encrypt)",
        json={"data": zeros_plaintext.decode('latin1')}
    )
    response.raise_for_status() # Báo lỗi nếu request không thành công (vd: 404, 500)
    keystream_hex = response.json()['ciphertext']
    keystream = bytes.fromhex(keystream_hex)
    print(f"[+] Đã nhận Keystream (hex): {keystream.hex()}")
    # XOR từng byte của ciphertext với keystream tương ứng
    plaintext_bytes = bytes(c ^ k for c, k in zip(ct_bytes, keystream))
    print("\n[+] SUCCESS! Plaintext đã được khôi phục:")
    print("-------------------------------------------")
    print(plaintext_bytes.decode('utf-8', errors='ignore'))
    print("-------------------------------------------")

except requests.exceptions.ConnectionError:
    print("\n[!] Lỗi: Không thể kết nối đến oracle. Bạn đã chạy 'python oracle.py' chưa?")
except Exception as e:
    print(f"\n[!] Đã có lỗi xảy ra: {e}")
```
Kết quả:
![Ảnh chụp màn hình 2025-07-29 220436](/images/fptsecathon2025/4.png)

> Flag: FUSec2025{StreamXorMagic!}



## Crypto Onion: Peeling Challenge

### Đề bài

```python
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import base64
import json
import os

def generate_rsa_keypair():
    key_size = 2048
    key = RSA.generate(key_size)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

def aes_encrypt(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext

def rsa_encrypt(data, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher_rsa.encrypt(data)
    return encrypted_data

def hybrid_encrypt(flag, public_key):
    plaintext = flag.encode()
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    ciphertext_aes = aes_encrypt(plaintext, aes_key, iv)
    encrypted_aes_key = rsa_encrypt(aes_key, public_key)
    return ciphertext_aes, encrypted_aes_key, iv

if __name__ == "__main__":
    flag = "FUSec2025{Hay_thu_phan_tich_doan_chuong_trinh_nay_xem}"

    private_key, public_key = generate_rsa_keypair()

    with open("private_key.pem", "wb") as f:
        f.write(private_key.export_key())
    with open("public_key.pem", "wb") as f:
        f.write(public_key.export_key())

    ciphertext_aes, encrypted_aes_key, iv = hybrid_encrypt(flag, public_key)

    data = {
        "ciphertext_aes": base64.b64encode(ciphertext_aes).decode(),
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
        "iv": base64.b64encode(iv).decode()
    }

    with open("encrypted_data.json", "w") as f:
        json.dump(data, f, indent=4)

    print("Encryption completed. Data saved to encrypted_data.json")
    print("Private and public keys saved to private_key.pem and public_key.pem")
```
Cùng với đó là đề cho thêm 3 file:
- [encrypted_data.json](https://drive.google.com/file/d/1ANgFePDtFvJwr4-O91YMMslIqPh8DDpz/view?usp=sharing): Chứa ciphertext đã được mã hóa bằng AES-CBC, key AES lại được mã hóa bằng RSA.
- [public_key.pem](https://drive.google.com/file/d/1PbupGmoG7I7-lNhnUggArbCJ4zx9tjFm/view?usp=sharing), [private_key.pem](https://drive.google.com/file/d/1d7VxeZBeTbN6XxkEDu1I2Xqijrvjq3t9/view?usp=sharing): Cặp khóa RSA.


### Phân tích kỹ thuật

Đây là mô hình **hybrid encryption** phổ biến:
- Flag được mã hóa bằng AES-256-CBC với một key ngẫu nhiên.
- Key AES này lại được mã hóa bằng RSA (PKCS1_OAEP).
- IV (vector khởi tạo) cũng được lưu lại.


####  Tạo cặp khóa RSA

```python
key = RSA.generate(2048)
private_key = key
public_key = key.publickey()
```

- Tạo khóa 2048-bit, đảm bảo tính bảo mật tốt.
- Lưu lại khóa riêng và khóa công khai.

#### Mã hóa AES-CBC

```python
aes_key = os.urandom(32)  # AES-256: 32 bytes
iv = os.urandom(16)       # IV cho chế độ CBC
ciphertext_aes = aes_encrypt(plaintext, aes_key, iv)
```

- AES-256 với chế độ CBC.
- Dữ liệu được **pad** chuẩn PKCS#7 (`Crypto.Util.Padding.pad`).

#### Mã hóa key AES bằng RSA-OAEP

```python
encrypted_aes_key = rsa_encrypt(aes_key, public_key)
```

- Sử dụng chuẩn **PKCS1_OAEP**, chống lại nhiều loại tấn công như chosen ciphertext.

#### Lưu dữ liệu mã hóa vào JSON

```python
data = {
    "ciphertext_aes": base64.b64encode(ciphertext_aes).decode(),
    "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
    "iv": base64.b64encode(iv).decode()
}
```

Quy trình giải mã:
1. Dùng private key RSA để giải mã key AES.
2. Dùng key AES và IV để giải mã ciphertext, thu được flag.


---

### Solution

Bài này cũng khá đơn giản, và đây là solution của mình:
```python
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad
import base64
import json

def rsa_decrypt(encrypted_data, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_data)
def aes_decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    return unpad(decrypted_padded, AES.block_size)
# Load private key
with open("private_key.pem", "rb") as f:
    private_key = RSA.import_key(f.read())
# Load encrypted data
with open("encrypted_data.json", "r") as f:
    data = json.load(f)
ciphertext_aes = base64.b64decode(data["ciphertext_aes"])
encrypted_aes_key = base64.b64decode(data["encrypted_aes_key"])
iv = base64.b64decode(data["iv"])
# Decrypt AES key
aes_key = rsa_decrypt(encrypted_aes_key, private_key)
flag = aes_decrypt(ciphertext_aes, aes_key, iv)
print("Flag:", flag.decode())
```
**Kết quả:**

![Ảnh chụp màn hình 2025-07-29 222703](/images/fptsecathon2025/5.png)

> Flag: FUSec2025{Chuc_mung_ban_da_thanh_cong}


### Note:

- Hybrid encryption là kỹ thuật kết hợp giữa mã hóa đối xứng (AES) và bất đối xứng (RSA) để tận dụng ưu điểm của cả hai.
- Nếu private key bị lộ, toàn bộ dữ liệu có thể bị giải mã.
- Luôn bảo vệ private key cẩn thận!


# Góc enjoy
Mặc dù có khá nhiều tranh cãi sau cuộc thi và một vài sự cố trước cuộc thi nữa.. ờm maybe chắc lần đầu open toàn quốc nên hong tránh được sự cố request khổng lồ... thôi thì cứ ch1ll và vét tea break trước..

![Ảnh chụp màn hình 2025-07-29 224217](/images/fptsecathon2025/6.png)

... Và nhiều cái khác nữa, nhưng dù sao thì cũng cảm ơn trường Ép đã tạo sân chơi học thuật cho sinh viên toàn quốc được tham gia và học hỏi.
> P/s: Không phải challenge mà Tea Break là thứ bị clear đầu tiên💀... cơm gà ngol lắm ạ