---
title: "GDUCTF Training "
description: "Writeup for Forensic, MISC Challenge"
summary: "Writeup for Forensic, MISC Challenge"
categories: ["Writeup"]
tags: ["Forensic", "Vietnamese"]
date: 2024-04-10
draft: false
authors:
  - ducnocrypt
cover: "/images/post_covers/wu_gdu_training.jpg"
---


## Phần 1: Phân tích log (evidence_data)

### Q1: Tìm IP Attacker
**Câu hỏi:** Biết hacker đã upload thành công webshell sau đó truy cập vào để điều khiển máy chủ ứng dụng.

Khi tấn công vào hệ thống cần rất nhiều thời gian, ta lọc time-token lớn nhất.
![image](https://hackmd.io/_uploads/SkME5tLH-x.png)

> **IP của attacker:** `216.139.234.95`

### Q2: Thời gian tấn công bằng webshell
Dựa vào IP tìm được ở câu 1, đối chiếu qua thời gian (time).
![image](https://hackmd.io/_uploads/HybB9KLB-e.png)

> **Thời gian tấn công:** `15:19:50`

### Q3: Xác minh mã hash SHA-256 của webshell
Dựa vào câu 1 đối chiếu thì đường dẫn webshell là: `/webs/web/images/image1.php`.
Tuy nhiên, khi vào thư mục `images` lại không tìm thấy tệp `image1.php`. Có nghĩa là attacker đã đổi tên và di chuyển nó đi nơi khác.
![image](https://hackmd.io/_uploads/rkTI5FUHbl.png)

Nhìn xuống dòng tiếp theo sẽ thấy attacker truy cập vào: `/Webs/Web/ListSP/showSanPham.php`
![image](https://hackmd.io/_uploads/BklO9tIHbl.png)

Sau khi truy cập vào đường dẫn thì tìm được webshell:
![image](https://hackmd.io/_uploads/HJnOct8Sbe.png)

Tính toán mã hash SHA-256 của webshell:
![image](https://hackmd.io/_uploads/B1KFqK8SWx.png)

> **SHA-256:**
> ```text
> 6cc20142eb377f11e445657df27b41e5c5bfcbab4ba558ee17495fc15d534765
> ```

### Q4: Xác định tài khoản được tạo thêm
Để xác định được tài khoản được tạo thêm, kiểm tra Windows Powershell của `web-data`.
Để tạo tên đăng nhập sẽ dùng lệnh `New-LocalUser` nên chỉ cần lọc lệnh này ra.
![image](https://hackmd.io/_uploads/r1TcqtLrWl.png)

Sau khi kiểm tra thì biết được thông tin:
![image](https://hackmd.io/_uploads/B12a9Y8S-l.png)

> **Username:** `SOCAdmin`
> **Password:** `qwerty@123#`

### Q5: Xác định mã hash SHA-256 của công cụ leo thang đặc quyền
Để xác định được công cụ leo thang đặc quyền, kiểm tra Windows Powershell của `web-data`.
Để tải 1 công cụ leo thang đặc quyền thì dùng lệnh `wget` nên ta sẽ lọc từ khóa này.
![image](https://hackmd.io/_uploads/BJ3yotISWg.png)

Sau khi kiểm tra thì tìm được:
![image](https://hackmd.io/_uploads/S1KliYIH-l.png)

Xác định `GodPotato-NET35.exe` là công cụ leo thang đặc quyền.
![image](https://hackmd.io/_uploads/S1QWoKLrWe.png)

> **SHA-256:**
> ```text
> 3027a212272957298bf4d32505370fa63fb162d6a6a6ec091af9d7626317a858
> ```

### Q6: Xác định mật khẩu tài khoản dùng để tấn công AD
Như ở câu trên thì attacker đã dùng công cụ leo thang đặc quyền nên thường tài khoản tấn công sẽ là **Administrator**.
![image](https://hackmd.io/_uploads/HkTZsFUr-e.png)

Theo dõi luồng (Follow Stream):
![image](https://hackmd.io/_uploads/SJZGjYLrZe.png)
Tài khoản dùng tấn công đã đăng nhập vào lúc `16:00:49`.

Xuất file `ad-vm1.pcapng` sang `ad-vm1.pcap`.
![image](https://hackmd.io/_uploads/HkszjFUHWx.png)

Dùng **Network Miner** tìm đến khoảng thời gian trên thì sẽ thấy hash password (NTLMv2).
![image](https://hackmd.io/_uploads/HyhQiFLBWl.png)

Dùng Hashcat để crack chuỗi NetNTLMv2 hash. Cấu trúc: `USERNAME::DOMAIN:SERVER_CHALLENGE:NTLMV2_RESPONSE:BLOB`

> **Password:** `mayihelpyou`

### Q7: Policy trên máy người dùng
Kiểm tra trong Windows Powershell của `ad-data`. Vì là policy nên lọc theo `new-gpo`.
![image](https://hackmd.io/_uploads/HyONstISbe.png)

**Cú pháp cơ bản:**
`New-GPO -Name "Tên-GPO" [-Domain "tên-domain"] [-Comment "ghi chú"] [-StarterGPOName "tên-starter-gpo"]`

![image](https://hackmd.io/_uploads/H1yrjKIrZx.png)
![image](https://hackmd.io/_uploads/HkOHsYLBZx.png)

> **Tên Policy:** `OpenThis`

### Q8: Xác định mã hash SHA-256 của Mã độc mã hóa tệp tin
Mở file `pc-user-vm0.pcapng`. Lọc theo giao thức `smb2`.
Chuột phải chọn **Protocol Preferences 🡪 SMB2 (…) 🡪 Use the full…**
![image](https://hackmd.io/_uploads/HJ8UsKUH-g.png)

Sau đó Export file -> Lưu file -> Dùng `sha256sum` để kiểm tra.
![image](https://hackmd.io/_uploads/HJJwsF8H-x.png)
![image](https://hackmd.io/_uploads/By2wiY8BWg.png)
![image](https://hackmd.io/_uploads/rkgdsFIHWe.png)

> **SHA-256:**
> ```text
> be56b79a52bfc2ed32927cb5fd654d7ca2d145838f5f5ce0af5644b945eae99f
> ```



## Phần 2: Đọc ổ đĩa (Horcrux-partition 5)

### Q1. Bản phân phối Linux nào đang được sử dụng?
Kiểm tra tại `partition5/boot`.
![image](https://hackmd.io/_uploads/r1uKoFLH-l.png)

> **Đáp án:** `vmlinuz-4.13.0-kali1-amd64`

### Q2. Hàm băm MD5 của access.log apache là gì?
Đường dẫn: `/var/log/apache/`.
![image](https://hackmd.io/_uploads/BJWqoFUBZe.png)

Vào file chọn *Export file hash list*, mở file đã export.
![image](https://hackmd.io/_uploads/SyLqjF8r-x.png)
![image](https://hackmd.io/_uploads/H1eosFLHZg.png)

> **MD5 Hash:** `d41d8cd98f00b204e9800998ecf8427e`

### Q3. Tên tệp của công cụ kết xuất thông tin xác thực đã tải xuống?
Kiểm tra thư mục Downloads: `/root/Downloads/`.
![image](https://hackmd.io/_uploads/BkqsiFLH-l.png)

> **Tên công cụ:** `mimikatz_trunk.zip`

### Q4. Đường dẫn tuyệt đối của tệp siêu bí mật?
Kiểm tra file `.bash_history` trong `/root/` để xem lịch sử lệnh.
![image](https://hackmd.io/_uploads/BJV2iYIBbx.png)
![image](https://hackmd.io/_uploads/Sk93iYUHZl.png)

> **Đường dẫn:** `/root/Desktop/SuperSecretFile.txt`

### Q5. Chương trình nào được sử dụng với didyouthinkwedmakeiteasy.jpg?
Vẫn tìm trong `.bash_history`.
![image](https://hackmd.io/_uploads/Hkl6oFISZl.png)

> **Chương trình:** `binwalk`

### Q6. Mục tiêu thứ ba trong danh sách kiểm tra mà Karen tạo ra?
Kiểm tra tại `/root/Desktop/`.
![image](https://hackmd.io/_uploads/Hkv6sFLS-l.png)

> **Mục tiêu:** `Profit`

### Q7. Apache đã chạy bao nhiêu lần?
Kiểm tra `/var/log/`.
![image](https://hackmd.io/_uploads/rJRpjKUBWe.png)
Kích thước file `access.log` là 0.

> **Kết luận:** Máy chủ Apache chưa chạy lần nào.

### Q8. Hồ sơ nào chứng minh máy này dùng để tấn công người khác?
Vào `/root/`.
![image](https://hackmd.io/_uploads/HJr0otUr-g.png)

### Q9. Karen đang chế nhạo ai qua kịch bản bash?
Vào `/root/Documents/myfirsthack/`.
![image](https://hackmd.io/_uploads/Hk5RjF8rWe.png)

> **Karen đang chế nhạo:** `Young`

### Q10. Ai là người dùng đã root vào lúc 11:26 nhiều lần?
Vào `partition5/var/log/auth.log`.
![image](https://hackmd.io/_uploads/BJ-y3KUBbg.png)

> **User:** `postgres`

### Q11. Dựa trên lịch sử bash, thư mục làm việc hiện tại là gì?
Vào `/root/`.
![image](https://hackmd.io/_uploads/HyIy3FIHZe.png)

> **Thư mục:** `/root/Documents/myfirsthack/`



## Phần 3: Phân tích đĩa (Horcrux-partition 2)

### Q1. Tên của examiner đã tạo ra E01 là gì?
![image](https://hackmd.io/_uploads/SJlght8HZl.png)
> **Đáp án:** `Minerva`

### Q2. Tên người dùng chính của máy?
![image](https://hackmd.io/_uploads/HkCe2tUHWe.png)
![image](https://hackmd.io/_uploads/H1Q-nKISWx.png)
> **Đáp án:** `Karen`

### Q3. Hàm băm SHA1 của bằng chứng là gì?
![image](https://hackmd.io/_uploads/Bklr2tIrZx.png)
> **SHA1:** `0fa6ab4bd9a707d49ded70e8b9198fe18114b369`

### Q4. Hình ảnh được tạo ra lúc mấy giờ?
Format UTC (24h): `MM/DD/YYYY HH:MM:SS`
![image](https://hackmd.io/_uploads/HyzInKIBbe.png)
> **Đáp án:** `03/23/2019 00:08:08`

### Q5. Hệ điều hành nào được cài đặt?
![image](https://hackmd.io/_uploads/B1T8nKUrbe.png)
> **Đáp án:** `Windows 10`

### Q6. Chủ đề được sử dụng khi tạo ra E01 là gì?
*Gợi ý: Phân biệt chữ hoa chữ thường, hai từ.*

* Minerva (Minerva McGonagall)
    ![image](https://hackmd.io/_uploads/rkNd2YUrZx.png)
* Voldemort
    ![image](https://hackmd.io/_uploads/SJqw3YLBZe.png)
    ![image](https://hackmd.io/_uploads/B1NK3tUrZe.png)
    ![image](https://hackmd.io/_uploads/SJnFhKIBbg.png)
* Horcrux
    ![image](https://hackmd.io/_uploads/ByS5ht8HZl.png)
* Dementor
    ![image](https://hackmd.io/_uploads/Syi5hF8HZl.png)

> **Chủ đề:** `Harry Potter`

### Q7. Tên được giải mã của Hồ sơ bằng chứng?
![image](https://hackmd.io/_uploads/HkrsnFLHWx.png)
![image](https://hackmd.io/_uploads/S1Vn3YUBWx.png)
> **Đáp án:** `You're a wizard Harry!`

### Q8. Tên máy chủ của phân vùng Windows?
![image](https://hackmd.io/_uploads/SJ6n3KISZe.png)
> **Hostname:** `TOTALLYNOTAHACK`

### Q9. Tên phần mềm nhắn tin được sử dụng?
![image](https://hackmd.io/_uploads/H1-T3FLHbl.png)
![image](https://hackmd.io/_uploads/SJdT2YLH-e.png)
> **Software:** `Skype`

### Q10. Mã zip của bài đăng craigslist của Karen?
![image](https://hackmd.io/_uploads/SJCahY8Sbe.png)
> **Zip code:** `19709`

### Q11. What are the initials of the person who contacted Karen?
> **Initials:** `M.S`

### Q12. How much money was TAAUSAI willing to pay Karen upfront?
![image](https://hackmd.io/_uploads/Hk502KIBWx.png)
> **Amount:** `150000 USD`

### Q13. What country is Karen meeting the hacker group in?
Tọa độ: `27°22’50.10″N, 33°37’54.62″E`
![image](https://hackmd.io/_uploads/HJolaK8Hbg.png)
> **Country:** `Ai Cập` (Egypt)

### Q14. What is the timezone?
![image](https://hackmd.io/_uploads/S1U-pYUBbg.png)
> **Timezone:** `UTC`

### Q15. Thời gian truy cập cuối cùng cho AlpacaCare.docx?
*Yêu cầu: Gửi theo UTC dưới dạng MM/DD/YYYY HH:MM:SS (24h)*
Vì máy đang ở múi giờ ICT nên cần đổi sang UTC.
![image](https://hackmd.io/_uploads/HJkQptIrZl.png)
> **Đáp án:** `03/17/2019 21:52:20`

### Q16. Chữ cái ổ đĩa của vách ngăn thứ hai?
![image](https://hackmd.io/_uploads/BkAbTYLSZg.png)
> **Drive Letter:** `A`

### Q17. Câu trả lời cho câu hỏi mà quản lý của Michael hỏi Karen?
![image](https://hackmd.io/_uploads/BJEuTKLBWl.png)
![image](https://hackmd.io/_uploads/BJKdTY8HZe.png)
> **Đáp án:** `TheCardCriesNoMore`

### Q18. Karen được xem xét cho công việc gì?
*Lưu ý: Viết thường, không khoảng trắng.*
![image](https://hackmd.io/_uploads/BkJtatUSZl.png)
> **Job:** `cybersecurityanalysts`

### Q19. Mật khẩu của Karen được thay đổi lần cuối khi nào (UTC)?
![image](https://hackmd.io/_uploads/BJQYptIr-e.png)
![image](https://hackmd.io/_uploads/rJuKTYLrWe.png)
> **Time:** `03/21/2019 19:13:09`

### Q20. Phiên bản Chrome nào được cài đặt?
![image](https://hackmd.io/_uploads/Syb56FLHZx.png)
> **Version:** `72.0.3626.121`

### Q21. Địa chỉ email liên kết với câu trả lời từ Alpaca enthusiast?
![image](https://hackmd.io/_uploads/Hy1o6KUS-g.png)
> **Email:** `7066d7539fdf30539e2e43ba5fd21606@reply.craigslist.org`

### Q22. Công cụ mà Karen hy vọng sẽ học cách sử dụng?
![image](https://hackmd.io/_uploads/rJBoTKLrWe.png)
> **Tool:** `BeEF`

### Q23. Tên tập đĩa của phân vùng thứ ba trên laptop?
![image](https://hackmd.io/_uploads/S1p3aYIBWe.png)
> **Label:** `PacaLady`

### Q24. HostUrl của Skype là gì?
![image](https://hackmd.io/_uploads/rkHBRFLSWe.png)
![image](https://hackmd.io/_uploads/Bk5HCF8HWe.png)
> **URL:** `https://download.skype.com/s4l/download/win/Skype-8.41.0.54.exe`

### Q25. Tên của Alpaca yêu thích của Bob?
![image](https://hackmd.io/_uploads/HkHURtUBZe.png)
![image](https://hackmd.io/_uploads/H1KL0t8Bbe.png)

Tải về và extract với password: `pacalove`
![image](https://hackmd.io/_uploads/BJovCFIrZx.png)
![image](https://hackmd.io/_uploads/HJgOCt8r-x.png)

Giải mã chuỗi: `MFDfMiTfMyHfMyHfMyj=`
![image](https://hackmd.io/_uploads/r1ndRKIHZe.png)
![image](https://hackmd.io/_uploads/r1WF0tLBZg.png)
> **Name:** `Jerry`

### Q26. Tìm tệp với MD5 2BD8E82961FC29BBBCF0083D0811A9DB?
![image](https://hackmd.io/_uploads/rk6YCtLHbg.png)
![image](https://hackmd.io/_uploads/BJL90FUB-x.png)
![image](https://hackmd.io/_uploads/B1RqAFLBZl.png)
> **Link:** `http://ctf.champdfa.org/winnerwinnerchickendinner/potato.txt`

### Q27. Tên miền trang web Karen duyệt (liên quan AlpacaCare.docx)?
![image](https://hackmd.io/_uploads/H17sAtUSbg.png)
![image](https://hackmd.io/_uploads/r1oiRt8BWl.png)
> **Domain:** `palominoalpacafarm`

### Q28. Dấu thời gian tạo tệp bí mật (UTC)?
![image](https://hackmd.io/_uploads/SkdnCK8S-e.png)
![image](https://hackmd.io/_uploads/BJ6hRFLB-l.png)
![image](https://hackmd.io/_uploads/HyV6AFIS-l.png)

*Chú ý: Bật hiển thị giây trong WinRAR: Options 🡪 Settings 🡪 Show seconds*
![image](https://hackmd.io/_uploads/SJkR0FIBZe.png)
> **Đáp án:** `03/25/2019 15:23:45`

### Q29. Mật khẩu LinkedIn của Duane là gì?
Vị trí: `C:\Users\Karen\Desktop\DuanesChallenge`.
![image](https://hackmd.io/_uploads/HyiJJcLrbx.png)
![image](https://hackmd.io/_uploads/ry1g15IS-e.png)
![image](https://hackmd.io/_uploads/S14lyqLr-g.png)

Kéo xuống cuối sẽ có 1 đoạn Base64. Copy và Export file ra Excel.
![image](https://hackmd.io/_uploads/HyyWkqLHbg.png)
![image](https://hackmd.io/_uploads/r1ob158BWx.png)
![image](https://hackmd.io/_uploads/SJZf158H-x.png)

> **Password:** `R33*D)DogHouse`

## Phần 4: Phân tích RAM (ram.mem)


### Q0: Profile phù hợp nhất cho máy này?
*Xác định profile Volatility phù hợp để phân tích memory dump*

```bash
vol -f ram.mem imageinfo
```
![image](https://hackmd.io/_uploads/HyGQCqUB-x.png)

> **Profile:** `Win7SP1x64`



### Q1: Process ID của notepad.exe?
*Liệt kê các process đang chạy để tìm notepad.exe*

```bash
vol -f ram.mem --profile=Win7SP1x64 pslist | grep notepad
```
![image](https://hackmd.io/_uploads/SJsX09Irbe.png)

> **PID:** `3032`



### Q2: Tên tiến trình con của wscript.exe?
*Phân tích process tree để tìm child process của wscript.exe*

```bash
vol -f ram.mem --profile=Win7SP1x64 pstree
```
![image](https://hackmd.io/_uploads/HyB40c8Hbe.png)

> **Process Name:** `UWkpjFjDzM.exe`



### Q3: Địa chỉ IP của máy tại thời điểm dump RAM?
*Kiểm tra network connections và interfaces*

```bash
vol -f ram.mem --profile=Win7SP1x64 netscan
```
![image](https://hackmd.io/_uploads/ryJUCqIrWe.png)
> **IP:** `10.0.0.101`



### Q4: IP của kẻ tấn công (dựa trên PID bị nhiễm)?
*Xác định remote IP kết nối với process độc hại*

```bash
vol -f ram.mem --profile=Win7SP1x64 netscan | grep 3496
```
![image](https://hackmd.io/_uploads/Hy6uC5LrWg.png)


> **Attacker IP:** `10.0.0.106`



### Q5: VCRUNTIME140.dll liên quan đến tên quy trình nào?
*Kiểm tra DLL được load bởi các process*

```bash
vol -f ram.mem --profile=Win7SP1x64 dlllist | grep -8 33 "VCRUNTIME140.dll"
```
![image](https://hackmd.io/_uploads/BkOFRcLSZe.png)

> **Process Name:** `OfficeClickToR`



### Q6: Giá trị băm MD5 của phần mềm độc hại?
*Dump malicious process và tính hash*
![image](https://hackmd.io/_uploads/B1STCqLrbl.png)

```bash
vol -f ram.mem --profile=Win7SP1x64 procdump -p 3496 -D output/
md5sum output/executable.3496.exe
```
![image](https://hackmd.io/_uploads/Hy3aC9IBWe.png)

> **MD5:** `690ea20bc3bdfb328e23005d9a80c290`



### Challenge 7: Hàm băm LM của tài khoản bobs?
*Extract password hashes từ registry*
![image](https://hackmd.io/_uploads/HJKlyjLHbx.png)

```bash
vol -f ram.mem --profile=Win7SP1x64 hashdump
```

> **LM Hash:** `aad3b435b51404eeaad3b435b51404ee`



### Q8: Protections tại nút VAD của 0xfffffa800577ba10?
*Kiểm tra Virtual Address Descriptor để xem memory protections*

```bash
vol -f ram.mem --profile=Win7SP1x64 vadinfo | grep "0xfffffa800577ba10" -A 3
```
![image](https://hackmd.io/_uploads/r14bkiIBWe.png)

> **Protection:** `PAGE_READONLY`



### Q9: Protections của VAD từ 0x00000000033c0000 đến 0x00000000033dffff?
*Tìm protection flags cho memory range cụ thể*

```bash
vol -f ram.mem --profile=Win7SP1x64 vadinfo | grep "Start 0x00000000033c0000 End 0x00000000033dffff" -A 3
```
![image](https://hackmd.io/_uploads/rJ4GJjLr-e.png)

> **Protection:** `PAGE_NOACCESS`



### Q10: Tên của tập lệnh VBS đang chạy?
*Phân tích command line của wscript.exe*
![image](https://hackmd.io/_uploads/BJyQkiUSWl.png)

```bash
vol -f ram.mem --profile=Win7SP1x64 cmdline | grep -i wscript
```
![image](https://hackmd.io/_uploads/Hy8XyoUSZl.png)

> **Script Name:** `vhjReUDEuumrX`



### Q11: Tên chương trình chạy lúc 2019-03-07 23:06:58 UTC?
*Sử dụng shimcache để xem execution history*

```bash
vol -f ram.mem --profile=Win7SP1x64 shimcache | grep "2019-03-07 23:06:58"
```
![image](https://hackmd.io/_uploads/SypQyoUH-x.png)

> **Program:** `C:\Program Files (x86)\Microsoft\Skype for Desktop\Skype.exe`



### Q12: Những gì đã được viết trong notepad.exe?
*Dump memory của notepad process và extract text*

```bash
vol -f ram.mem --profile=Win7SP1x64 memdump -p 3032 -D output/
strings output/3032.dmp | grep -A 10 -B 10 "relevant_text"
```
![image](https://hackmd.io/_uploads/BJU4JjIrZx.png)
![image](https://hackmd.io/_uploads/HysVkiLHWl.png)




### Q13: Tên viết tắt của tệp tại bản ghi tệp 59045?
*Parse Master File Table để tìm file record*

```bash
vol -f ram.mem --profile=Win7SP1x64 mftparser | grep "59045" -A 20
```
![image](https://hackmd.io/_uploads/Hks8yo8rbg.png)
![image](https://hackmd.io/_uploads/rJ7vks8SZl.png)

> **Filename:** `EMPLOY~1.XLS`



### Q14: PID bị nhiễm (Meterpreter)?
*Dựa trên phân tích từ Q2, UWkpjFjDzM.exe là malware*

```bash
vol -f ram.mem --profile=Win7SP1x64 pslist | grep UWkpjFjDzM
```
![image](https://hackmd.io/_uploads/SJ2Pki8SZe.png)
![image](https://hackmd.io/_uploads/rkzdJiISZx.png)

> **PID:** `3496`



## Phần 5: Kiểm tra (Incident Response)

### C0. Compression format used?
*Định dạng nén mà attacker sử dụng để đóng gói dữ liệu*
![image](https://hackmd.io/_uploads/Sy2_kiUrZx.png)

> **Format:** `7z`



### C1. Password used by attacker?
*Mật khẩu được sử dụng để bảo vệ file nén hoặc truy cập hệ thống*
![image](https://hackmd.io/_uploads/HJnYJjIr-g.png)
![image](https://hackmd.io/_uploads/Bke5kiLBbg.png)

> **Password:** `apokonooijang1`



### C2. Folder used to temporarily store data?
*Thư mục tạm thời để staging dữ liệu trước khi exfiltration*
![image](https://hackmd.io/_uploads/rJUqyiUHWl.png)

> **Path:** `/tmp/...`



### C3. Domain name (onion) used?
*Tor hidden service domain được attacker sử dụng*
![image](https://hackmd.io/_uploads/BJTc1iLHbx.png)

> **Onion Domain:** `jilgx2dpduxwr3byjbxfbf777kfmtqoed2rrbwshhlrdpfhzu63hj2qd.onion`



### C4. Web shell type?
*Loại web shell được deploy trên server*
![image](https://hackmd.io/_uploads/H1BjkjIr-x.png)

> **Web Shell:** `sonang.php`



### C5. File affected to deface the website?
*File chính bị thay đổi trong cuộc tấn công defacement*
![image](https://hackmd.io/_uploads/SyFiJiUS-e.png)

> **File:** `index.php`



### C6. File containing DB creds (full path)?
*Đường dẫn đầy đủ đến file chứa thông tin xác thực database*
![image](https://hackmd.io/_uploads/ryxhki8HZx.png)

> **Path:** `/opt/drillsaham/.env`



### C7. Tool used during first compromise?
*Công cụ được sử dụng trong giai đoạn initial access*
![image](https://hackmd.io/_uploads/BydnJiLSWx.png)

> **Tool:** `Curl`



### C8. Backdoor special key?
*Key hoặc signature đặc biệt của backdoor*
![image](https://hackmd.io/_uploads/rk22kjISZe.png)

> **Key:** `BKD0`



### C9. Linux tool used to exfiltrate data?
*Công cụ Linux được dùng để đánh cắp dữ liệu*
![image](https://hackmd.io/_uploads/HJbT1oUrWe.png)

> **Tool:** `Rsync`



### C10. Email used to report abuse?
*Địa chỉ email liên hệ của attacker hoặc dùng để báo cáo*
![image](https://hackmd.io/_uploads/rJNAJsISZg.png)


> **Email:** `apokono@jilgx2dpduxwr3byjbxfbf777kfmtqoed2rrbwshhlrdpfhzu63hj2qd.onion`



### C11. Server IP during defacement?
*Địa chỉ IP của server tại thời điểm bị defacement*
![image](https://hackmd.io/_uploads/ry_JejUH-g.png)

> **IP:** `10.108.102.48`



### C12. IP of local repository storing affected Ubuntu package?
*Địa chỉ IP của repository local chứa package Ubuntu bị ảnh hưởng*
![image](https://hackmd.io/_uploads/B1Ryes8rWl.png)

> **IP:** `10.108.201.140`



## MISC Challenge

![image](https://hackmd.io/_uploads/HygX8NvBZx.png)



### Phiến Poneglyphs Thứ Nhất

Ở phiến đầu tiên, ta nhận được một tấm ảnh có tên **poneglyphs.jpg**.

![image](https://hackmd.io/_uploads/rkSV8NPBZx.png)

Thử kiểm tra định dạng thực sự của file ảnh này:

![image](https://hackmd.io/_uploads/S1ZBLEDHZg.png)

Kết quả cho thấy đây không phải JPG thông thường mà là **Targa image data**.


Mỗi định dạng ảnh (PNG, JPG, …) đều có **magic bytes** ở phần đầu file. Với ảnh JPG, 3 byte đầu tiên luôn là:

```
FF D8 FF
```

Nếu các byte này bị thay đổi, trình đọc ảnh sẽ không nhận diện đúng định dạng, dẫn đến lỗi hoặc hiển thị sai dữ liệu.

![image](https://hackmd.io/_uploads/SyS8LEPr-g.png)

Mở file bằng **HxD**, ta thấy 3 byte đầu **không phải** `FF D8 FF`.

![image](https://hackmd.io/_uploads/BJFPIVwHbx.png)

Tiến hành chỉnh sửa lại các byte đầu cho đúng chuẩn JPG. Sau khi sửa xong, file ảnh có thể mở bình thường.

![image](https://hackmd.io/_uploads/SyEOLNwBWg.png)

Kết quả thu được là **phiến poneglyphs đầu tiên**, chứa ký tự **P**.



### Phiến Poneglyphs Thứ Hai

Tiếp theo, ta đi vào thư mục của phiến thứ hai:

![image](https://hackmd.io/_uploads/HJbYU4wSZl.png)

Bên trong có hai folder, mỗi folder chứa nhiều file `.php`.

Khi kiểm tra một trong các folder, ta nhận thấy chỉ có **1 bit dữ liệu**, nên thử mở ra xem nội dung. Kết quả thu được là ký tự **O**.

![image](https://hackmd.io/_uploads/SJ75INwrWe.png)

Vậy đây chính là **phiến poneglyphs thứ hai**.



### Phiến Poneglyphs Cuối Cùng

Đến với mảnh cuối:

![image](https://hackmd.io/_uploads/B1kyvVvBWx.png)

Ta tiến hành **decode đoạn Base64** được cung cấp:

![image](https://hackmd.io/_uploads/SkdyvNPr-x.png)

Sau khi decode, kết quả là chuỗi **`user_input`**.

Chuỗi này gợi ý rằng dữ liệu đến từ **đầu vào của người dùng**. Vậy trên website, nơi nào cho phép nhập dữ liệu?

![image](https://hackmd.io/_uploads/HJPlPEwS-x.png)

Khả năng cao chính là **URL**.

#### Khai thác

Ta thử sử dụng kỹ thuật **chèn mã (XSS)** bằng cách truyền tham số qua URL:

```
?user_input=<script>alert()</script>
```

Khi payload được thực thi, ta thu được **phiến poneglyphs cuối cùng** với ký tự **F**.



### Tổng Hợp Manh Mối

Ba mảnh poneglyphs thu được là:

```
F – O – P
```

Quay lại trang đầu để xem **hint**:

![image](https://hackmd.io/_uploads/ByMbvEPHbx.png)
![image](https://hackmd.io/_uploads/SygGwVPSbx.png)

Từ đó suy ra đây có thể là một **đường dẫn**. Sau khi thử các hoán vị, ta tìm được URL hợp lệ:

```
/FOP
```

![image](https://hackmd.io/_uploads/BJ6MvVPr-l.png)



### Kết Thúc Challenge

Sau khi nhập key **"Vua Hải Tặc"**, hệ thống hiển thị thông báo thành công.

Tiếp theo, quay lại trang trước và click vào **kho báu**:

![image](https://hackmd.io/_uploads/B17mDEwrWx.png)

Ta nhận được một đoạn dữ liệu mới. Đưa đoạn này lên **CyberChef** để xử lý tiếp:

![image](https://hackmd.io/_uploads/SJumDEPHWx.png)