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
![image](/images/gductf_training/1.png)

> **IP của attacker:** `216.139.234.95`

### Q2: Thời gian tấn công bằng webshell
Dựa vào IP tìm được ở câu 1, đối chiếu qua thời gian (time).
![image](/images/gductf_training/2.png)

> **Thời gian tấn công:** `15:19:50`

### Q3: Xác minh mã hash SHA-256 của webshell
Dựa vào câu 1 đối chiếu thì đường dẫn webshell là: `/webs/web/images/image1.php`.
Tuy nhiên, khi vào thư mục `images` lại không tìm thấy tệp `image1.php`. Có nghĩa là attacker đã đổi tên và di chuyển nó đi nơi khác.
![image](/images/gductf_training/3.png)

Nhìn xuống dòng tiếp theo sẽ thấy attacker truy cập vào: `/Webs/Web/ListSP/showSanPham.php`
![image](/images/gductf_training/4.png)

Sau khi truy cập vào đường dẫn thì tìm được webshell:
![image](/images/gductf_training/5.png)

Tính toán mã hash SHA-256 của webshell:
![image](https://hackmd.io/_uploads/B1KFqK8SWx.png)

> **SHA-256:**
> ```text
> 6cc20142eb377f11e445657df27b41e5c5bfcbab4ba558ee17495fc15d534765
> ```

### Q4: Xác định tài khoản được tạo thêm
Để xác định được tài khoản được tạo thêm, kiểm tra Windows Powershell của `web-data`.
Để tạo tên đăng nhập sẽ dùng lệnh `New-LocalUser` nên chỉ cần lọc lệnh này ra.
![image](/images/gductf_training/7.png)

Sau khi kiểm tra thì biết được thông tin:
![image](/images/gductf_training/8.png)

> **Username:** `SOCAdmin`
> **Password:** `qwerty@123#`

### Q5: Xác định mã hash SHA-256 của công cụ leo thang đặc quyền
Để xác định được công cụ leo thang đặc quyền, kiểm tra Windows Powershell của `web-data`.
Để tải 1 công cụ leo thang đặc quyền thì dùng lệnh `wget` nên ta sẽ lọc từ khóa này.
![image](/images/gductf_training/9.png)

Sau khi kiểm tra thì tìm được:
![image](/images/gductf_training/10.png)

Xác định `GodPotato-NET35.exe` là công cụ leo thang đặc quyền.
![image](/images/gductf_training/11.png)

> **SHA-256:**
> ```text
> 3027a212272957298bf4d32505370fa63fb162d6a6a6ec091af9d7626317a858
> ```

### Q6: Xác định mật khẩu tài khoản dùng để tấn công AD
Như ở câu trên thì attacker đã dùng công cụ leo thang đặc quyền nên thường tài khoản tấn công sẽ là **Administrator**.
![image](/images/gductf_training/12.png)

Theo dõi luồng (Follow Stream):
![image](/images/gductf_training/13.png)
Tài khoản dùng tấn công đã đăng nhập vào lúc `16:00:49`.

Xuất file `ad-vm1.pcapng` sang `ad-vm1.pcap`.
![image](/images/gductf_training/14.png)

Dùng **Network Miner** tìm đến khoảng thời gian trên thì sẽ thấy hash password (NTLMv2).
![image](/images/gductf_training/15.png)

Dùng Hashcat để crack chuỗi NetNTLMv2 hash. Cấu trúc: `USERNAME::DOMAIN:SERVER_CHALLENGE:NTLMV2_RESPONSE:BLOB`

> **Password:** `mayihelpyou`

### Q7: Policy trên máy người dùng
Kiểm tra trong Windows Powershell của `ad-data`. Vì là policy nên lọc theo `new-gpo`.
![image](/images/gductf_training/16.png)

**Cú pháp cơ bản:**
`New-GPO -Name "Tên-GPO" [-Domain "tên-domain"] [-Comment "ghi chú"] [-StarterGPOName "tên-starter-gpo"]`

![image](/images/gductf_training/17.png)
![image](/images/gductf_training/18.png)

> **Tên Policy:** `OpenThis`

### Q8: Xác định mã hash SHA-256 của Mã độc mã hóa tệp tin
Mở file `pc-user-vm0.pcapng`. Lọc theo giao thức `smb2`.
Chuột phải chọn **Protocol Preferences 🡪 SMB2 (…) 🡪 Use the full…**
![image](/images/gductf_training/19.png)

Sau đó Export file -> Lưu file -> Dùng `sha256sum` để kiểm tra.
![image](/images/gductf_training/20.png)
![image](/images/gductf_training/21.png)
![image](/images/gductf_training/22.png)

> **SHA-256:**
> ```text
> be56b79a52bfc2ed32927cb5fd654d7ca2d145838f5f5ce0af5644b945eae99f
> ```



## Phần 2: Đọc ổ đĩa (Horcrux-partition 5)

### Q1. Bản phân phối Linux nào đang được sử dụng?
Kiểm tra tại `partition5/boot`.
![image](/images/gductf_training/23.png)

> **Đáp án:** `vmlinuz-4.13.0-kali1-amd64`

### Q2. Hàm băm MD5 của access.log apache là gì?
Đường dẫn: `/var/log/apache/`.
![image](/images/gductf_training/24.png)

Vào file chọn *Export file hash list*, mở file đã export.
![image](/images/gductf_training/25.png)
![image](/images/gductf_training/26.png)

> **MD5 Hash:** `d41d8cd98f00b204e9800998ecf8427e`

### Q3. Tên tệp của công cụ kết xuất thông tin xác thực đã tải xuống?
Kiểm tra thư mục Downloads: `/root/Downloads/`.
![image](/images/gductf_training/27.png)

> **Tên công cụ:** `mimikatz_trunk.zip`

### Q4. Đường dẫn tuyệt đối của tệp siêu bí mật?
Kiểm tra file `.bash_history` trong `/root/` để xem lịch sử lệnh.
![image](/images/gductf_training/28.png)
![image](/images/gductf_training/29.png)

> **Đường dẫn:** `/root/Desktop/SuperSecretFile.txt`

### Q5. Chương trình nào được sử dụng với didyouthinkwedmakeiteasy.jpg?
Vẫn tìm trong `.bash_history`.
![image](/images/gductf_training/30.png)

> **Chương trình:** `binwalk`

### Q6. Mục tiêu thứ ba trong danh sách kiểm tra mà Karen tạo ra?
Kiểm tra tại `/root/Desktop/`.
![image](/images/gductf_training/31.png)

> **Mục tiêu:** `Profit`

### Q7. Apache đã chạy bao nhiêu lần?
Kiểm tra `/var/log/`.
![image](/images/gductf_training/32.png)
Kích thước file `access.log` là 0.

> **Kết luận:** Máy chủ Apache chưa chạy lần nào.

### Q8. Hồ sơ nào chứng minh máy này dùng để tấn công người khác?
Vào `/root/`.
![image](/images/gductf_training/33.png)

### Q9. Karen đang chế nhạo ai qua kịch bản bash?
Vào `/root/Documents/myfirsthack/`.
![image](/images/gductf_training/34.png)

> **Karen đang chế nhạo:** `Young`

### Q10. Ai là người dùng đã root vào lúc 11:26 nhiều lần?
Vào `partition5/var/log/auth.log`.
![image](/images/gductf_training/35.png)

> **User:** `postgres`

### Q11. Dựa trên lịch sử bash, thư mục làm việc hiện tại là gì?
Vào `/root/`.
![image](/images/gductf_training/36.png)

> **Thư mục:** `/root/Documents/myfirsthack/`



## Phần 3: Phân tích đĩa (Horcrux-partition 2)

### Q1. Tên của examiner đã tạo ra E01 là gì?
![image](/images/gductf_training/37.png)
> **Đáp án:** `Minerva`

### Q2. Tên người dùng chính của máy?
![image](/images/gductf_training/38.png)
![image](/images/gductf_training/39.png)
> **Đáp án:** `Karen`

### Q3. Hàm băm SHA1 của bằng chứng là gì?
![image](/images/gductf_training/40.png)
> **SHA1:** `0fa6ab4bd9a707d49ded70e8b9198fe18114b369`

### Q4. Hình ảnh được tạo ra lúc mấy giờ?
Format UTC (24h): `MM/DD/YYYY HH:MM:SS`
![image](/images/gductf_training/41.png)
> **Đáp án:** `03/23/2019 00:08:08`

### Q5. Hệ điều hành nào được cài đặt?
![image](/images/gductf_training/42.png)
> **Đáp án:** `Windows 10`

### Q6. Chủ đề được sử dụng khi tạo ra E01 là gì?
*Gợi ý: Phân biệt chữ hoa chữ thường, hai từ.*

* Minerva (Minerva McGonagall)
    ![image](/images/gductf_training/43.png)
* Voldemort
    ![image](/images/gductf_training/44.png)
    ![image](/images/gductf_training/45.png)
    ![image](/images/gductf_training/46.png)
* Horcrux
    ![image](/images/gductf_training/47.png)
* Dementor
    ![image](/images/gductf_training/48.png)

> **Chủ đề:** `Harry Potter`

### Q7. Tên được giải mã của Hồ sơ bằng chứng?
![image](/images/gductf_training/49.png)
![image](/images/gductf_training/50.png)
> **Đáp án:** `You're a wizard Harry!`

### Q8. Tên máy chủ của phân vùng Windows?
![image](/images/gductf_training/51.png)
> **Hostname:** `TOTALLYNOTAHACK`

### Q9. Tên phần mềm nhắn tin được sử dụng?
![image](/images/gductf_training/52.png)
![image](/images/gductf_training/53.png)
> **Software:** `Skype`

### Q10. Mã zip của bài đăng craigslist của Karen?
![image](/images/gductf_training/54.png)
> **Zip code:** `19709`

### Q11. What are the initials of the person who contacted Karen?
> **Initials:** `M.S`

### Q12. How much money was TAAUSAI willing to pay Karen upfront?
![image](/images/gductf_training/55.png)
> **Amount:** `150000 USD`

### Q13. What country is Karen meeting the hacker group in?
Tọa độ: `27°22’50.10″N, 33°37’54.62″E`
![image](/images/gductf_training/56.png)
> **Country:** `Ai Cập` (Egypt)

### Q14. What is the timezone?
![image](/images/gductf_training/57.png)
> **Timezone:** `UTC`

### Q15. Thời gian truy cập cuối cùng cho AlpacaCare.docx?
*Yêu cầu: Gửi theo UTC dưới dạng MM/DD/YYYY HH:MM:SS (24h)*
Vì máy đang ở múi giờ ICT nên cần đổi sang UTC.
![image](/images/gductf_training/58.png)
> **Đáp án:** `03/17/2019 21:52:20`

### Q16. Chữ cái ổ đĩa của vách ngăn thứ hai?
![image](/images/gductf_training/59.png)
> **Drive Letter:** `A`

### Q17. Câu trả lời cho câu hỏi mà quản lý của Michael hỏi Karen?
![image](/images/gductf_training/60.png)
![image](/images/gductf_training/61.png)
> **Đáp án:** `TheCardCriesNoMore`

### Q18. Karen được xem xét cho công việc gì?
*Lưu ý: Viết thường, không khoảng trắng.*
![image](/images/gductf_training/62.png)
> **Job:** `cybersecurityanalysts`

### Q19. Mật khẩu của Karen được thay đổi lần cuối khi nào (UTC)?
![image](/images/gductf_training/63.png)
![image](/images/gductf_training/64.png)
> **Time:** `03/21/2019 19:13:09`

### Q20. Phiên bản Chrome nào được cài đặt?
![image](/images/gductf_training/65.png)
> **Version:** `72.0.3626.121`

### Q21. Địa chỉ email liên kết với câu trả lời từ Alpaca enthusiast?
![image](/images/gductf_training/66.png)
> **Email:** `7066d7539fdf30539e2e43ba5fd21606@reply.craigslist.org`

### Q22. Công cụ mà Karen hy vọng sẽ học cách sử dụng?
![image](/images/gductf_training/67.png)
> **Tool:** `BeEF`

### Q23. Tên tập đĩa của phân vùng thứ ba trên laptop?
![image](/images/gductf_training/68.png)
> **Label:** `PacaLady`

### Q24. HostUrl của Skype là gì?
![image](/images/gductf_training/69.png)
![image](/images/gductf_training/70.png)
> **URL:** `https://download.skype.com/s4l/download/win/Skype-8.41.0.54.exe`

### Q25. Tên của Alpaca yêu thích của Bob?
![image](/images/gductf_training/71.png)
![image](/images/gductf_training/72.png)

Tải về và extract với password: `pacalove`
![image](/images/gductf_training/73.png)
![image](/images/gductf_training/74.png)

Giải mã chuỗi: `MFDfMiTfMyHfMyHfMyj=`
![image](/images/gductf_training/75.png)
![image](/images/gductf_training/76.png)
> **Name:** `Jerry`

### Q26. Tìm tệp với MD5 2BD8E82961FC29BBBCF0083D0811A9DB?
![image](/images/gductf_training/77.png)
![image](/images/gductf_training/78.png)
![image](/images/gductf_training/79.png)
> **Link:** `http://ctf.champdfa.org/winnerwinnerchickendinner/potato.txt`

### Q27. Tên miền trang web Karen duyệt (liên quan AlpacaCare.docx)?
![image](/images/gductf_training/80.png)
![image](/images/gductf_training/81.png)
> **Domain:** `palominoalpacafarm`

### Q28. Dấu thời gian tạo tệp bí mật (UTC)?
![image](/images/gductf_training/82.png)
![image](/images/gductf_training/83.png)
![image](/images/gductf_training/84.png)

*Chú ý: Bật hiển thị giây trong WinRAR: Options 🡪 Settings 🡪 Show seconds*
![image](/images/gductf_training/85.png)
> **Đáp án:** `03/25/2019 15:23:45`

### Q29. Mật khẩu LinkedIn của Duane là gì?
Vị trí: `C:\Users\Karen\Desktop\DuanesChallenge`.
![image](/images/gductf_training/86.png)
![image](/images/gductf_training/87.png)
![image](/images/gductf_training/88.png)

Kéo xuống cuối sẽ có 1 đoạn Base64. Copy và Export file ra Excel.
![image](/images/gductf_training/89.png)
![image](/images/gductf_training/90.png)
![image](/images/gductf_training/91.png)

> **Password:** `R33*D)DogHouse`

## Phần 4: Phân tích RAM (ram.mem)


### Q0: Profile phù hợp nhất cho máy này?
*Xác định profile Volatility phù hợp để phân tích memory dump*

```bash
vol -f ram.mem imageinfo
```
![image](/images/gductf_training/92.png)

> **Profile:** `Win7SP1x64`



### Q1: Process ID của notepad.exe?
*Liệt kê các process đang chạy để tìm notepad.exe*

```bash
vol -f ram.mem --profile=Win7SP1x64 pslist | grep notepad
```
![image](/images/gductf_training/93.png)

> **PID:** `3032`



### Q2: Tên tiến trình con của wscript.exe?
*Phân tích process tree để tìm child process của wscript.exe*

```bash
vol -f ram.mem --profile=Win7SP1x64 pstree
```
![image](/images/gductf_training/94.png)

> **Process Name:** `UWkpjFjDzM.exe`



### Q3: Địa chỉ IP của máy tại thời điểm dump RAM?
*Kiểm tra network connections và interfaces*

```bash
vol -f ram.mem --profile=Win7SP1x64 netscan
```
![image](/images/gductf_training/95.png)
> **IP:** `10.0.0.101`



### Q4: IP của kẻ tấn công (dựa trên PID bị nhiễm)?
*Xác định remote IP kết nối với process độc hại*

```bash
vol -f ram.mem --profile=Win7SP1x64 netscan | grep 3496
```
![image](/images/gductf_training/96.png)


> **Attacker IP:** `10.0.0.106`



### Q5: VCRUNTIME140.dll liên quan đến tên quy trình nào?
*Kiểm tra DLL được load bởi các process*

```bash
vol -f ram.mem --profile=Win7SP1x64 dlllist | grep -8 33 "VCRUNTIME140.dll"
```
![image](/images/gductf_training/97.png)

> **Process Name:** `OfficeClickToR`



### Q6: Giá trị băm MD5 của phần mềm độc hại?
*Dump malicious process và tính hash*
![image](/images/gductf_training/98.png)

```bash
vol -f ram.mem --profile=Win7SP1x64 procdump -p 3496 -D output/
md5sum output/executable.3496.exe
```
![image](/images/gductf_training/99.png)

> **MD5:** `690ea20bc3bdfb328e23005d9a80c290`



### Challenge 7: Hàm băm LM của tài khoản bobs?
*Extract password hashes từ registry*
![image](/images/gductf_training/100.png)

```bash
vol -f ram.mem --profile=Win7SP1x64 hashdump
```

> **LM Hash:** `aad3b435b51404eeaad3b435b51404ee`



### Q8: Protections tại nút VAD của 0xfffffa800577ba10?
*Kiểm tra Virtual Address Descriptor để xem memory protections*

```bash
vol -f ram.mem --profile=Win7SP1x64 vadinfo | grep "0xfffffa800577ba10" -A 3
```
![image](/images/gductf_training/101.png)

> **Protection:** `PAGE_READONLY`



### Q9: Protections của VAD từ 0x00000000033c0000 đến 0x00000000033dffff?
*Tìm protection flags cho memory range cụ thể*

```bash
vol -f ram.mem --profile=Win7SP1x64 vadinfo | grep "Start 0x00000000033c0000 End 0x00000000033dffff" -A 3
```
![image](/images/gductf_training/102.png)

> **Protection:** `PAGE_NOACCESS`



### Q10: Tên của tập lệnh VBS đang chạy?
*Phân tích command line của wscript.exe*
![image](/images/gductf_training/103.png)

```bash
vol -f ram.mem --profile=Win7SP1x64 cmdline | grep -i wscript
```
![image](/images/gductf_training/104.png)

> **Script Name:** `vhjReUDEuumrX`



### Q11: Tên chương trình chạy lúc 2019-03-07 23:06:58 UTC?
*Sử dụng shimcache để xem execution history*

```bash
vol -f ram.mem --profile=Win7SP1x64 shimcache | grep "2019-03-07 23:06:58"
```
![image](/images/gductf_training/105.png)

> **Program:** `C:\Program Files (x86)\Microsoft\Skype for Desktop\Skype.exe`



### Q12: Những gì đã được viết trong notepad.exe?
*Dump memory của notepad process và extract text*

```bash
vol -f ram.mem --profile=Win7SP1x64 memdump -p 3032 -D output/
strings output/3032.dmp | grep -A 10 -B 10 "relevant_text"
```
![image](/images/gductf_training/106.png)
![image](/images/gductf_training/107.png)




### Q13: Tên viết tắt của tệp tại bản ghi tệp 59045?
*Parse Master File Table để tìm file record*

```bash
vol -f ram.mem --profile=Win7SP1x64 mftparser | grep "59045" -A 20
```
![image](/images/gductf_training/108.png)
![image](/images/gductf_training/109.png)

> **Filename:** `EMPLOY~1.XLS`



### Q14: PID bị nhiễm (Meterpreter)?
*Dựa trên phân tích từ Q2, UWkpjFjDzM.exe là malware*

```bash
vol -f ram.mem --profile=Win7SP1x64 pslist | grep UWkpjFjDzM
```
![image](/images/gductf_training/110.png)
![image](/images/gductf_training/111.png)

> **PID:** `3496`



## Phần 5: Kiểm tra (Incident Response)

### C0. Compression format used?
*Định dạng nén mà attacker sử dụng để đóng gói dữ liệu*
![image](/images/gductf_training/112.png)

> **Format:** `7z`



### C1. Password used by attacker?
*Mật khẩu được sử dụng để bảo vệ file nén hoặc truy cập hệ thống*
![image](/images/gductf_training/113.png)
![image](/images/gductf_training/114.png)

> **Password:** `apokonooijang1`



### C2. Folder used to temporarily store data?
*Thư mục tạm thời để staging dữ liệu trước khi exfiltration*
![image](/images/gductf_training/115.png)

> **Path:** `/tmp/...`



### C3. Domain name (onion) used?
*Tor hidden service domain được attacker sử dụng*
![image](/images/gductf_training/116.png)

> **Onion Domain:** `jilgx2dpduxwr3byjbxfbf777kfmtqoed2rrbwshhlrdpfhzu63hj2qd.onion`



### C4. Web shell type?
*Loại web shell được deploy trên server*
![image](/images/gductf_training/117.png)

> **Web Shell:** `sonang.php`



### C5. File affected to deface the website?
*File chính bị thay đổi trong cuộc tấn công defacement*
![image](/images/gductf_training/118.png)

> **File:** `index.php`



### C6. File containing DB creds (full path)?
*Đường dẫn đầy đủ đến file chứa thông tin xác thực database*
![image](/images/gductf_training/119.png)

> **Path:** `/opt/drillsaham/.env`



### C7. Tool used during first compromise?
*Công cụ được sử dụng trong giai đoạn initial access*
![image](/images/gductf_training/120.png)

> **Tool:** `Curl`



### C8. Backdoor special key?
*Key hoặc signature đặc biệt của backdoor*
![image](/images/gductf_training/121.png)

> **Key:** `BKD0`



### C9. Linux tool used to exfiltrate data?
*Công cụ Linux được dùng để đánh cắp dữ liệu*
![image](/images/gductf_training/122.png)

> **Tool:** `Rsync`



### C10. Email used to report abuse?
*Địa chỉ email liên hệ của attacker hoặc dùng để báo cáo*
![image](/images/gductf_training/123.png)


> **Email:** `apokono@jilgx2dpduxwr3byjbxfbf777kfmtqoed2rrbwshhlrdpfhzu63hj2qd.onion`



### C11. Server IP during defacement?
*Địa chỉ IP của server tại thời điểm bị defacement*
![image](/images/gductf_training/124.png)

> **IP:** `10.108.102.48`



### C12. IP of local repository storing affected Ubuntu package?
*Địa chỉ IP của repository local chứa package Ubuntu bị ảnh hưởng*
![image](/images/gductf_training/125.png)

> **IP:** `10.108.201.140`



## MISC Challenge

![image](/images/gductf_training/126.png)



### Phiến Poneglyphs Thứ Nhất

Ở phiến đầu tiên, ta nhận được một tấm ảnh có tên **poneglyphs.jpg**.

![image](/images/gductf_training/127.png)

Thử kiểm tra định dạng thực sự của file ảnh này:

![image](/images/gductf_training/128.png)

Kết quả cho thấy đây không phải JPG thông thường mà là **Targa image data**.


Mỗi định dạng ảnh (PNG, JPG, …) đều có **magic bytes** ở phần đầu file. Với ảnh JPG, 3 byte đầu tiên luôn là:

```
FF D8 FF
```

Nếu các byte này bị thay đổi, trình đọc ảnh sẽ không nhận diện đúng định dạng, dẫn đến lỗi hoặc hiển thị sai dữ liệu.

![image](/images/gductf_training/129.png)

Mở file bằng **HxD**, ta thấy 3 byte đầu **không phải** `FF D8 FF`.

![image](/images/gductf_training/130.png)

Tiến hành chỉnh sửa lại các byte đầu cho đúng chuẩn JPG. Sau khi sửa xong, file ảnh có thể mở bình thường.

![image](/images/gductf_training/131.png)

Kết quả thu được là **phiến poneglyphs đầu tiên**, chứa ký tự **P**.



### Phiến Poneglyphs Thứ Hai

Tiếp theo, ta đi vào thư mục của phiến thứ hai:

![image](/images/gductf_training/132.png)

Bên trong có hai folder, mỗi folder chứa nhiều file `.php`.

Khi kiểm tra một trong các folder, ta nhận thấy chỉ có **1 bit dữ liệu**, nên thử mở ra xem nội dung. Kết quả thu được là ký tự **O**.

![image](/images/gductf_training/133.png)

Vậy đây chính là **phiến poneglyphs thứ hai**.



### Phiến Poneglyphs Cuối Cùng

Đến với mảnh cuối:

![image](/images/gductf_training/134.png)

Ta tiến hành **decode đoạn Base64** được cung cấp:

![image](/images/gductf_training/135.png)

Sau khi decode, kết quả là chuỗi **`user_input`**.

Chuỗi này gợi ý rằng dữ liệu đến từ **đầu vào của người dùng**. Vậy trên website, nơi nào cho phép nhập dữ liệu?

![image](/images/gductf_training/136.png)

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

![image](/images/gductf_training/137.png)
![image](/images/gductf_training/138.png)

Từ đó suy ra đây có thể là một **đường dẫn**. Sau khi thử các hoán vị, ta tìm được URL hợp lệ:

```
/FOP
```

![image](/images/gductf_training/139.png)



### Kết Thúc Challenge

Sau khi nhập key **"Vua Hải Tặc"**, hệ thống hiển thị thông báo thành công.

Tiếp theo, quay lại trang trước và click vào **kho báu**:

![image](/images/gductf_training/140.png)

Ta nhận được một đoạn dữ liệu mới. Đưa đoạn này lên **CyberChef** để xử lý tiếp:

![image](/images/gductf_training/141.png)