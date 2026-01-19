---
title: "Securinets CTF 2025"
description: "Writeup for Forensic Challenge"
summary: "Writeup for Forensic Challenge"
categories: ["Writeup"]
tags: ["Forensic"]
#externalUrl: ""
date: 2025-10-04
draft: false
authors:
  - ducnocrypt
cover: "/images/post_covers/securinet.jpg"
---


## Silent Visitor

This challenge requires us to investigate a disk image file from a Windows computer to understand suspicious activity. The investigation is divided into logical stages, from initial analysis, identifying the attack source, malware analysis, and finally tracing its actions on the system.

```
What is the SHA256 hash of the disk image provided?
Input: 122b2b4bf1433341ba6e8fefd707379a98e6e9ca376340379ea42edb31a5dba2
Correct answer
Identify the OS build number of the victim’s system?
Input: 19045
Correct answer
What is the ip of the victim's machine?
Input: 192.168.206.131
Correct answer
What is the name of the email application used by the victim?
Input: thunderbird
Correct answer
What is the email of the victim?
Input: ammar55221133@gmail.com
Correct answer
What is the email of the attacker?
Input: masmoudim522@gmail.com
Correct answer
What is the URL that the attacker used to deliver the malware to the victim?
Input: https://tmpfiles.org/dl/23860773/sys.exe
Correct answer
What is the SHA256 hash of the malware file?
Input: be4f01b3d537b17c5ba7dc1bb7cd4078251364398565a0ca1e96982cff820b6d
Correct answer
What is the IP address of the C2 server that the malware communicates with?
Input: 40.113.161.85
Correct answer
What port does the malware use to communicate with its Command & Control (C2) server?
Input: 5000
Correct answer
What is the url if the first Request made by the malware to the c2 server?
Input:  http://40.113.161.85:5000/helppppiscofebabe23
Correct answer
The malware created a file to identify itself. What is the content of that file?
Input: 3649ba90-266f-48e1-960c-b908e1f28aef
Correct answer
Which registry key did the malware modify or add to maintain persistence?
Input: HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MyApp
Correct answer
What is the content of this registry?
Input: C:\Users\ammar\Documents\sys.exe
Correct answer
The malware uses a secret token to communicate with the C2 server. What is the value of this key?
Input:
Input: e7bcc0ba5fb1dc9cc09460baaa2a6986
Correct answer
Sahaaaaaaaaaaa Securinets{de2eef165b401a2d89e7df0f5522ab4f}
by enigma522
```
### Stage 1: Initial Analysis and System Identification

The first step in any forensics investigation is gathering basic information about the victim system to establish context.

**Q1: What is the SHA256 hash of the disk image file?**

Use any tool (e.g., sha256sum on Linux or Get-FileHash on PowerShell) to calculate the hash.

**Answer:**`122B2B4BF1433341BA6E8FEFD707379A98E6E9CA376340379EA42EDB31A5DBA2`

**Q2: What is the operating system build number?**

Analyze the SOFTWARE registry hive. This information is located in the key: `SOFTWARE\Microsoft\Windows NT\CurrentVersion`.

![image](https://hackmd.io/_uploads/HysgyodSZx.png)

**Answer:** `19045`

Extract the SOFTWARE file FIRST. Load it into Registry Explorer.
![image](https://hackmd.io/_uploads/SytdyoOB-l.png)


**Question 3: What is the victim machine's IP address?**

Analyze the SYSTEM registry hive. Network configuration is stored at key: `SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{GUID}`.
**Answer:** `192.168.206.131`

![image](https://hackmd.io/_uploads/rJtKJsOrbl.png)


Extract the SYSTEM file first. Load it into Registry Explorer.

### Stage 2: Investigating Entry Point and Attack Vector 

After obtaining basic information, we trace how the attacker infiltrated the system. Clues typically lie in user activity.

**Question 4: Which email application does the victim use?**

Check user application folders, especially AppData. During this process, a suspicious file named sys.exe is discovered. When uploaded to VirusTotal, it's confirmed as malware.
**Answer:** `thunderbird`

**Question 5: What is the victim's email address?**

Analyze the Thunderbird profile at `Profiles/6red5uxz.default-release/ImapMail/`. The INBOX file contains all received emails, revealing the victim's address.
**Answer:** `ammar55221133@gmail.com`

![image](https://hackmd.io/_uploads/HJQTksOBbl.png)


**Question 6: What is the attacker's email address?**

Read the INBOX file contents, discovering emails from someone named "mohamed Masmoudi". One of these emails contains a link to a GitHub source code repository, disguised as an educational project.
**Answer:** `masmoudim522@gmail.com`

**Question 7: What URL did the attacker use to distribute the malware?**

Analyze the GitHub repository sent in the email. The package.json file contains a PowerShell script. This script doesn't actually clone the repo but instead downloads sys.exe from another URL.

**Answer:** `https://tmpfiles.org/dl/23860773/sys.exe`

![image](https://hackmd.io/_uploads/ryYyesOHZe.png)


Access the GitHub link
![image](https://hackmd.io/_uploads/BkJZlj_SZx.png)
![image](https://hackmd.io/_uploads/HJVWejuB-l.png)


### Stage 3: Malware Analysis

Now that we have the malware and know its origin, the next stage is analyzing it to understand its behavior.

**Question 8: What is the malware file's SHA256 hash?**

- **Method:** Calculate the hash of sys.exe file.
- **Answer:** `BE4F01B3D537B17C5BA7DC1BB7CD4078251364398565A0CA1E96982CFF820B6D`

![image](https://hackmd.io/_uploads/BJwzlsuB-g.png)


**Questions 9 & 10: What are the IP address and port of the C2 (Command & Control) server?**

 Use dynamic analysis results from VirusTotal or run in a sandbox like Any.run. Reports show the malware (written in Go) connects to a specific IP and port.
- **IP Answer:** `40.113.161.85`
- **Port Answer:** `5000`

![image](https://hackmd.io/_uploads/B1QXliuB-x.png)


**Question 11: What is the URL of the first request the malware sends to C2?**

Analyze network protocol logs from Any.run sandbox.
**Answer:** `http://40.113.161.85:5000/helppppiscofebabe23`

![image](https://hackmd.io/_uploads/B1ZEes_Bbl.png)


### Stage 4: Post-Infection Artifacts & Persistence Mechanisms 

Finally, we investigate changes the malware made to the system to ensure persistent access.

**Question 12: The malware creates an identification file. What is its content?**

VirusTotal reports show the malware creates id.txt file at `C:\Users\Public\Documents`. We return to the disk image and read this file's contents.
**Answer:** `3649ba90-266f-48e1-960c-b908e1f28aef`

![image](https://hackmd.io/_uploads/Bk8Ilj_BZl.png)


**Question 13: Which Registry key did the malware modify/add to maintain access?**

VirusTotal shows the malware creates an entry in the Registry Run key, a common technique for automatic startup with Windows.
**Answer:** `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MyApp`

![image](https://hackmd.io/_uploads/ryy_xoOSWe.png)


**Question 14: What is the content of this Registry key?**

Extract the NTUSER.DAT registry hive (corresponding to HKEY_CURRENT_USER) and read the MyApp key value.

**Answer:** `C:\Users\ammar\Documents\sys.exe`

**Question 15: The malware uses a "secret token" to communicate with C2. What is its value?**

Use simple static analysis with the strings command on sys.exe file and filter (grep) with the keyword "secret".

**Answer:** `e7bcc0ba5fb1dc9cc09460baaa2a6986`

![image](https://hackmd.io/_uploads/rkrFgidHWe.png)




## Lost File

![image](https://hackmd.io/_uploads/rJbBMouH-e.png)

### Stage 1: Static Analysis of Executable File (locker_sim.exe)

The first step is understanding how the executable operates to determine its encryption mechanism.

**Question 1: How does the executable work?**

- **Purpose:** Understand the encryption program's logic.
- **Method:** Use a decompiler tool like IDA to analyze the C source code of locker_sim.exe.
- **Source Code Analysis:**
    1. The program receives an input parameter from the command line (argv[1]).
    2. It reads the computer name (hostname) from the Registry.
    3. It reads the contents of a file named secret_part.txt, then **deletes this file**.
    4. All three pieces of information are combined into a single string in the format: `<command line parameter>|<computer name>|<secret file content>`.
    5. This string is then used to generate the encryption key.

**Question 2: How is the encryption key generated?**

- **Purpose:** Identify the algorithm and source data for key generation.
- **Method:** Based on source code analysis from IDA.
- **Result:** The program uses the **SHA256** algorithm to hash the combined string above. This hash result is the key used for AES-256 encryption. The first 16 bytes of the hash are used as the IV (Initialization Vector).

**Question 3: Which file is encrypted and what is the result?**

- **Purpose:** Identify the target and output of the encryption process.
- **Method:** Source code analysis.
- **Result:** The program encrypts the file to_encrypt.txt using **AES-256** algorithm (CBC mode) and saves the result as to_encrypt.txt.enc.

### Stage 2: Memory Dump Analysis (mem.vmem)

Since secret_part.txt has been deleted and we don't know the command line parameter that was used, we need to analyze the memory dump file to retrieve this information.

**Question 4: What command line parameter (argv[1]) was used?**

- **Purpose:** Find the first piece of the key generation string.
- **Method:** Use Volatility with the consoles plugin to review commands executed in the command line interface.

```bash
python2 volatility/vol.py -f mem.vmem --profile=WinXPSP2x86 consoles
```

- **Result:** `hmmisitreallyts`

![image](https://hackmd.io/_uploads/H1x7uGo_BZg.png)


**Question 5: What is the victim's computer name (hostname)?**

- **Purpose:** Find the second piece of the key generation string.
- **Method:** Use Volatility with the envars plugin to extract environment variables, which contain the hostname.
- **Command:**

```bash
python2 volatility/vol.py -f mem.vmem --profile=WinXPSP2x86 envars
```

- **Result:** `RAGDOLLF-F9AC5A`

![image](https://hackmd.io/_uploads/S1wFfsuSWe.png)


### Stage 3: Recovering Deleted File

The final piece is the content of the secret_part.txt file that was deleted by the program.

**Question 6: What is the content of secret_part.txt?**

- **Purpose:** Find the final piece of the key generation string.
- **Method:** Since the file was deleted, it's likely still in the system's Recycle Bin. Analyze the disk image (if available) or use file recovery tools to retrieve this content.
- **Result:** `sigmadroid`

### Stage 4: File Decryption and Flag Recovery

With all three pieces of information: command line parameter, hostname, and secret file content, we can reconstruct the key and decrypt the file.

**Question 7: How is the decryption script written?**

```python
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def derive_key(arg, computername, secret_part):
    data = f"{arg}|{computername}|{secret_part}"
    sha = hashlib.sha256(data.encode()).digest()
    return sha

def decrypt_file(enc_path, out_path, arg, computername, secret_part):
    key = derive_key(arg, computername, secret_part)
    iv = key[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    with open(enc_path, "rb") as f:
        ciphertext = f.read()
    
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    with open(out_path, "wb") as f:
        f.write(plaintext)
    
    print(f"[+] Decrypted -> {out_path}")
    print(f"Content: {plaintext.decode()}")

decrypt_file(
    "to_encrypt.txt.enc",
    "to_encrypt_decrypted.txt",
    arg="hmmisitreallyts",
    computername="RAGDOLLF-F9AC5A",
    secret_part="sigmadroid"
)
```

**Question 8: What is the final flag?**

- **Method:** Run the decryption script and process the resulting string.
- **Decrypted content:** `Vm14U1MxWXlSblJWYkd4VVltdEtjRmxzV2xwa01XdzJWR3BDYkdKSGREWlZNakUwV1ZaYU5sVnViRnBOYWtaWVdXMHhSMWRXVW5GUmJYQnBZbGhTTlZkWGVHdFpWVEZIVVdwYVVGWkhjems9`
- **Processing:** The above string is Base64 encoded. After Base64 decoding, we obtain the final flag.
- **Flag:** `Securinets{screen+registry+mft??}`

![image](https://hackmd.io/_uploads/B1ZbDs_HWl.png)


## Recovery

We had 2 files: a pcapng file and a backup. First, I looked through the backup: 

![image](https://hackmd.io/_uploads/rk3wDouSWl.png)


When I opened files, I could not read since they were encrypted although their name looked normal:

![image](https://hackmd.io/_uploads/rJ5Ows_Bbe.png)


From here I read content of powershell_history.txt for more information and I noticed a github repo:

![image](https://hackmd.io/_uploads/H1AtDjurbl.png)


It looked so suspicious so I accessed this repo. Read app.py and this was result: 

![image](https://hackmd.io/_uploads/r1T5DidBbe.png)


I checked commit to see file history and I found many things interesting, especially DNS exfiltration which used domain **meow**. To confirm this information I opened 
**Wireshark** and fortunately it's correct:

![image](https://hackmd.io/_uploads/H1ooPs_S-l.png)


When we solved, we found the dns6 commit contained the correct decryption method for this case, and I rewrote the script for decryption:

```python
import argparse
import base64
import os
from collections import defaultdict
from dnslib import DNSRecord
from scapy.all import PcapReader, UDP


def xor_bytes(data_bytes, key_byte):
    """XOR every byte with a single-byte key."""
    return bytes([b ^ key_byte for b in data_bytes])


def padded_base32(s: str) -> bytes:
    """Pad a base32 string to a multiple of 8 and decode."""
    # base32 expects padding with '=' to a multiple of 8
    pad_len = (8 - (len(s) % 8)) % 8
    s_padded = s + ("=" * pad_len)
    return base64.b32decode(s_padded, casefold=True)


def process_dns_qname(qname: str, special_domain: str = "meow"):
    """
    If query name matches the pattern chunk.index.meow... (i.e. labels[0]=chunk, labels[1]=index, labels[2]=meow),
    return (index:int, chunk_bytes:bytes). Otherwise return None.
    """
    labels = qname.rstrip(".").split(".")
    if len(labels) < 3:
        return None
    # We expect the third label to be the special domain according to user's format
    if labels[2].lower() != special_domain.lower():
        return None

    chunk_label = labels[0]
    index_label = labels[1]

    # special-case: end.<something>.meow  (original script used labels[0]=="end")
    if chunk_label.lower() == "end":
        try:
            # if index present use it, otherwise -1
            idx = int(index_label) if index_label.isdigit() else -1
        except Exception:
            idx = -1
        return ("__END__", idx)

    # otherwise try to decode
    try:
        decoded = padded_base32(chunk_label)
        if len(decoded) < 1:
            return None
        key_byte = decoded[0]
        encrypted_chunk = decoded[1:]
        original = xor_bytes(encrypted_chunk, key_byte)
        index = int(index_label)
        return (index, original)
    except Exception:
        return None

def extract_from_pcap(pcap_path: str, out_path: str, special_domain: str = "meow", verbose: bool = True):
    """
    Iterate through pcapng, parse DNS queries and collect chunks.
    When an 'end' marker is found, reconstruct file and write to out_path.
    """
    chunks = dict()
    seen_indices = set()
    end_seen = False

    if verbose:
        print(f"[+] Opening pcap file: {pcap_path}")

    total_packets = 0
    dns_packets = 0
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            total_packets += 1
            # Filter UDP DNS queries (port 53) - both src or dst 53 possible depending on capture direction
            if not pkt.haslayer(UDP):
                continue
            udp = pkt[UDP]
            sport = int(udp.sport) if hasattr(udp, "sport") else None
            dport = int(udp.dport) if hasattr(udp, "dport") else None
            if sport != 53 and dport != 53:
                continue

            # get raw UDP payload (may be DNS)
            try:
                raw = bytes(udp.payload)
                if not raw:
                    continue
                # parse DNS packet using dnslib for robustness
                try:
                    dns = DNSRecord.parse(raw)
                except Exception:
                    continue
                # only process queries (QR=0) and at least one question
                if dns.header.get_qr() != 0 or len(dns.questions) == 0:
                    continue

                qname = str(dns.q.qname)
                dns_packets += 1
                result = process_dns_qname(qname, special_domain=special_domain)
                if result is None:
                    continue
                if isinstance(result, tuple) and result[0] == "__END__":
                    end_seen = True
                    if verbose:
                        idx = result[1]
                        print(f"[+] Found END marker (index={idx}) at packet #{total_packets}, qname={qname}")
                    # do not break; keep scanning to collect all chunks (pcap might have chunks after end marker)
                    continue
                index, data = result
                if index in chunks:
                    # if duplicate, skip or optionally prefer first seen
                    if verbose:
                        print(f"[*] Duplicate chunk index {index} encountered; skipping duplicate.")
                else:
                    chunks[index] = data
                    seen_indices.add(index)
                    if verbose:
                        print(f"[+] Collected chunk index={index}, len={len(data)} qname={qname}")

            except Exception as e:
                if verbose:
                    print(f"[!] Failed to process packet #{total_packets}: {e}")
                continue

    if verbose:
        print(f"[+] Finished scanning pcap: total pkts={total_packets}, DNS-like pkts={dns_packets}")
        print(f"[+] Collected {len(chunks)} chunks, end_seen={end_seen}")

    if not chunks:
        raise RuntimeError("No valid meow chunks found in pcap.")

    # Reconstruct ordered by index (lowest to highest)
    ordered_indices = sorted(chunks.keys())
    # Check for missing indices (optional)
    min_idx = ordered_indices[0]
    max_idx = ordered_indices[-1]
    missing = [i for i in range(min_idx, max_idx + 1) if i not in chunks]
    if missing and verbose:
        print(f"[!] Warning: missing chunk indices between {min_idx} and {max_idx}: {missing}")

    reconstructed = b"".join(chunks[i] for i in ordered_indices if i in chunks)

    # Write to disk
    out_dir = os.path.dirname(out_path)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    with open(out_path, "wb") as f:
        f.write(reconstructed)

    if verbose:
        print(f"[+] Reconstructed file written to: {out_path} (size={len(reconstructed)} bytes)")
        print("[!] Note: this script does NOT execute the file. If you need to run it, do so manually in a safe, isolated environment (VM).")

    return out_path, len(reconstructed), missing


def main():
    ap = argparse.ArgumentParser(description="Extract meow DNS exfil chunks from pcapng and reconstruct file.")
    ap.add_argument("pcap", help="Path to pcapng / pcap file")
    ap.add_argument("-o", "--out", help="Output file path", required=True)
    ap.add_argument("--domain", help="Special domain label (default: meow)", default="meow")
    ap.add_argument("--noisy", help="Verbose output", action="store_true")
    args = ap.parse_args()

    try:
        out_path, size, missing = extract_from_pcap(args.pcap, args.out, special_domain=args.domain, verbose=args.noisy)
        print(f"Done. Wrote {size} bytes to {out_path}. Missing indices: {missing}")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
```

I ran the code and got a packed executable file

Simply I unpacked it and used IDA Pro again: 

![image](https://hackmd.io/_uploads/B1nAwsOSWe.png)


I searched and found the function for encrypting files:

![image](https://hackmd.io/_uploads/B1vbOiuSbl.png)


You could see that they used a simple XOR operation for encryption. But we need to know exactly how they implemented their encryption method. Next we will dig into 
**sub_401460** which processed the **Filename** for something:

```asm
int __cdecl sub_401460(const char *a1, int a2, int a3)
{
  int v3; // edx
  int v4; // ebx
  unsigned int v5; // kr04_4
  char v6; // cl
  int v7; // esi
  int i; // eax
  int v9; // ebx
  char v10; // cl
  int result; // eax

  v3 = 0;
  v4 = 0;
  v5 = strlen(a1) + 1;
  while ( v4 != v5 - 1 )
  {
    v6 = 8 * (v4 & 3);
    v7 = a1[v4++];
    v3 ^= v7 << v6;
  }
  for ( i = 0; i != 37; ++i )
  {
    v9 = byte_40B200[i];
    v10 = i;
    v3 ^= v9 << (8 * (v10 & 3));
  }
  for ( result = a2; result != a2 + a3; *(_BYTE *)(result - 1) = v3 )
  {
    ++result;
    v3 = 1664525 * v3 + 1013904223;
  }
  return result;
}
```

**sub_401460** takes a string a1, a buffer address a2, and a length a3, and uses the string to produce a deterministic stream of pseudorandom bytes written into the 
buffer. It begins by building a 32-bit seed v3 from the input string: each character is XORed into v3 at byte-aligned positions (cycling through shifts of 0, 8, 16, 24 bits), 
then the seed is further mixed by XORing in 37 bytes from **byte_40B200**. That mixed value becomes the initial state for a standard linear congruential 
generator (v3 = 1664525 * v3 + 1013904223), and the routine iterates the LCG to produce a3 bytes, storing the low byte of the LCG state sequentially into the buffer 
at a2. 

To know what 37 bytes string was, we just simple click on the variable and we can see the content:

![image](https://hackmd.io/_uploads/r1Ofus_S-g.png)


Because filename was an important part of seeding process, giving correct filepath is very essential and just a small modification will change the seed. And fortunately 
this function below gave me how the filepath looked like:

```asm
void *__cdecl sub_4015FD(char *a1)
{
  void *result; // eax
  void *v2; // edi
  int v3; // eax
  const char *Str1; // ebx
  _stat32 Stat; // [esp+2Ch] [ebp-43Ch] BYREF
  char FileName[1048]; // [esp+50h] [ebp-418h] BYREF

  result = (void *)sub_403A60(a1);
  if ( result )
  {
    v2 = result;
    while ( 1 )
    {
      v3 = sub_403C20(v2);
      if ( !v3 )
        break;
      Str1 = (const char *)(v3 + 12);
      if ( strcmp((const char *)(v3 + 12), ".") )
      {
        if ( strcmp(Str1, "..") )
        {
          if ( strcmp(Str1, "AppData") )
          {
            sub_4023B0(FileName, 1024, "%s\\%s", a1, Str1);
            if ( stat(FileName, &Stat) != -1 )
            {
              if ( (Stat.st_mode & 0xF000) == 0x4000 )
              {
                sub_4015FD(FileName);
              }
              else if ( (Stat.st_mode & 0xF000) == 0x8000 )
              {
                sub_4014D1(FileName);
              }
            }
          }
        }
      }
    }
    return (void *)sub_403C70(v2);
  }
  return result;
}
```

In short, the filepath will use double backslash, filepath will be put into the seeding. So this is my Python script for decryption:

```python
import sys
import os

SECRET = b"evilsecretcodeforevilsecretencryption"
A = 1664525
C = 1013904223
MASK32 = 0xFFFFFFFF
BLOCK_SIZE = 64 * 1024  # 64 KiB

def build_seed_from_filename(filename: str) -> int:
    """
    Recreate seed from the original malware logic:
      full = "C:\\Users\\gumba\\Desktop\\" + filename
      seed = 0
      for each byte in full: seed ^= (byte << ((i % 4) * 8))
      for each byte in SECRET: seed ^= (byte << ((i % 4) * 8))
    """
    full = "C:\\Users\\gumba\\Desktop\\" + filename
    fb = full.encode("utf-8", errors="replace")
    seed = 0
    for i, b in enumerate(fb):
        seed ^= (b & 0xFF) << ((i & 3) * 8)
        seed &= MASK32
    for i, b in enumerate(SECRET):
        seed ^= (b & 0xFF) << ((i & 3) * 8)
        seed &= MASK32
    return seed & MASK32

def keystream_generator_for_filename(filename: str):
    """
    Generate keystream bytes for the given filename. Update LCG state first, then output (state & 0xFF).
    """
    state = build_seed_from_filename(filename)
    while True:
        state = (state * A + C) & MASK32
        yield state & 0xFF

def decrypt_file(filename: str):
    if not os.path.isfile(filename):
        print(f"[!] File not found: {filename}")
        return 1
    size = os.path.getsize(filename)
    if size == 0:
        print(f"[!] Empty file, skipping: {filename}")
        return 1
    
    keystream = keystream_generator_for_filename(filename)
    outname = f"decrypted_{filename}"
    key_preview = bytearray()

    with open(filename, "rb") as inf, open(outname, "wb") as outf:
        while True:
            block = inf.read(BLOCK_SIZE)
            if not block:
                break
            out_block = bytearray(len(block))
            for i, b in enumerate(block):
                k = next(keystream)
                out_block[i] = b ^ k
                if len(key_preview) < 64:
                    key_preview.append(k)
            outf.write(out_block)

    print(f"[+] Decrypted {filename} -> {outname} (size={size} bytes)")
    print(f"[+] Keystream preview (first {len(key_preview)} bytes): {key_preview.hex()}")
    return 0

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <filename>")
        sys.exit(1)
    filename = sys.argv[1]
    decrypt_file(filename)

if __name__ == "__main__":
    main()
```

Run with the filename and you got the flag:

![image](https://hackmd.io/_uploads/SJD7djuB-l.png)


That's my writeup for all forensic challenges. Thank you for reading my blog, see you in the next post. Byeeee!!!