---
title: "Platform Attack/Defense"
description: "Hướng dẫn triển khai CTF Cup & Cheatsheet Attack-Defense"
summary: "Hướng dẫn triển khai CTF Cup & Cheatsheet Attack-Defense"
categories: ["Notebook"]
tags: ["Technical"]
#externalUrl: ""
date: 2025-10-16
draft: false
authors:
  - ducnocrypt
cover: "images/post_covers/Platform_CTFCup_AD.png"
---

## Giới thiệu

Tài liệu này hướng dẫn các bước để triển khai bộ mã nguồn của cuộc thi **CTF Cup Attack-Defense** trên một máy chủ ảo (VM) duy nhất. Mục tiêu là tạo ra một môi trường lab cá nhân để **phân tích, thực hành, và trình diễn** các bài thi (services).

Hệ thống nguyên bản được thiết kế để chạy trên nền tảng ForcAD, nhưng hướng dẫn này cấu hình để hoạt động **độc lập** trên một máy chủ đơn cho mục đích demo.



## 1. Yêu cầu Môi trường

**Hệ điều hành (gợi ý):** Ubuntu 22.04 LTS (hoặc Debian tương đương)

**Phần mềm cần thiết:**
- `git`
- `docker.io`
- `docker-compose`
- `python3`
- `python3-pip`

**Cấu hình phần cứng tối thiểu (khuyến nghị cho demo):**
- CPU: 4 cores
- RAM: 8 GB
- Disk: 40 GB dung lượng trống

> **Gợi ý:** Với nhiều service và khi build image lần đầu, bạn càng có nhiều RAM và disk càng tốt (16 GB RAM, 80 GB disk nếu có thể).



## 2. Cài đặt & Cấu hình Chi tiết

Thực hiện tuần tự các bước sau trên VM (giả sử bạn đang dùng Ubuntu 22.04):

### Bước 1: Tải Mã nguồn

```bash
git clone https://github.com/C4T-BuT-S4D/ctfcup-2023-ad.git
cd ctfcup-2023-ad/
```

> Nếu repo private, hãy chuẩn bị SSH key hoặc token và clone với HTTPS có credential.

### Bước 2: Cấu hình Môi trường Demo

Vì chỉ chạy trên một VM, cần chỉnh file cấu hình chính để game engine kiểm tra các service chạy cục bộ.

Mở file `forcad_config.yml`:

```bash
nano forcad_config.yml
```

Tìm phần `teams` ở cuối file. Xóa mọi đội khác, chỉ giữ một đội duy nhất với IP `127.0.0.1`.

Nội dung mẫu:

```yaml
teams:
  - ip: 127.0.0.1
    name: DemoTeam
    highlighted: true
```

Lưu và thoát (Ctrl+X → Y → Enter).

**Lý do:** Trong môi trường demo một máy, engine cần biết nơi để kiểm tra service — dùng localhost để hướng mọi bài thi về chính VM đó.

### Bước 3: Sửa lỗi Cấu hình Docker (rox -> ro)

Mã nguồn gốc có lỗi nhỏ trong hai file `docker-compose.yml` (dòng mount có hậu tố `rox` thay vì `ro`). Sửa lại để Docker có thể mount script khởi tạo DB.

- Sửa file của `oilmarket`:

```bash
nano services/oilmarket/docker-compose.yml
```
Tìm dòng:
```
- ./postgres/init-db.sh:/docker-entrypoint-initdb.d/init-db.sh:rox
```
Sửa `rox` thành `ro`.

- Sửa file của `neftetochka`:

```bash
nano services/neftetochka/docker-compose.yml
```
Tương tự, thay `rox` -> `ro`.

> **Lưu ý:** Luôn kiểm tra cú pháp YAML (khoảng trắng, thụt lề) sau khi sửa.

### Bước 4: Cài đặt Dependencies (Thư viện Python)

Cài thư viện cho script chính và checker:

```bash
sudo pip3 install -r requirements.txt
sudo pip3 install -r checkers/requirements.txt --break-system-packages
```

> `--break-system-packages` được dùng trên một số bản Ubuntu/Debian để cho phép pip can thiệp vào environment hệ thống. Nếu bạn sử dụng virtualenv, **khuyến nghị** tạo virtualenv thay vì dùng `sudo pip3`.

**Alternative (khuyến nghị an toàn hơn):** dùng `python3 -m venv venv` → `source venv/bin/activate` → `pip install -r requirements.txt` và tương tự cho checkers (hoặc pip vào cùng venv nếu phù hợp).

### Bước 5: Mở Cổng Firewall

Mở các cổng cần thiết để truy cập service từ bên ngoài (hoặc từ host nếu VM NAT):

```bash
sudo ufw allow ssh
sudo ufw allow 2112/tcp comment 'Service: oilmarket'
sudo ufw allow 9090/tcp comment 'Service: bluwal'
sudo ufw allow 8087/tcp comment 'Service: neftetochka'
sudo ufw allow 8000/tcp comment 'Service: explorers'
sudo ufw enable
```

> Nếu VM chạy trên cloud (AWS/GCP/OVH...), đừng quên mở Security Group / Firewall của nhà cung cấp tương ứng.



##  3. Vận hành Platform

Sau khi cài đặt & cấu hình xong, dùng `check.py` để quản lý toàn bộ platform.

### Khởi động tất cả Services

```bash
sudo python3 check.py up
```

Lần chạy đầu tiên có thể mất vài phút do build image và pull base images.

### Kiểm tra trạng thái

Dùng `docker ps` để kiểm tra container đang chạy. Kỳ vọng: **khoảng 9 container** (tùy phiên bản và dịch vụ có thể khác).

```bash
sudo docker ps
```
![Ảnh chụp màn hình 2025-10-16 214942](https://hackmd.io/_uploads/ByxjUFR6el.png)
![Ảnh chụp màn hình 2025-10-16 215059](https://hackmd.io/_uploads/HycRLtC6eg.png)

### Dừng tất cả Services

```bash
sudo python3 check.py down
```

Lệnh `down` sẽ dừng và xóa container, network, volume liên quan — thuận tiện để dọn dẹp môi trường demo.

![Ảnh chụp màn hình 2025-10-16 214951](https://hackmd.io/_uploads/BJcsLYCpgl.png)


## 4. Tương tác & Tấn công (Thực hành)

Khi service đang chạy, bạn có thể bắt đầu tương tác hoặc thử các khai thác (exploit) trong thư mục `sploits/`.

### Truy cập Giao diện Web (Blue Team)

Mở trình duyệt tới `http://<IP_VM>:<PORT>` tương ứng:

- Oilmarket: `http://<IP_VM>:2112`
- Bluwal: `http://<IP_VM>:9090`
- Neftetochka: `http://<IP_VM>:8087`
- Explorers: `http://<IP_VM>:8000`

**Bluwal:** trước khi đăng nhập cần tạo `user_id` qua API:

```bash
curl -X POST http://<IP_VM>:9090/api/users -H "Content-Type: application/json" -d '{"username": "testplayer"}'
```

Lệnh trả về JSON chứa `user_id` — copy và dùng để đăng nhập.

### Chạy Exploit (Red Team)

Mở terminal mới, chuyển vào từng thư mục `sploits/` và chạy script tương ứng.

**Bluwal (Port 9090):**

```bash
cd sploits/bluwal/
# Lấy <contest_id> từ giao diện web
python3 genji_array_comparison.py <IP_VM> <contest_id>
```

**Explorers (Port 8000):**

```bash
cd sploits/explorers/
python3 xxe.py <IP_VM> 8000
```

**Neftetochka (Port 8087):**

```bash
cd sploits/neftetochka/
python3 spl.py <IP_VM> 8087
```

**Oilmarket (Port 2112):**

```bash
cd sploits/oilmarket/
python3 sploit.py <IP_VM>
```

> Thực hành exploit chỉ nên làm trong môi trường lab/được phép.



## 6. Kiểm tra & Xác thực hoạt động

1. Sau khi `check.py up` hoàn tất, kiểm tra `docker ps` — các container chính (web services, postgres, redis, etc.) phải ở trạng thái `Up`.
2. Truy cập từng giao diện web bằng trình duyệt để xác thực trang load đúng.
3. Kiểm tra log từng container nếu có lỗi:

```bash
sudo docker logs <container_name_or_id>
```

4. Kiểm tra kết nối tới DB nếu service chưa khởi động:

```bash
# ví dụ kiểm tra postgres
sudo docker exec -it <postgres_container> pg_isready
```



## 7. Ghi chú bảo mật và an toàn

- Không triển khai môi trường này trên máy chủ sản xuất hoặc với cổng mở public mà không có kiểm soát; các service chứa intentional vulnerabilities.
- Chỉ mở cổng cần thiết; nếu có thể, hạn chế truy cập bằng firewall rules cho IP cụ thể hoặc VPN.
- Đặt snapshot/backup trước khi chạy exploit.  
- Giới hạn quyền `sudo` và sử dụng user non-root khi vận hành script nếu có thể.



## 8. Troubleshooting — Các sự cố thường gặp

**1) Docker không khởi động do mount sai (`rox`)**
- Triệu chứng: container fail khi `docker-compose` chạy; log báo lỗi mount.
- Giải pháp: sửa `rox` -> `ro` như mô tả ở Bước 3.

**2) Thiếu dependencies / pip lỗi**
- Triệu chứng: `pip` báo lỗi hoặc cài không thành công.
- Giải pháp: sử dụng `venv` thay vì `sudo pip`, hoặc thêm `--break-system-packages` nếu thật cần và hiểu rủi ro.

**3) Một service không trả lời trên cổng**
- Kiểm tra `docker ps` để xác định container có chạy hay không.
- Kiểm tra logs: `sudo docker logs <container>`.
- Kiểm tra firewall/host firewall/cloud security group.

**4) Lỗi cấu hình YAML**
- Dùng `yamllint` hoặc kiểm tra thụt lề, tránh tab/space mix.

**5) Lỗi permission khi chạy `check.py`**
- Hãy chạy với `sudo` nếu script cần quyền cao, hoặc chỉnh quyền file (chỉ khi bạn hiểu tác động bảo mật).



## 9. Checklist triển khai nhanh (Quick-run)

1. [ ] Chuẩn bị VM (Ubuntu 22.04), update & upgrade
2. [ ] Cài Docker & docker-compose, python3, pip
3. [ ] Clone repo
4. [ ] Sửa `forcad_config.yml` -> teams: localhost
5. [ ] Sửa `rox` -> `ro` trong 2 docker-compose
6. [ ] Cài dependencies (pip install)
7. [ ] Mở cổng ufw
8. [ ] `sudo python3 check.py up` — chờ build
9. [ ] `sudo docker ps` — xác thực
10. [ ] Truy cập web & chạy sploits nếu cần



## 10. Phụ lục

### Command cheat-sheet

```bash
# Clone
git clone https://github.com/C4T-BuT-S4D/ctfcup-2023-ad.git
cd ctfcup-2023-ad/

# Edit config
nano forcad_config.yml

# Fix docker-compose mounts
nano services/oilmarket/docker-compose.yml
nano services/neftetochka/docker-compose.yml

# Install deps
sudo pip3 install -r requirements.txt
sudo pip3 install -r checkers/requirements.txt --break-system-packages

# Firewall
sudo ufw allow ssh
sudo ufw allow 2112/tcp
sudo ufw allow 9090/tcp
sudo ufw allow 8087/tcp
sudo ufw allow 8000/tcp
sudo ufw enable

# Run platform
sudo python3 check.py up
sudo docker ps
sudo python3 check.py down

# Create Bluwal user (example)
curl -X POST http://<IP_VM>:9090/api/users -H "Content-Type: application/json" -d '{"username": "testplayer"}'
```
### Gợi ý mở rộng (nếu muốn triển khai gần thực tế hơn)
- Chạy multiple VM hoặc containerized teams để mô phỏng nhiều đội cùng lúc.
- Kết hợp với ForcAD/CaCTF nếu có sẵn để sử dụng engine gốc.
- Tự động hoá việc tạo snapshots trước khi chạy exploit bằng script (LVM/ZFS/snapshot API của cloud provider).

### Tài liệu tham khảo
- Repository: `https://github.com/C4T-BuT-S4D/ctfcup-2023-ad`




## 11. Cheatsheet

### Công cụ Attack

**S4DFarm** (Khuyên dùng cho đội): https://github.com/C4T-BuT-S4D/S4DFarm

![image](https://hackmd.io/_uploads/HyGC51ccA.png)

**DestructiveFarm** (Khuyên dùng cho cá nhân): https://github.com/DestructiveVoice/DestructiveFarm

![image](https://hackmd.io/_uploads/Hk7zckc5A.png)

#### Hướng Dẫn Cài Đặt

**Cài đặt S4DFram:**

![image](https://hackmd.io/_uploads/B1n3fb590.png)

Cấu Hình File config.py

```python
import os

CONFIG = {
    'DEBUG': os.getenv('DEBUG') == '1',

    'TEAMS': {
        f'Team #{i}': f'10.60.{i}.3'
        for i in range(0, 10)
    },
    
    'FLAG_FORMAT': r'[A-Z0-9]{31}=',

    'SYSTEM_PROTOCOL': 'forcad_tcp',
    'SYSTEM_HOST': '10.10.10.10',
    'SYSTEM_PORT': '31337',
    'TEAM_TOKEN': '4fdcd6e54faa8991',

    'SUBMIT_FLAG_LIMIT': 100,
    'SUBMIT_PERIOD': 2,
    'FLAG_LIFETIME': 5 * 60,

    'SERVER_PASSWORD': os.getenv('SERVER_PASSWORD') or '1234',

    'TIMEZONE': 'Europe/Moscow',
}
```


**Cấu hình đội (Team config):**

Cấu hình IP của đội đối thủ. Ví dụ: 10.60.0.3 (Đội 1), 10.60.1.3 (Đội 2).

```python
'TEAMS': {
    f'Team #{i}': f'10.60.{i}.3'
    for i in range(0, 10)
}
```

**Cấu hình Flag:**

Định dạng này phụ thuộc vào quy tắc của cuộc thi bạn tham gia.

Ví dụ:
- `'FLAG_FORMAT': r'[A-Z0-9]{31}='`
- `'FLAG_FORMAT': r'BKISC{[\w-]*\.[\w-]*\.[\w-]*}'`

**Cấu hình hệ thống:**

Phụ thuộc vào cuộc thi bạn tham gia như FAUST CTF, RuCTF.

Ví dụ cấu hình RuCTF:

```python
'SYSTEM_PROTOCOL': 'ructf_http',
'SYSTEM_URL': 'http://monitor.ructfe.org/flags',
'SYSTEM_TOKEN': 'your_secret_token',
```

**Các tham số khác:**
- `FLAG_LIFETIME`: Phụ thuộc vào cuộc thi
- `SERVER_PASSWORD`: Bạn cần thay đổi giá trị này

**Lưu ý:** Nếu bạn không thể cấu hình farm, có một số template hữu ích trong `/dashboard/resources` để submit flag hoặc tự động hóa tấn công.

#### Submit Flag

**Lệnh thực thi:**

```bash
python3 start_sploit.py --server-url http://FARM-IP/ --server-pass YOUR_PASS exploit.py
```

**Script exploit mẫu (sample_exploit.py):**

```python
#!/usr/bin/env python3

import random
import string
import sys

print("Hello! I am a little sploit. I could be written on any language, but "
      "my author loves Python. Look at my source - it is really simple. "
      "I should steal flags and print them on stdout or stderr. ")

host = sys.argv[1]
print("I need to attack a team with host: {}".format(host))

print("Here are some random flags for you:")

for _ in range(3):
    flag = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(31)) + '='
    print(flag, flush=True)
```

**Lưu ý quan trọng:** Hai điều cần có trong script exploit của bạn là `#!/usr/bin/env python3` và `print(flag, flush=True)`.

### Công Cụ Defense

**Lưu ý:** Công cụ phòng thủ phải được cài đặt trong vulnbox của bạn!

### Proxy

![image](https://hackmd.io/_uploads/rk4DM799A.png)

#### Hướng Dẫn Sử Dụng

**Cấu hình file YAML:**

```yaml
# Thay đổi rules tại đây
rules:
    ####### TCP RULES ########
    - name: flag_in_tcp
      type: tcp::ingress::regex
      args:
          - "[A-Z0-9]{31}="
    - name: flag_out_tcp
      type: tcp::egress::regex
      args:
          - "[A-Z0-9]{31}="
    
    ######## HTTP RULES #########
    - name: flag_in_http
      type: http::ingress::body::regex
      args:
          - "[A-Z0-9]{31}="
    - name: flag_out_http
      type: http::egress::body::regex
      args:
          - "[A-Z0-9]{31}="

# Thay đổi services tại đây
services:
    - name: TCP example
      type: tcp
      listen: 0.0.0.0:1338
      target: 127.0.0.1:1337
      filters:
        - rule: flag_in_tcp
          verdict: "alert:: flag in tcp"
        - rule: flag_out_tcp
          verdict: "alert:: flag out tcp"

    - name: HTTP example
      type: http
      listen: 0.0.0.0:5001
      target: 127.0.0.1:5000
      request_timeout: 10s
      filters:
        - rule: flag_in_http
          verdict: "alert:: flag in http"
        - rule: flag_out_http
          verdict: "alert:: flag out http"

# Thay đổi theo nhu cầu
web:
    username: admin
    password: admin
```

**Khởi chạy:**
- Chạy lệnh `./proxy` và truy cập http://127.0.0.1:8000

**Lưu ý:** Bạn có thể thêm rule trên giao diện frontend.

**Chi tiết của công cụ này sẽ được cập nhật sau.**

### Các Công Cụ Khác

**ctf_proxy (beta):** Một hệ thống ngăn chặn xâm nhập (Intrusion Prevention System)

Chi tiết: https://github.com/ByteLeMani/ctf_proxy

*Hướng dẫn sử dụng sẽ được cập nhật sau.*

### Iptables

Nếu bạn chưa biết Iptables là gì, hãy xem [slide này](https://docs.google.com/presentation/d/1JEaOmak3C0HvF9fNzwa_oPXHPaylreRCH-fe0OBNGbM/edit?usp=sharing).

**Các lệnh cơ bản:**

```bash
iptables-save > /tmp/dump.txt 
iptables -F
iptables-restore < /tmp/dump.txt
iptables -nvL -t filter
iptables -A FORWARD -p tcp --dport 80 -j ACCEPT
iptables -I FORWARD 1 -t filter -p tcp \
-d [vulnbox_ip] --dport [service_port] \
-m string --string "[payload]" --algo bm \
[-m string --hex-string "| [hex] |" --algo kmp \]
-j DROP
```

#### Giải Thích Các Lệnh

- `iptables-save > /tmp/dump.txt` - Lưu cấu hình iptables hiện tại vào file dump.txt
- `iptables -F` - Xóa tất cả các rules, đây là thao tác reset
- `iptables-restore < /tmp/dump.txt` - Khôi phục cấu hình iptables
- `iptables -nvL -t filter` - Liệt kê các rules hiện tại trong bảng filter (Có thể dùng để debug)
- `iptables -A FORWARD -p tcp --dport 80 -j ACCEPT` - Cho phép traffic TCP trên cổng 80

**Rule chặn packet:**

```bash
iptables -I FORWARD 1 -t filter -p tcp \
-d [vulnbox_ip] --dport [service_port] \
-m string --string "[payload]" --algo bm \
[-m string --hex-string "| [hex] |" --algo kmp \]
-j DROP
```

Rule này chèn vào chuỗi FORWARD, và bạn có thể sửa đổi theo nhu cầu. Bộ lọc hex string là tùy chọn. Hành động `-j DROP` sẽ loại bỏ bất kỳ packet nào khớp với rule, chặn nó một cách hiệu quả.

**Ví dụ:**
- `-m string --string "malicious string" --algo bm`
- `[-m string --hex-string "| 6576696C5F7061796C6F6164 |" --algo kmp \]` (evil_payload)

**Các lựa chọn iptables thay thế:**

```bash
iptables -I INPUT 1 -p tcp --dport 80 -m string --hex-string '| hex will be block here |' --algo bm -j DROP
iptables -I FORWARD 1 -p tcp --dport 80 -m string --hex-string '| hex will be block here |' --algo bm -j DROP
iptables -A OUTPUT -p tcp -m string --string "PAYLOAD" --algo bm -j DROP
```

**Cảnh báo quan trọng:** 

Trong trường hợp bạn viết rule không đúng, chẳng hạn như sử dụng `-string "*"`, hãy lưu ý rằng ký tự `*` có thể khớp với bất kỳ packet nào, bao gồm cả các giao thức quan trọng như SSH. Điều này có thể dẫn đến việc kết nối SSH bị ngắt. Do đó, hãy cẩn thận khi viết rules iptables. Nếu bạn viết rule không đúng, hãy xóa nó ngay lập tức và khôi phục cấu hình trước đó.

### Công Cụ Ghi Log

#### Tulip

Link: https://github.com/OpenAttackDefenseTools/tulip

![image](https://hackmd.io/_uploads/SJGMz4qqA.png)

##### Cài Đặt Tulip

**Bước 1:** Chỉnh sửa file `/services/api/configurations.py`

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from pathlib import Path

traffic_dir = Path(os.getenv("TULIP_TRAFFIC_DIR", "/traffic"))
tick_length = os.getenv("TICK_LENGTH", 2*60*1000)
start_date = os.getenv("TICK_START", "2018-06-27T13:00+02:00")
mongo_host = os.getenv("TULIP_MONGO", "localhost:27017")
flag_regex = os.getenv("FLAG_REGEX", "[A-Z0-9]{31}=")
mongo_server = f'mongodb://{mongo_host}/'
vm_ip = os.getenv("VM_IP", "10.10.3.1")

services = [
    {"ip": vm_ip, "port": 9876, "name": "cc_market"},
    {"ip": vm_ip, "port": 80, "name": "maze"},
    {"ip": vm_ip, "port": 8080, "name": "scadent"},
    {"ip": vm_ip, "port": 5000, "name": "starchaser"},
    {"ip": vm_ip, "port": 1883, "name": "scadnet_bin"},
    {"ip": vm_ip, "port": -1, "name": "other"}
]
```

**Bước 2:** Chạy lệnh `cp .env.example .env`

Lệnh này sẽ copy file .env và sau đó chỉnh sửa theo ý muốn. Nếu bạn không biết cách cấu hình, chỉ cần tập trung vào `FLAG_REGEX="[A-Z0-9]{31}="` và `TRAFFIC_DIR_HOST="./services/test_pcap"`

**Bước 3:** Chạy lệnh `docker-compose up -d --build`

**Lưu ý:** Bạn cần sử dụng tcpdump để capture traffic và lưu file `.pcap` vào thư mục `test_pcap` để Tulip có thể nhận và phân tích.

#### pcap-broker

Một công cụ để capture network traffic và cung cấp cho một hoặc nhiều client thông qua [PCAP-over-IP](https://www.netresec.com/?page=Blog&month=2022-08&post=What-is-PCAP-over-IP).

##### Hướng Dẫn Sử Dụng

**Build pcap-broker:**

```bash
go build ./cmd/pcap-broker
./pcap-broker --help
```

**Hoặc build với Docker:**

```bash
docker build -t pcap-broker .
docker run -it pcap-broker --help
```

**Sử dụng:**

```bash
./pcap-broker --help
Usage of ./pcap-broker:
  -cmd string
        command to execute for pcap data (eg: tcpdump -i eth0 -n --immediate-mode -s 65535 -U -w -)
  -debug
        enable debug logging
  -json
        enable json logging
  -listen string
        listen address for pcap-over-ip (eg: localhost:4242)
  -n    disable reverse lookup of connecting PCAP-over-IP client IP address
```

**Truyền tham số qua command line:**

```bash
./pcap-broker -cmd "sudo tcpdump -i eth0 -n --immediate-mode -s 65535 -U -w -"
```

**Hoặc qua biến môi trường:**

```bash
LISTEN_ADDRESS=:4242 PCAP_COMMAND='sudo tcpdump -i eth0 -n --immediate-mode -s 65535 -U -w -' ./pcap-broker
```

**Lưu ý:** Sử dụng biến môi trường rất hữu ích khi bạn chạy `pcap-broker` trong môi trường Docker.

**Kết nối và stream dữ liệu:**

Sử dụng `nc` và `tcpdump`:

```bash
nc -v localhost 4242 | tcpdump -nr -
```

Hoặc sử dụng công cụ hỗ trợ PCAP-over-IP, ví dụ `tshark`:

```bash
tshark -i TCP@localhost:4242
```

Chi tiết thêm: https://github.com/fox-it/pcap-broker

#### TCPDump

Sử dụng để dump traffic trên mạng.

**Lệnh:**

```bash
tcpdump -i any -w -not port 22 -w /tmp/capture-%Y-%m-%d-%H-%M-%S.pcap
```

### Các Lệnh Hữu Ích

```bash
# Copy tài nguyên từ máy local sang vulnbox
scp -i ~/.ssh/yourkey -r ./proxy masamune@IP:/tmp/source

# Thay đổi mật khẩu
passwd

# Tạo cặp khóa SSH public và private
ssh-keygen -t ed25519
```