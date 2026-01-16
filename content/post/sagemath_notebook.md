---
title: "Sagemath Notebook"
description: "Hướng dẫn cài đặt & sử dụng SageMath"
summary: "Hướng dẫn cài đặt & sử dụng SageMath"
categories: ["Notebook"]
tags: ["Crypto", "Technical"]
#externalUrl: ""
date: 2025-08-01
draft: false
authors:
  - ducnocrypt
cover: "images/post_covers/sagemath_notebook.png"
---


#  Cài Đặt & Sử Dụng SageMath
## Trên Linux
Trước tiên bạn có thể tạo 1 thư mục `sagemath` trên `Desktop` hoặc bất kỳ đâu tùy bạn thích.
###  Bước 1: Cài đặt Miniforge (trình quản lý môi trường `conda`)

#### Tải Miniforge cho hệ thống 64-bit

```
curl -L -O "https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-$(uname)-$(uname -m).sh"
bash Miniforge3-$(uname)-$(uname -m).sh
```
Với uname và uname -m trên máy Linux của bạn. Ví dụ như của mình:
![Ảnh chụp màn hình 2025-07-31 224027](https://hackmd.io/_uploads/HJDcLoFDel.png)

Thì ta sẽ có lệnh như sau:

```bash
curl -L -O https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-Linux-x86_64.sh
```

#### Chạy trình cài đặt
Sau khi tải Miniforge3 thành công, ta sẽ được 1 file .sh. Tiếp tục chạy trình cài đặt:
```bash
bash Miniforge3-Linux-x86_64.sh
```
![Ảnh chụp màn hình 2025-07-31 224039](https://hackmd.io/_uploads/BktCPjtPle.png)

 Khi được hỏi `Do you accept the license...`, chọn `yes`.
![Ảnh chụp màn hình 2025-07-31 224121](https://hackmd.io/_uploads/ByYHIiKPge.png)

 Sau khi cài xong, **đóng terminal và mở lại**, hoặc chạy thủ công:

```bash
source ~/.zshrc    # nếu dùng Zsh
source ~/.bashrc   # nếu dùng Bash
```
Kết quả thành công, khi bạn gõ conda sẽ hiển thị như trong ảnh
![Ảnh chụp màn hình 2025-07-31 224221](https://hackmd.io/_uploads/BymGDiYvgl.png)


### Bước 2: Tạo môi trường riêng cho SageMath

```bash
conda create -n sage sage python=3.11
```

![Ảnh chụp màn hình 2025-07-31 224234](https://hackmd.io/_uploads/rJY_vjYDeg.png)

Trong quá trình tạo, các bạn cứ tiếp tục chọn yes nhé

![Ảnh chụp màn hình 2025-07-31 224303](https://hackmd.io/_uploads/SJBpusKwee.png)

Sau khi tạo xong, tiến hành activate sage
```bash
conda activate sage
```
![Ảnh chụp màn hình 2025-08-01 093942](https://hackmd.io/_uploads/HynmFotvlx.png)

Tới đây thì môi trường ảo `Conda` đã được kích hoạt

> ? Vậy "sage" trong dòng đó có nghĩa là gì?
> Trong môi trường này, bạn đã cài sage. Nên từ đây bạn có thể chạy lệnh sage để khởi động chương trình SageMath.

### Bước 3: Chạy SageMath

#### Dùng dòng lệnh:

```bash
sage
```

#### Hoặc mở giao diện Jupyter Notebook:

```bash
sage -n
```

 Một đường link local sẽ hiện ra trong cmd, ví dụ:
![Ảnh chụp màn hình 2025-07-31 224428](https://hackmd.io/_uploads/SyJg9stPxg.png)

```
http://localhost:8888/tree?token=...
```

→ Mở link này trong trình duyệt để sử dụng SageMath qua Jupyter.
![Ảnh chụp màn hình 2025-08-01 095145](https://hackmd.io/_uploads/ryCensFPxg.png)


### Gợi ý (tuỳ chọn)

Nếu muốn **tự động kích hoạt** môi trường Sage mỗi khi mở terminal, thêm dòng sau vào cuối `~/.zshrc` hoặc `~/.bashrc`:

```bash
conda activate sage
```

## Trên Windows

Trên windows đơn giản ta sẽ thêm 1 bước trước khi cài `conda` thôi  
### Bước 1: Mở PowerShell với quyền Administrator

1. Nhấn **Windows**
2. Gõ `powershell` hoặc `cmd`
3. Chuột phải → chọn **"Run as Administrator"**


### Bước 2: Cài đặt WSL (nếu chưa có)

```powershell
wsl --install
```

Quá trình này sẽ tự động cài đặt WSL và Ubuntu mặc định.  
Nếu được yêu cầu, **hãy khởi động lại máy tính** để hoàn tất cài đặt.




### Bước 3: Kiểm tra WSL đã cài chưa

```powershell
wsl --version
```

Nếu thấy phiên bản như `WSL version: 2.0.x`, bạn đã cài thành công.


### Bước 4: Xem danh sách bản phân phối Linux có thể cài

```powershell
wsl --list --online
```

Danh sách sẽ hiển thị các distro như: Ubuntu-20.04, Ubuntu-22.04, Ubuntu-24.04...
![Ảnh chụp màn hình 2025-08-01 101822](https://hackmd.io/_uploads/rkcHznFwlx.png)


### Bước 5: Cài Ubuntu 24.04

```powershell
wsl --install -d Ubuntu-24.04
```

Quá trình này sẽ tải và cài Ubuntu 24.04 trên nền WSL.

**Ở đây có 1 lưu ý đó là khi gặp lỗi:**


> The operation could not be started because a required feature is not installed.  
> Error code: Wsl/InstallDistro/Service/RegisterDistro/CreateVm/HCS/HCS_E_SERVICE_NOT_AVAILABLE


Thì nguyên nhân là do hệ thống của bạn đang **thiếu một số thành phần cần thiết để chạy WSL2** (đặc biệt là Hyper-V hoặc Virtual Machine Platform) hoặc các dịch vụ liên quan chưa hoạt động.

**Cách khắc phục** 

Đảm bảo các tính năng WSL liên quan đã bật:
Mở PowerShell với quyền Administrator, lần lượt chạy lệnh:

```
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
```

Sau đó khởi động lại máy và cài đặt lại 
`wsl --install -d <version your choice>`

Sau khi cài xong, Ubuntu sẽ tự mở. Bạn cần nhập:

- **Username** (ví dụ: `minhduc`)
- **Password** (nhập 2 lần để xác nhận)

Ở đây các bạn có thể sẽ xuất hiện thêm 1 lỗi về Network nữa (đã xảy ra với mình) đó là 


> - Kết nối Internet chậm hoặc không ổn định
> - Windows đang tải từ server chậm hoặc bị gián đoạn
> - Tường lửa hoặc phần mềm diệt virus chặn
> - DNS trục trặc khiến việc phân giải domain tải về bị chậm hoặc không thực hiện được.

Thì các bạn thử Chuyển DNS sang Google:
1. Vào Control Panel > Network and Internet > Network and Sharing Center
2. Click Change adapter settings
3. Chuột phải vào kết nối đang dùng → Properties
4. Chọn Internet Protocol Version 4 (TCP/IPv4) → Properties
5. Chọn Use the following DNS server addresses và nhập:
```
Preferred: 8.8.8.8
Alternate: 8.8.4.4
```
![Ảnh chụp màn hình 2025-08-01 103532](https://hackmd.io/_uploads/HkjVLhFwex.png)

Sau đó nhấn OK và tải lại 

### Bước 6: Mở lại Ubuntu sau này

#### Cách 1: từ CMD/Powershell:

```powershell
wsl -d Ubuntu-24.04
```


#### Cách 2: từ menu Start:

Nhấn **Windows** → gõ `Ubuntu 24.04` → Enter



### Một số lệnh quản lý WSL hữu ích

| Lệnh | Mục đích |
|------|----------|
| `wsl --list --verbose` | Xem các distro đã cài & trạng thái |
| `wsl --set-default Ubuntu-24.04` | Đặt Ubuntu 24.04 làm mặc định |
| `wsl --shutdown` | Tắt toàn bộ WSL, giải phóng RAM |



### Gợi ý sau khi vào Ubuntu lần đầu

Chạy lệnh cập nhật và cài đặt công cụ cơ bản:

```bash
sudo apt update && sudo apt upgrade
sudo apt install git curl python3 python3-pip
```

Sau khi có môi trường Linux trên Windows thì các bạn tiến hành cài đặt như [các bước ở trên Linux](https://hackmd.io/@m1nhd4cc/HJRxEjFPgx#Tr%C3%AAn-Linux) 




# Kiểm Tra SageMath

Sau khi cài đặt và chạy thành công, mình sẽ kiểm tra SageMath bằng 2 challenge CTF
Ở đây mình sẽ mượn tạm 2 challenge Crypto của giải [HCMUS-CTF 2025](https://hackmd.io/@YaipbyxZRByK2Qi9Le0t4A/Sk_8Z6c8xx)

Các bạn chỉ cần copy Solution của Author và paste vào chương trình với tên file .py là được. Ở đây mình đặt exploit.py
![Ảnh chụp màn hình 2025-07-31 222843](https://hackmd.io/_uploads/Sk2Q1hFPgx.png)

Chạy và exploit thành công! Get được flag

# Lời kết & Ref

SageMath không chỉ là một công cụ mạnh mẽ để hỗ trợ giải các bài toán đại số, hình học và mật mã — mà còn là một người bạn đồng hành đắc lực cho dân chơi CTF, sinh viên ngành khoa học máy tính, và bất kỳ ai đam mê toán học

Ref:
https://doc.sagemath.org/html/en/installation/index.html#windows