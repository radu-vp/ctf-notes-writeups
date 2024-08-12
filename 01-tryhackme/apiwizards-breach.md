# APIWizards Breach

Link: [APIWizards Breach](https://tryhackme.com/r/room/apiwizardsbreach)

## High-Level Overview

Investigate a security breach at APIWizards Inc.

## Tools Needed

* N/A

## Walkthrough

Connect to the VPN

`sudo openvpn thm-rooms.ovpn`

Edit the file `/etc/hosts` to include the following line

`sudo nano /etc/hosts`

```
MACHINE:IP     api.thm
```

Log into the machine using SSH and the following credentials: `dev`:`d3v-p455w0rd`

```bash
$ ssh dev@api.thm
```

Once we are on the machine, we can run the following commands in sequence to answer all the questions.

```bash
$ ssh
$ ls -lah
$ cd apiservice/
$ ls -lah
# We can tell what programming language the app was written it based on the file extensions.
$ systemctl status apiservice.service
$ cd /var/log/nginx
$ ls -lah
$ head access.log.1
$ cd ~
$ cat .bash_history
$ cd ~/apiservice/src/
$ cat config.py
$ sudo su
$ cd ~
$ cat .bash_history
$ cat /etc/crontab
$ cat /etc/environment
$ echo $SYSTEMUPDATE
$ ss -tnlp | grep 0.0.0.0
# Look at the interesting line below, PID will vary
# LISTEN    0         1                    0.0.0.0:3578              0.0.0.0:*        users:(("nc",pid=588,fd=3))
$ ps aux | grep 588

$ pstree -s -p 588
# systemd(1)\u2500\u2500\u2500bash(575)\u2500\u2500\u2500nc(588)
$ ps aux | grep 575
$ grep -R "nc -l" /etc/systemd/system
$ cat /etc/systemd/system/socket.service
# Look at the line that contains "nc"
$ iptables -L -n
$ grep -iHR "iptables" /etc 2>/dev/null
$ grep -iHR "iptables" /home 2>/dev/null
$ grep -iHR "iptables" /root 2>/dev/null
$ grep -ER "useradd|usermod|adduser" /var/log/auth.log*
$ groups support
$ find /home/*/.ssh -type f
$ find /root/.ssh -type f
$ cat /home/dev/.ssh/authorized_keys
$ cat /root/.ssh/authorized_keys
$ stat /etc/systemd/system/socket.service
$ find /etc/ -type f -newerct "2023-07-30 16:35:00" ! -newerct "2023-07-30 16:45:00" -ls | tail -n 3
$ find /root/ -type f -newerct "2023-07-30 16:35:00" ! -newerct "2023-07-30 16:45:00" -ls | tail -n 3
$ find /bin/ -type f -newerct "2023-07-30 16:35:00" ! -newerct "2023-07-30 16:45:00" -ls | tail -n 3
$ ll /bin/clamav
$ md5sum /bin/clamav
$ ll /bin/clamav /bin/bash
$ md5sum /bin/bash
$ exit
$ whoami
# dev
$ /bin/clamav -p
$ stat /bin/clamav
$ cd /root
$ ls -lah
$ cat .dump.json
# base64 decode the strings
$ cat .bash_history
$ cat .review.csv
```
