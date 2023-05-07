# MD2PDF

Link: [MD2PDF](https://tryhackme.com/room/md2pdf)

## High-Level Overview

Identify the vulnerability in the MD2PDF product of TopTierConversions LTD and retrieve the flag.

## Tools Needed

* Nmap
* Gobuster
* Firefox

## Walkthrough

Initial scan using `nmap` of the machine:

```bash
$ sudo nmap -sS -sV -p- -Pn MACHINE:IP
```

We can see that the following ports are open:

* 22/tcp - shh
* 80/tcp - http
* 5000/tcp - upnp

The web application is a markdown to pdf converter. Entering text formatted using markdown, we can generate a nice pdf document and download it on our machine.

Since there is a web application running at `http://MACHINE:IP:80` we can try to enumerate it using gobuster:

```bash
$ gobuster dir -u http://MACHINE:IP -w /usr/share/wordlists/dirb/common.txt
```

The only result we get is a page called `/admin`.

There appears to be another web application running on port 5000. It looks identical to the one running on port 80. Moreover, it has a similar `/admin` page at `http://MACHINE:IP:5000/admin`. We cannot open, it seems it is only accessible to localhost.

Fortunately, the web application running on port 80 appears to be vulnerable, since it interprets some input as commands and the generated pdf file contains the output.

We can create a payload in the markdown entry form of the web application running on port 80. If we enter the string `<iframe src="http://localhost:5000/admin"></iframe>` and generate the pdf, we can open the page only accessible from localhost in an `iframe` and there we can get the flag we need to complete the challenge.