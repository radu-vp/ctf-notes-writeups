# Forensics

Link: [Forensics](https://tryhackme.com/r/room/forensics)

## High-Level Overview

This is a memory dump of compromised system, do some forensics kung-fu to explore the inside.

## Tools Needed

* strings
* Volatility 2
* Volatility 3

## Walkthrough

First, download the file attached to the task 1. It is an archive named `victim_1556932027367.zip`.
Note: The same file seems to be attached to all 3 tasks.
The contents of the `.zip` archive are: a file named `victim.raw`.

The sections below show the necessary `Volatility` and `strings` commands that are needed in order
to solve the challenge.
The flags needed to answer the questions can be identified in the output.

### Task 1

```bash
$ cd Downloads/
$ mkdir output
$ unzip victim_1556932027367.zip -d output/
$ cd output
$ vol -f victim.raw windows.info
$ vol -f victim.raw windows.psscan
# Need Volatility2 for the shellbags plugin
$ vol.py -f victim.raw --profile=Win7SP1x64 shellbags
```

### Task 2

```bash
$ vol -f victim.raw windows.netscan
$ vol -f victim.raw windows.psscan
$ vol -f victim.raw windows.malfind
```

### Task 3

```bash
$ vol -f victim.raw -o . windows.memmap --dump --pid 1820
$ vol -f victim.raw -o . windows.memmap --dump --pid 1860
$ vol -f victim.raw -o . windows.memmap --dump --pid 2464
$ strings pid.1820.dmp | grep '\<www\.go....\.ru\>'
$ strings pid.1820.dmp | grep '\<www.\i....\.com\>'
$ strings pid.1820.dmp | grep '\<www.\ic......\.com\>'
$ strings pid.1820.dmp | grep '\<202\....\.233\....\>'
$ strings pid.1820.dmp | grep '\<209\.190\....\....\>'
$ vol -f victim.raw windows.envars --pid 2464
```
