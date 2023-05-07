# Warzone 2

Link: (Warzone 2)[https://tryhackme.com/room/warzonetwo]

## High-Level Overview

Investigate a network case based on **Misc. activity** and **A Network Trojan Was Detected** and **A Potential Corporate Privacy Violation**.

## Tools Needed

* Brim
* Wireshark

## Walkthrough

* Brim queries:

```
event_type == "alert"
filename!=null | cut _path, tx_hosts, rx_hosts, conn_uids, mime_type, filename, md5, sha1
_path=="http" 185.118.164.8
```

* Check the host and the uri and combine them for the third flag

Open `Wireshark` and click `File` -> `Export Objects` -> `HTTP` and get the cap file.

Now get the md5 hash for it and check it on virustotal.

```bash
$ md5sum 'fxla.php%3fl=gap1.cab'
```

Additionally, use Wireshark to identify the user agent. Can click on packet nr. 6 and follow TCP stream or check packet details.

* additional Brim queries

```
alert.category=="Not Suspicious Traffic" | count() by src_ip
"64.225.65.166" in answers
"142.93.211.176" in answers | cut query
```