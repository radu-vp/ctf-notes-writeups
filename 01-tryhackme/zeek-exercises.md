# Zeek Exercises

Link: [Zeek Exercises](https://tryhackme.com/room/zeekbroexercises)

## High-Level Overview

Investigate a series of traffic data and stop malicious activity in three different scenarios.

## Tools Needed

* Zeek

## Walkthrough - Anomalous DNS

* commands:

```bash
$ zeek -C -r dns-tunneling.pcap
$ cat dns.log | grep -o "AAAA" | wc -l
$ cat conn.log | zeek-cut duration | sort | tail
$ cat dns.log | zeek-cut query |rev | cut -d '.' -f 1-2 | rev | sort | uniq | wc -l
$ cat conn.log | zeek-cut id.orig_h orig_pkts | sort -n
```

## Walkthrough - Phishing

* Commands:

```bash
$ zeek -C -r phishing.pcap file-extract-demo.zeek hash-demo.zeek
$ cat http.log | zeek-cut id.orig_h
$ cat http.log | zeek-cut host
$ md5sum
$ sha1sum
```

## Walkthrough - Log4J

* Commands:

```bash
$ zeek -C -r log4shell.pcapng detection-log4j.zeek
$ cat signatures.log | zeek-cut note
$ cat http.log | zeek-cut user_agent
$ cat http.log | head
$ cat log4j.log | zeek-cut value | head
$ echo 'dG91Y2ggL3RtcC9wd25lZAo=' | base64 --decode
```