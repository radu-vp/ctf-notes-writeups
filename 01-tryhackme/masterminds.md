# Masterminds

Link: [Masterminds](https://tryhackme.com/room/mastermindsxlq)

## High-Level Overview

Three machines in the Finance department at **Pfeffer PLC** were compromised. Two initial points of compromise were likely at fault: a phishing attack and an infected USB drives. Use `Brim` to investigate network traffics for indicators of the attack and identify the attacker.

## Tools Needed

* Brim

## Infection 1

* Brim Queries

```
cut id.orig_h, id.resp_h | uniq -c

_path=="http" id.orig_h==192.168.75.249 status_code==404

_path=="http" id.orig_h==192.168.75.249 response_body_len==1309

_path=="dns" | count() by query | sort -r

_path=="http" id.orig_h==192.168.75.249 host=="bhaktivrind.com"

_path=="http" id.orig_h==192.168.75.249 uri matches *.exe
```

## Infection 2

* Brim Queries

```
cut id.orig_h, id.resp_h | uniq -c

_path=="http" id.orig_h==192.168.75.146 method=="POST"

_path=="http" id.orig_h==192.168.75.146 method=="POST" | count()

_path=="http" id.orig_h==192.168.75.146 method=="GET"

event_type=="alert" | cut src_ip, dest_ip, alert.category
```

## Infection 3

* Brim Queries

```
cut id.orig_h, id.resp_h | uniq -c

_path=="http" id.orig_h==192.168.75.232 method=="GET" | cut ts, id.resp_h, host, uri

_path=="dns" query=="efhoahegue.ru" | uniq -c | count()

_path=="http" host=="efhoahegue.ru" method=="GET" | uri matches *.exe | count()

count() by _path | sort -r
```