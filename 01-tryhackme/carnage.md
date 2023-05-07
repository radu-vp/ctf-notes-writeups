# Carnage

Link: [Carnage](https://tryhackme.com/room/c2carnage)

## High-Level Overview

Investigate the packet capture to discover the malicious activities and retrieve all the flags.

## Tools Needed

* Wireshark

## Walkthrough

* Wireshark queries

First we can go to `Edit`, `Preferences`, `Name Resolution` and then select `Resolve Network (IP) addresses` to aid us in in corelating hostname to IP addresses and expedite the search.

```
http
```

We can then sort the packets at time, then click the desired packet and look under `Frame` at the `Arrival Time`.

We can search for the word `zip` by pressing `CTRL+F` and then choose the filtering option for `string` in the `packet details` option. After which, we can right click the first packet that contains the word `zip` and click on `Follow TCP Stream`.

View the contents of the response, and select `view as UTF-8`. Reading the hint might reveal additional helpful information.

```
(frame.time > "Sep 24, 2021 16:45:11") && (frame.time > "Sep 24, 2021 16:45:30") && tcp.port == 443
# Follow TCP stream of the packets with the destination IP starting with 148, 210
# inspect packet 2436 for CA
```

```
# Open Statistics -> Conversations -> IPv4 -> Enable Limit Display Filter -> Sort by packets descending
tcp.port == 8080 or tcp.port == 80 or tcp.port == 50050
ip.addr == 185.106.96.158 and http
http.request.method == POST
# CTRL + F -> search in packet details for "securitybusinpuff.com"
# look at full request URI
# look at length of packet 3822
# follow stream on packet 3822
ip.addr==10.9.23.102 && dns && frame contains "api"
# follow udp stream on packet 24149
```

```
smtp contains "MAIL FROM"
smtp
```