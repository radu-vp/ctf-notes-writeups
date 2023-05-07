# Warzone 1

Link: [Warzone 1](https://tryhackme.com/room/warzoneone)

## High-Level Overview

Investigate a network case based on **Potentially Bad Traffic** and **Malware C2 Activity**.

## Tools Needed

* Brim
* Wireshark

## Walkthrough

First step of the investigation is going to be to open the capture file in `Brim`.

We will be investigating this case based on the queries below:

```
event_type == "alert"
_path=="http" | 169.239.128.11 | cut user_agent
_path=="http" | 172.16.1.102 | method == "GET" | sort | uniq -c
# 185[.]10[.]68[.]235, 192[.]36[.]27[.]92
_path=="http" 192.36.27.92
_path=="http" | cut uri
# click on file activity filter or write the below filter
filename!=null | cut _path, tx_hosts, rx_hosts, conn_uids, mime_type, filename, md5, sha1
```

For the final 2 flags, we need to identify the location where the files have been downloaded. We will open the capture file in `Wireshark`.

We can search inside the packets using the file names identified earlier.

* Press CTRL+F to filter by the file names (`filter.msi`, `10opd3r_load.msi`)
* Make sure to change the filter to look for `strings` inside `packet details`

Next, when we identify the packet that contains either file, we can right click it and then follow the TCP stream. The full file path should be around the end of the results.