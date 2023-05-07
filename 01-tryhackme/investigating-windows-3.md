# Windows 3.x

Link: [Investigating Windows 3.x](https://tryhackme.com/room/investigatingwindows3)

## High-Level Overview

Determine what type of attack compromised the endpoint and identify artifacts.

## Tools Needed

* Sysinternals Suite
* Event Viewer
* Powershell

## Walkthrough

We can begin by investigating the files placed on the desktop. First, using the `Autoruns` Sysinternals Suite utility we can see some processes highlighted in yellow. We can see in one of those entries, under `Image Path`, there seems to be an encoded string. This is likely the malicious payload.

If we open Registry Editor under the corresponding key, we can see a String with the value name `Debug` that has listed the payload which has been encoded in base64. Inside the payload, there is an additional base64 encoded payload.

Next we can open `Event Viewer` and check the `Sysmon` logs found under `Application and Service Logs` -> `Microsoft` -> `Windows` -> `Sysmon` -> `Operational`. Researching for the `Sysmon Event ID` for a registry value being set we can see it is `Event ID 13` and we can filter the logs by selecting this event id. We need to look for an event that specifies powershell usage. Alternatively we can save this as an event log file and open powershell to search using the command:

```shell
> Get-WinEvent -Path .\sysmon.evtx -FilterXPath '*/System/EventID=13' | Sort-Object TimeCreated | Where-Object {$_.Message -like "*enc*"} | fl
```

We can decode the payload to answer some other questions.

If we use the same command as above but we search for a message like `ualapi.dll` we can see the PID for this event listed as `1596` which if we filter for in `Process Monitor` we can identify as `spoolsv.exe`. If we right click the entry and click on event properties we can see under the `Process` tab a parent PID listed.

Searching for `ualapi.dll` on the internet we can see a proof of concept bind shell using the `Fax` Service. To check for the Event ID associated with this service we will use Event Viewer and look under `Application and Service Logs` -> `Microsoft` -> `Windows` -> `Print Service` -> `Admin`.

Powershell is responsible for running the encoded payload so we can filter for `powershell` in `Process Monitor`

There are a few files listed under the logged in user's `Documents` folder. If we look in the third PowerShell Transcript and we google the function `Invoke-PSInject` we will find the C2 framework.

In the previously identified encoded payload there is another encoded string that contains the IP address. A NS lookup would reveal the FQDN of the attacker

```bash
$ nslookup 34.245.128.161
```

We can look for other connections by filtering for Sysmon EventID=3 and using the command:

```powershell
Get-WinEvent -Path .\sysmon.evtx -FilterXPath '*/System/EventID=3'| Sort-Object TimeCreated | fl
```

We can see one of the processes is `explorer.exe`

To find out the path for the first image loaded we can open process monitor and filter for `PID is 2684` and `Operation is load image`. The culprit is `mscoree.dll`

To answer the next question we need to check events generated between the time `explorer.exe` and `spoolsv.exe` was generated.

```powershell
> Get-WinEvent -Path .\sysmon.evtx -FilterXPath `*/System/EventID=13' | Sort-Object TimeCreated | Where-Object {$_.Message -like "*enc*"} | fl
# TimeCreated  : 1/21/2021 5:08:13 PM
# explorer.exe
```

```powershell
> Get-WinEvent -Path .\sysmon.evtx -FilterXPath `*/System/EventID=1' | Sort-Object TimeCreated | Where-Object {$_.Message -like "*enc*"} | fl
# TimeCreated  : 1/21/2021 5:05:45 PM
# powershell.exe
```

We will set the times as variables

```powershell
$starttime= Get-Date -Date "1/21/2021 5:05:45 PM"
# powershell =  start date
```

```powershell
$endtime = Get-Date -Date "1/21/2021 5:08:13 PM"
# explorer.exe = end date
```

```powershell
> Get-WinEvent -Path .\sysmon.evtx -FilterXPath `*/System/*' | Where-Object {$_.TimeCreated -ge $startdate -and $_.TimeCreated -le $endtime } | Sort-Object TimeCreated
```

We can see the first event that looks interesting right after our 5:05:45 PM time

```
1/21/2021 5:05:45 PM             1 Information      Process Create:.
```

After a network connection was detected, we can see the rest of the events are very similar. The rest of the questions can be answered based on the search results. The first event had a date of `1/21/2021 5:05:46 PM`

```powershell
$date = Get-Date -Date "1/21/2021 5:07:06 PM"
> Get-WinEvent -Path .\sysmon.evtx -FilterXPath '*/System/*' | Where-Object { $_.TimeCreated -like $date } | fl
```

We can take the PID (3088) from the first event and filter for it in the `Process Monitor`.

In Resource Monitor filter for `Path` `contains` `Release`.