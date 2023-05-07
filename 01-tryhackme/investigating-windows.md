# Investigating Windows

Link: [THM-Investigating-Windows](https://tryhackme.com/room/investigatingwindows)

## High-Level Overview

We are tasked with investigating a Windows Machine that has been previously compromised.

## Tools Needed

* Powershell
* Event Viewer
* Task Scheduler
* System Information
* Windows Defender Firewall with Advanced Security

## Walkthrough

After turning on the machine and logging into Windows, we get a pop up. It is a cmd shell running from the location `C:\TMP\p.exe` it seems that there is an application called `PsExec v1.98` that is trying to execute processes remotely. To do this, it tries to connect to the IP `10.34.*.*`. Taking note of this IP, as it is the 4th flag required for the completion of this challenge.

We need to find out the version and year of the windows machine. To do this, we can use the windows search feature and type in `System Information`. Opening this utility, we can see in the `System Summary` tab that the information listed under `OS Name` contains `Windows Server xxxx`. This is our first flag.

Next, we need to identify which user logged in last. Using the Windows search functionality again, we can type in `Event Viewer`. Opening this utility and then going to the tab `Windows Logs` and then underneath it into `Security`, we can see security events such as log on, log offs. Sorting by date and time, we can see that the last user to log in was `A*************`

We should establish what other users have accounts for this machine. To do that, we can open a new PowerShell instance as administrator, and we can type in the command `net user`. We can now see all listed users for this machine: Administrator, DefaultAccount, Guest, Jenny, John

We need to identify the last time **John** logged onto the system, and we can do this using the same Powershell instance, by typing in `net user John`. This gives us more information about **John**, and we can see under the line `Last Logon` that he last logged in on `03/02/**19 5:*8:*8 PM`

To identify what other accounts had administrative privileges, we can use the command `net localgroup Administrators`. This shows us that Besides the `Administrator` account, 2 other users belong to this group: `J****, G****`. This is our 5th flag.

We need to identify a scheduled task that was deemed malicious. Using the `Powershell` instance, we can type in the command `schtasks`, which lists all the scheduled tasks and the folders they are located in. Here we can identify the task `Clean f*** s*****`. This is our 6th flag.

To view what time this task was scheduled to run at, we can use Windows search yet again, and type in `Task Scheduler`. Under `Task Scheduler (Local)` and going into `Task Scheduler Library`, we can see the suspected task `Clean file system`. Clicking on it then going to the `Actions` tab in the lower half of the `Task Scheduler` utility, we can see that the task is scheduled to run a program `C:\T**\n*.ps1 -l 1**8`. This information contains the 7th and the 8th flag, as the port that this file will listen to is listed in the action.

Next, we need to find out when **Jenny** last logged in. Using the previous `Powershell` instance, we can issue the command `net user Jenny` to find out, and under `Last Logon` there doesn't seem to be a date, just the string: `Nev**`. This is our 9th flag.

We need to find out when the compromise took place. We begin by looking through the file systems for indicators of compromise. ANy folder or file structure that is out of the ordinary to help point us in the right direction. Opening the `File Explorer`, we can go to `Local Disk (C:)` and start checking the structure. Normally the `TMP` folder is not present. Opening the folder, we can see that all the files inside it were modified at the same date, and around the same time. The date modified is listed as `*3/*2/2*** 4:37 PM`. This is the date of the compromise, and also our 10th flag.

To find out when Windows first assigned special privileges to a new logon, we need to open `Event Viewer` and have a look at the logs. We are probably looking for a `Special Logon` event, so if we sort by `Task Category` we should have an easier time to look at them. Searching for an event near the date of the compromise, we can see that on `03/02/2019 04:04:49 PM` some special privileges were assigned to a new logon (Event ID 4672). This constitutes our 11th flag.

We need to find out what tool was used to get the Windows Passwords. To do this, we will search through the `TMP` folder for any indicators. It seems there is a file named `mim.exe` that also produced a `.txt` file as output. Investigating the `mim-out.txt` file, we can determine that the tool used was `mimikatz`. This is our 12th flag.

To find evidence of the control and command servers IP, we need to investigate the file `hosts` file located in `C:\Windows\System32\drivers\etc\`. Here we can find a few lines that were manually added:

```
76.32.97.1*2 g**gle.com
76.32.97.1*2 www.g**gle.com
```

It seems the attackers were trying to spoof the domain google.com to trick the user into connecting to their C2 server whenever they searched for google. The IP address constitutes the 13th flag. The domain that was poisoned was `g*****.com`, and this constitutes the 16th flag.

Next, we need to search for the extension name of the shell uploaded via the servers website. Looking for a location for this webserver, we identify the path `C:\inetpub\wwwroot` as a possibility. there we can find a file with the extension `.j**`. This is our 14th flag.

To find ports that were opened, we can can use Windows search functionality and type in `Windows Firewall with advanced Security`. Opening this utility, and selecting the tab `Inbound Rules`, we can see the connection rules for this machine. Most recent connections are going to be at the top. We can see here the first one has an unusual name `Allow outside connections for development`. If we double click it to view the `Properties` and then go to the `Protocols and Ports` tab, we can see the specified port is `1**7`. This is our 15th flag.