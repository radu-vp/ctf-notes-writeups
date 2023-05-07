# Investigating Windows 2.0

Link : [Investigating Windows 2.0](https://tryhackme.com/room/investigatingwindows2)

## High-Level Overview

Investigate a Windows machine that is infected with WMI Backdoor.

## Tools Needed

* Task Scheduler
* SysinternalsSuite
* Loki & Yara
* Process Hacker

## Walkthrough

It seems that every few minutes, this machine launches a couple of windows command prompt instances and then closes them almost instantly. These are `mim.exe` and `powershell.exe`.

To further investigate, we can begin with opening `Task Scheduler` using by pressing the WIN key and searching for `taskschd.msc`. The task we are looking for is called `GameOver`. The scheduled task is running an exe located at `C:\TMP\mim.exe`.

We can use the SysinternalsSuite utility called `autoruns` to investigate the tasks in more detail and find the registry key in question.

Opening different `SysinternalsSuite` utilities to see which one is immediately closed, we can see that `procexp64.exe` keeps crashing.

We can open `loki.exe` and see the full WQL query during startup. Open `loki` from the command line and make sure it outputs to a `.txt` file so you can investigate later.

```shell
> cd C:\Users\Administrator\Desktop\Tools\loki_0.33.0\loki
> loki.exe > loki-output.txt
```

* We can open `C:\TMP` and we can explore the file `WMIBackdoor.ps` to find the name of the other script, as well as the name of the company and the websites associated with this file.
* To find out more, we can open `procmon64.exe` to explore the processes that keep spawning. Filter for `Process Name` and specify it to `mim.exe`. In the first entry `Process Start`, we can see listed under the `Details` tab that the `Parent PID` is 932. Knowing this, we need to open `Process Hacker` and check for the `PID` corresponding to `mim.exe`
* In `Process Hacker` we can investigate the disk tab for unusual activity. Why is there a process name `no process`?
* The rest of the challenges can be done by investigating the `loki-output.txt` file.
	* Investigate `[ALERT]` entries
	* Stuff running where it normally shouldn't - that seems like a good reason

For the final challenge we need to define some `YARA` rules to catch the malicious `.exe` that was not seen with Loki.

* first go to the `Sysinternals Suite` folder and open a command prompt. Search the `mim.exe` file for strings which will be our indicators of compromise (IOC) for our `YARA` rule. Run the commands:

```
strings64.exe \tmp\mim.exe | findstr "exe"
strings64.exe \tmp\mim.exe | findstr "mk"
strings64.exe \tmp\mim.exe | findstr "v2"
```

* we can identify a few IOCs this way: `mk.pse1`, `mk.exe`, `v2.0.50727`
* save the code below to a `mim.yar` file and then place it in `C:\Users\Administrator\Desktop\Tools\loki_0.33.0\loki\signature-base\yara`
	* run `loki.exe` from the command line and now it will find the `mim.exe`

```
rule mim-detector {
		meta:
				author      = "radu"
				description = "THM find mim.exe"
				created     = "04/05/2023 00:00"
		strings:
				$version = "v2.0.50727"
				$mk-name = "mk.exe"
				$mk-ps   = "mk.ps1"
		condition:
				all of them;
}
```