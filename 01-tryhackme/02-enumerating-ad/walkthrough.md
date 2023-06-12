# Enumerating Active Directory

## High-Level Overview

## Tools Needed

* Powershell
* Microsoft Management Console
* Neo4j
* Sharphound
* Bloodhound

## Walkthrough

### Connecting to the Network

* Download the Network VPN Server `Breachingad` configuration file for OpenVPN
* Connect using OpenVPN and the TryHackMe VPN file
	* `sudo openvpn user-breachingad.ovpn`
* Configure the DNS on the host which you are running the VPN connection:
	* Edit the `resolv.conf` file with the command `sudo nano /etc/resolv.conf` and add the line `nameserver 10.200.56.101` at the end of the file.
	* Or use `sudo resolvectl dns enumad 10.200.56.101`
	* `10.200.56.101` is the IP of the `THMDC` in my case.
* Test DNS resolution with the command `nslookup thmdc.za.tryhackme.com` - this should resolve to the IP of the DC
* Your IP for can be identified using `ip add show enumad` - the inet IP you will use for reverse shells, listeners, etc.

### Requesting Your Credentials

To get the AD credentials required for both SSH and RDP connections to a machine on this network, we need to navigate to `http://distributor.za.tryhackme.com/creds` and request a credential pair by clicking `Get Credentials`.

We can connect using SSH with the following command:

```bash
$ ssh za.tryhackme.com\\AD_USERNAME@thmjmp1.za.tryhackme.com
# supply the provided password
```

For solving all tasks RDP will be the more useful connection option.

### Task 2

We will use `nslookup` to see if our domain is resolved using the command:

```bash
$ nslookup za.tryhackme.com
```

Connect to the machine using RDP:

```bash
$ xfreerdp /v:THMJMP1.za.tryhackme.com /u:AD_USERNAME /p:PASSWORD
```

We can now see if we get any interesting information using dir:

```bash
$ dir \\za.tryhackme.com\SYSVOL
$ dir \\10.200.56.101
```

### Task 3

Since we are connected via RDP from the previous task, we can solve the current task by using Microsoft Management Console (MMC)

The `THMJMP1` machine already has MMC with the Remote Server Administration Tools (RSAT) AD Snap-Ins.

Using your own Windows machine requires you to do the following steps.

* Open MMC by doing the following:
	* Press `Start`
	* Search "Apps & Features" and press Enter
	* Click on `Manage Optional Features`
	* Click `Add a feature`
	* Search for "RSAT"
	* Select `RSAT:Active Directory Domain Services and Lightweight Directory Tools` and click `Install`

Regardless of which machine you run this on now, you can start MMC by pressing `Start` and searching for `run`. Use the `run` utility to search for `MMC` and press enter to start it.

With `MMC` open, we must now do the following steps to attach the AD RSAT Snap-in:

In MMC, we can now attach the AD RSAT Snap-In:

* Click `File` -> `Add/Remove Snap-in`
* Select and `Add` all three Active Directory Snap-ins
* Click through any errors and warnings
* Right-click on `Active Directory Domains and Trusts` and select `Change Forest`
* Enter `za.tryhackme.com` as the Root domain and Click `OK`
* Right-click on `Active Directory Sites and Services` and select `Change Forest`
* Enter `za.tryhackme.com` as the Root domain and Click `OK`
* Right-click on `Active Directory Users and Computers` and select `Change Domain`
* Enter `za.tryhackme.com` as the Domain and Click `OK`
* Right-click on `Active Directory Users and Computers` in the left-hand pane
* Click on `View` -> `Advanced Features`

Now we can enumerate the AD environment, and for this task we need to focus on AD Users and Computers.

### Task 4

For this task we need to use CMD and can solve this task by using the following queries:

```powershell
> net user aaron.harris /domain
> net user Guest /domain
> net group "Tier 1 Admins" /domain
> net group "Tier 1 Admins" /domain | find "t1"
> net accounts /domain
```

### Task 5

For this task we need to use PowerShell to enumerate AD users and properties. We can do this by using the following queries:

```powershell
# enumerate AD users
> Get-ADUser
> Get-ADUser -Identity gordon.stevens -Server za.tryhackme.com -Properties *
# enumerate AD groups
> Get-ADGroup
> Get-ADGroup -Identity Administrators -Server za.tryhackme.com
> Get-ADGroupmember
> Get-ADGroupMember -Identity Administrators -Server za.tryhackme.com
# enumerate AD objects - more generic
> Get-ADObject
> $ChangeDate = New-Object DateTime(2022, 02, 28, 12, 00, 00)
> Get-ADObject -Filter 'whenChanged -gt $ChangeDate' -includeDeletedObjects -Server za.tryhackme.com
> Get-ADObject -Filter 'badPwdCount -gt 0' -Server za.tryhackme.com
# enumerate AD domains
> Get-ADDomain
> Get-ADDomain -Server za.tryhackme.com
# altering AD objects
> Set-ADAccountPassword -Identity gordon.stevens -Server za.tryhackme.com -OldPassword (ConvertTo-SecureString -AsPlaintext "old" -force) -NewPassword (ConvertTo-SecureString -AsPlainText "new" -Force)
```

Specifically for answering the questions, we will use these queries:

```powershell
> Get-ADUser -Identity beth.nolan -Server za.tryhackme.com -Properties title
> Get-ADUser -Identity Annette.Manning -Server za.tryhackme.com -Properties DistinguishedName
# first list all AD groups
> Get-ADGroup -Filter 'Name -like "*admin*"' | select name
> Get-ADGroup -Identity "Tier 2 Admins" -Property *
> Get-ADGroup -Identity "Tier 2 Admins" -Property Created
> Get-ADGroup -Identity "Enterprise Admins" -Property *
> Get-ADDomain
```

### Task 6

We can use the previous connection established with the `THMJMP1` machine to complete the final task.

The `THMJMP1` machine already has `SharpHound` on it located at `C:\Tools\Sharphound.exe`, so we will be using it to enumerate and collect data about the AD environment.

First we will copy the `Sharphound.exe` file to our user's Documents folder with the commands below:

```powershell
> copy C:\Tools\Sharphound.exe ~\Documents\
> cd ~\Documents\
```

Now we can run `SharpHound` in this folder with the following command:

```powershell
> .\SharpHound.exe --CollectionMethods All --Domain za.tryhackme.com --ExcludeDCs
```

Once that is done, copy the resulting archive file from the `THMJMP1` machine to your own attacker machine using scp:

```bash
$ scp AD_USERNAME@THMJMP1.za.tryhackme.com:C:/Users/AD_USERNAME/Documents/20230611171012_BloodHound.zip .
# replace 20230611171012_BloodHound.zip with your own file name
```

* Open a terminal tab and run `sudo neo4j console`
* In a new terminal tab and run `bloodhound --no-sandbox`
* Default credentials for `neo4j` are `neo4j`:`neo4j`

Click on `Upload data` and upload your `.bin` file collected by SharpHound.

Use the premade queries as well as the search functionality to answer the questions.