# Credentials Harvesting

Credentials harvesting refers to the techniques (such as network sniffing) used in order to either steal or search for stored credentials.

Credentials can take many forms, such as:

* Account details (usernames and passwords)
* Hashes (NTLM hashes, etc.)
* Authentication Tickets (Tickets Granting Ticket - TGT, Ticket Granting Server - TGS)
* Any other information that can help an attacker log into a system (such as private keys)

Credentials harvesting can be either external (attempted through phishing emails or other techniques) or internal.

The techniques detailed below mostly belong in the internal credential harvesting category.

## Credential Access

Credential access refers to where an attacker may find credentials in a compromised system and gain access to user credentials.

The attacker could then reuse the credentials or impersonate the user, which would aid them in performing lateral movement or accessing other applications or systems.

Some of the locations where credentials are likely to be stored insecurely are:

* Clear-text files
	* Commands history
	* Configuration files (Web App, FTP files, etc.)
	* Other files related to Windows Applications (Internet Browsers, Email Clients, etc.)
	* Backup files
	* Shared files and folders
	* Registry
	* Source code
* Database Files
* Password Managers
	* Built-in password managers (Windows)
	* Third-party: KeePass, 1Password, LastPass
* Memory Dump
	* Clear-text credentials
	* Cached passwords
	* AD Tickets
* Active Directory
	* Users' description
	* Group Policy SYSVOL
	* NTDS
	* AD Attacks
* Network Sniffing (Man-in-the-Middle attack)

## Local Windows Credentials

* Keystrokes
* Security Account Manager (SAM) - Dumping the SAM database contents can be done through a few ways:
	* Manual
		* `type c:\Windows\System32\config\sam`
		* `copy c:\Windows\System32\config\sam C:\Users\Administrator\Desktop\`
	* Metasploit's HashDump
	* Volume Shadow Copy Service
		* Run the `cmd.exe` as admininstrator
		* Execute `wmic`
		* `wmic shadowcopy call create Volume='C:\'`
		* `vssadmin list shadows`
		* `copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\users\Administrator\Desktop\sam`
		* `copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\users\Administrator\Desktop\system`
	* Registry Hive
		* `reg save HKLM\sam C:\users\Administrator\Desktop\sam-reg`
		* `reg save HKLM\system C:\users\Administrator\Desktop\system-reg`
		* Move the SAM and system files to your machine and decrypt them using `impacket/secretsdump.py`
		* `python3.9 /opt/impacket/examples/secretsdump.py -sam /tmp/sam-reg -system /tmp/system-reg LOCAL`

## Local Security Authority Subsystem Service (LSASS)

LSASS is a Windows process that handles the Operating System security policy and enforces it on a system. It verifies logged in accounts and ensures passwords, hashes, and Kerberos tickets. Credentials are stored in the LSASS process to enable users to access network resources.

LSASS is commonly abused to dump credentials. If we have administrators privileges, we can dump the process memory of the LSASS. We can do this with either:

* GUI (Task Manager -> Details -> Right-click on lsass.exe -> Create dump file, copy to attacker machine and extract NTLM hashes offline)
* CLI, using `ProcDump`, part of the `Sysinternals Suite`
	* `procdump.exe -accepteula -ma lsass.exe c:\Tools\Mimikatz\lsass_dump`
* CLI, using `Mimikatz` to extract the memory dump of the `lsass.exe` process

LSASS can also be protected in order to prevent from being accessed to extract credentials from memory. LSASS protection can be enabled, by modifying the registry `RunAsPPL DWORD` value in `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa` to 1.

## Windows Credential Manager

Credential Manager is a Windows feature that stores logon-sensitive information for websites, applications, and networks. It contains login credentials such as usernames, passwords, and internet addresses.

It can be accessed through GUI at Control Panel -> User Accounts -> Credential Manager or through the cli.

We can use the Microsoft Credentials Manager `valutcmd` utility for the cli. It is not able to show passwords, but we can rely on other PowerShell scripts to do so.

Alternatively, stored credentials enumerated using `cmdkey /list` can be abused using `RunAs`.

Also, `Mimikatz` can dump clear-text passwords stored in the Credential Manager from memory.

## Domain Controller

New Technologies Directory Services (NTDS) is a database that contains all AD data, including objects, attributes, credentials, etc. It is located in `C:\Windows\NTDS` by default, is encrypted, and access to it is disabled by default. However, we can get a copy of the NTDS file using `ntdsutil` and `Diskshadow` tool, and dump the file's contents. Decrypting the NTDS file requires a system Boot Key to attempt to decrypt LSA Isolated credentials, which is stored in the `SECURITY` file system. Therefore, we must also dump the security file containing all required files to decrypt.

Local Dumping (No Credentials) using `ntdsutil`, Windows utility used to manage and maintain AD configurations.

Remote Dumping (With Credentials) - If we have credentials, such as passwords or NTLM hashes, can can perform a DC Sync attack. This requires a privileged account, such as an AD admin account or an account that has specific AD permissions (Replicating Directory Changes aka RDC, RDC All, RDC in Filtered Set)

This type of attack can be performed using `Mimikatz` or using `Impacket-SecretsDump` script. If only NTLM hashes were extracted, they can be then cracked offline.

## Local Administrator Password Solution (LAPS)

LAPS is a more secure alternative to storing encrypted passwords in the `SYSVOL` folder and remotely managing the local administrator password.

To check if LAPS is enabled, we need to check the `admpwd.dll` path, located in `C:\Program Files\LAPS\CSE\`. Usually there is an AD organizational unit (OU) that has the "All extended rights" attribute that deals with LAPS. Finding this OU that has the right access level and then checking which groups and members are there. Compromising or impersonating the account that is part of that group, we can use it to recover the LAPS password.

## Other Attacks

* Kerberoasting - AD attack used to obtain AD tickets that can help with persistence. It is required to have access to SPN (Service Principal Name) accounts such as IIS User, MSSQL, etc. The attack involves requesting a TGT and TGS, enabling privilege escalation and lateral movement
* AS-REP Roasting - technique that allows the attacker to retrieve password hashes for AD users whose account options have been set to "Do not require Kerberos pre-authentication". It is commonly performed using `Impacket Get-NPUsers` script
* SMB Relay Attack
	* This attack abuses the NTLM authentication mechanism, essentially the attacker performing a Man-in-the-Middle attack to monitor and capture SMB packets to extract hashes. This requires that SMB signing is disabled
	* The end goal for this attack is to capture authentication NTLM hashes for a victim
* LLMNR/NBNS Poisoning
	* Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) help local network machines to find the right machine if DNS fails.
	* NBNS/LLMNR Poisoning occurs when an attacker spoofs an authoritative source on the network and responds to the LLMNR and NBT-NS traffic to the requested host with host identification service.
	* The end goal is to capture authentication NTLM hashes for the victim