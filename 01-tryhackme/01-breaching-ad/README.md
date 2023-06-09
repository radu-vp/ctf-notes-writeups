# Breaching Active Directory

Before exploiting AD misconfigurations for privilege escalation, lateral movement, and goal execution, you need initial access.

Initial access means acquiring and making use of an initial set of valid AD credentials.

## 1. OSINT and Phishing

By using OSINT techniques, it may be possible to recover publicly disclosed credentials. These credentials can be tested (such as by using NTLM Authenticated Services) to see whether they are valid or not since they can be outdated.

Alternatively, phishing usually entices users to either provide their credentials on a malicious application or can make them install tools that can provide a backdoor for the attacker.

## 2. NTLM Authenticated Services

NTLM and NetNTLM

#### 2.1. Brute-force Login Attacks / Password Spraying

* Brute-force Attack = attack that attempts to gain unauthorized access to a single account by guessing the password
* Password Spraying = attack that attempts to access a large number of accounts (usernames) with a few commonly used password
* These type of attack can be performed using tools such as `Hydra` or you could make a custom script as needed

## 3. LDAP Binding Credentials

* LDAP = authentication mechanism popular with applications that integrate with AD, such as Gitlab, Jenkins, Printers, VPNs, etc.
* LDAP Pass-back Attacks = attack that can be performed against LDAP authentication mechanisms. This is commonly done against network devices, such as printers, when you have gained initial access to the internal network, such as plugging in a rogue device in a boardroom.

## 4. Authentication Relays

Server Message Block (SMB) - Exploiting NetNTLM authentication with SMB:

* NTLM Challenges can be intercepted - which means we can use offline cracking techniques to recover the password associated with the NTLM Challenge
	* This method is slower than cracking NTLM hashes directly
* Use rogue device to stage a Man-in-the-Middle attack, relaying the SMB authentication between the client and server - will provide us with an active authenticated session and access to the target server

## 5. Microsoft Deployment Toolkit

Organizations likely use of tools to deploy and manage their infrastructure, since it would be very time consuming to install software manually on every single machine. Commonly used tools are:

* Microsoft Deployment Toolkit (MDT) = Microsoft service that helps automating the deployment of the OS - usually used for new deployments
* Microsoft's System Center Configuration Manager (SCCM) = patch management, helps IT review available updates to all software installed across the infrastructure, test patches in a sandbox environment, etc.
* PXE Boot = allows new devices that are connected to the network to load and install the OS directly over a network connection. It downloads a PXE boot image, and it can be exploited by:
	* Injecting a privilege escalation vector, such as a Local Administrator account
	* Perform password scraping attacks to recover AD credentials used during the install

## 6. Configuration Files

Different configuration files can be important for enumeration, such as:

* Web application configuration files
* Service configuration files
* Registry keys
* Centrally deployed applications