# Enumerating Active Directory

After getting AD credentials and using them to authenticate on the network, it is important to enumerate various details about the AD setup and structure, even if the access is only low-privilege.

This is important since it will eventually allow us to perform privilege escalation or lateral movement to gain even more access until we are able to reach our goal during a red team engagement.

## 1. Credential Injection Methods

Credentials are often found without compromising a domain-joined machine.

Therefore it is required to find a way to log in using these credentials so we can proceed with enumerating AD.

`Runas` = tool used if you have found AD credentials but don't know where to use them.

```powershell
> runas.exe /netonly /user:DOMAIN\USERNAME cmd.exe
```

## 2. Enumeration using Microsoft Management Console (MMC)

`MMC` is a GUI tool that provides an excellent way to gain an overview of the AD environment, and should we have sufficient privileges we can even use it to alter or add new AD objects. The downside is that since it's a GUI tool, we need RDP access to the machine.

## 3. Enumeration through Command Prompt

Command Prompt is best used when you need to perform quick AD lookups, especially when you don't have RDP access to a system or PowerShell use is monitored. It can be used to enumerate AD users, groups, password policy, etc.

## 4. Enumeration through PowerShell

PowerShell aka the upgrade of the Command Prompt. It can be used to enumerate AD users, groups, AD objects, domains. Additionally, it can be used to create or alter existing AD objects.

## 5. Enumeration through Bloodhound

`Bloodhound` - the most powerful AD enumeration tool to date; it is used to visualize the AD environment in a graph format with interconnected nodes.

`Sharphound` - although the name is used interchangeably with `Bloodhound`, `Sharphound` is the enumeration tool of `Bloodhound`, aka is used to enumerate the AD information which can then be visualised using `Bloodhound` GUI.

`Sharphound` consists of three different collectors - `Sharphound.ps1` (Powershell script), `Sharphound.exe` (windows executable version), `AzureHound.ps1` (Powershell script for Azure cloud computing services).