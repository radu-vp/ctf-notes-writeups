# Active Directory Basics

## Active Directory

Components:

* Servers & machines on-premise - these can be anything from Domain Controllers (DCs) and storage servers to domain user machines; everything needed for an AD environment besides the software
* `Domain Controllers` (DCs) - Windows server that has Active Directory Domain Services (AD DS) installed and has been promoted to a domain controller in the forest. DCs are the center of AD, controlling the rest of the domain.
* `AD DS Data Store` - holds the databases and processes needed to store and manage directory information such as users, groups, and services.

The core of any Windows Domain is the Active Directory Domain Service (AD DS). This service holds the information of all the "objects" that exist on the network, such as:

* `Users` - the most common AD objects. Users are one of the objects known as security principals, meaning that they can be authenticated by the domain and can be assigned privileges over resources. Users can be one of two types of entities:
	* People - employees of the organisation
	* Services - users defined to be used for services like IIS or MSSQL
* `Machines` - Every computer joined to the AD domain has a machine object created.Machines are also considered security principals, which means they are assigned an account just as any other user, but with limited rights, which functions as a local admin account for each machine
* `Security Groups` - User groups defined to assign access rights to files or other resources. Groups can have both users and machines as members, as well as other groups. The groups created by default are:
	* Domain Admins
	* Server Operators
	* Backup Operators
	* Account Operators
	* Domain Users
	* Domain Computers
	* Domain Controllers

## Active Directory Users and Computers

Users, groups or machines can be configured in AD by logging into the DC and running `Active Directory Users and Computers` GUI utility.

This tool groups users, computers and groups that exist on the domain in a hierarchy. These are typically referred to as objects and are organised in `Organizational Units` (OUs). They are container objects, mainly used to define sets of users with similar policing requirements.

Security Groups vs OUs:

* `OUs` are useful in applying policies to users and computers, which include specific configurations that are relevant to their role in the organization. A user can only be a member of a single OU at a time
* `Security Groups` are used to grant permissions over resources. Such as if you want to allow some users to access a shared folder it would be done by granting permissions as part of a Security Groups. A user can be part of many groups, which is good since they usually need to access multiple resources

## Group Policies

Since users and computers are organised in OUs, it allows us to deploy different policies for each of these OU individually.

Such policies are managed by Windows using the Group Policy Objects (GPO). They are a collection of settings that can be applied to OUs. They also enable setting a baseline policy on specific machines and identities.

GPOs are distributed to the network via a network share called `SYSVOL` which is stored on the DC. All users in domain should typically have access to this share over the network to sync their GPOs periodically.

## Authentication Models

When using Windows domains, all credentials are stored in the Domain Controller (DC). Authentication to a service using domain credentials will always require that the DC checks credentials to see if they are correct. There are two protocols used for network authentication:

* Kerberos - the default protocol in the latest versions
* NetNTLM - legacy authentication protocol kept for compatibility purposes

Authentication using Kerberos revolves around tickets that function as proof of previous authentication. Users present tickets to a service to demonstrate they have already authenticated into the network. Kerberos authentication steps:

1. A user sends their username and a timestamp encrypted using a key derived from their password to the Key Distribution Center (KDC) - usually on the DC
2. KDC creates and sends back an encrypted Ticket Granting Ticket (TGT), which allows the user to request additional tickets to access specific services. Along with the TGT, a Session Key is given to the user, which they need to generate requests after this step
	* The TGT is encrypted with the `krbtgt` account's password hash, meaning the user cannot access its contents
3. When the user wants to connect to a  service on the network, they use the TGT to ask the KDC for a Ticket Granting Service (TGS). TGS tickets are tickets that allow connection only to the specific service that they were created for.
	* The TGS is created if the user submits their username and a timestamp encrypted using the Session Key, along with the TGT and a Service Principal Name (SPN), which indicates the service and server name we intend to access
4. The KDC will send back a TGS along with a Service Session Key, which the user needs to authenticate to the service they want to access
	* The TGS is encrypted using a key derived from the Service Owner hash. The Service Owner is the user or machine account that the service runs under
5. The TGS can then be sent to the desired service to authenticate and establish a connection. The service will use its configured account's password hash to decrypt the TGS and validate the Service Session Key

Authentication using the NetNTLM protocol is based on a challenge-response mechanism. NetNTLM authentication steps:

1. The client sends an authentication request to the server they want to access
2. The server generates a random number and sends it as a challenge to the client
3. The client combines their NTLM password hash with the challenge (and other known data) to generate a response to the challenge and sends it back to the server for verification
4. The server forwards the challenge and the response to the DC for verification
5. The DC uses the challenge to recalculate the response and compares it to the original response sent by the client. If they both match, the client is authenticated; otherwise, access is denied. The authentication result is sent back to the server
6. The server forwards the authentication result to the client

## Trees, Forests and Trusts

Trees - the integration of multiple domains in a network by joining two domains that share the same namespace. (e.g.: if the domain `thm.local` is split into two subdomains `uk.thm.local` and `us.thm.local`, it could be build into a tree with the root domain of `thm.local` and 2 subdomains)

Forest - Domains can also be configured in different namespaces. The union of several trees with different namespaces into the same network is known as a forest.

Trust relationships refers to the trust between domains organised in trees and forests:

* One-way trust relationship - if Domain A trusts Domain B, this means that users on Domain B can be authorised to access resources on Domain A but not the other way around
* Two-way trust relationships - allow two domains to mutually authorise users from the other. By default, joining several domains under a tree or a forest will form a two-way trust relationship