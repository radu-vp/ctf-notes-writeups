# Persisting Active Directory

AD persistence is part of the cycle of compromising AD. This ensures if one of our entry points is detected, we still maintain access to the systems.

Persistence techniques depend on the specific permissions and privileges of the users that we have compromised during a red team engagement.

## Persistence through Credentials

Usually, organizations do not rely on a single domain controller. Since organizations have multiple regional locations, the domains must follow this model. But it is also required that a user can authenticate using the same credentials in different locations.

To enable this type of authentication, AD relies on domain replications. Every DC runs a process called the Knowledge Consistency Checker (KCC), which generates a replica topology of the AD forest and connects to other DCs through Remote Procedure Calls (RPC) to synchronise information. This includes updated information such as if a user has a new password or if new objects have been added. This replication process is called DC Synchronisation (DC Sync).

A popular way to establish persistence is using a DC Sync attack, which can be done if we have access to an account that has domain replication permissions.

## Persistence through Tickets

Kerberos Authentication:

* The user makes an AS-REQ to the Key Distribution Centre (KDC) on the DC that includes a timestamp encrypted with the user's NTLM hash - this is the request for a Ticket Granting Ticket (TGT)
* The DC checks the information and sends the TGT to the user
* The TGT is signed with the KRBTGT account's password hash that is only stored on the DC
* The user can now send this TGT to the DC to request a Ticket Granting Service (TGS) for the resource that the user wants to access
* If the TGT checks out, the DC responds to the TGS that is encrypted with the NTLM hash of the service that the user is requesting access for. The user then presents this TGS to the service for access, which can verify the TGS since it knows its own hash and can grant the user access.

**Golden Tickets** are forged TGTs, meaning they bypass steps 1 and 2 of the authentication, where we prove the user's identity to the DC. If we have a valid TGT of a privileged account, we can request a TGS for almost any service we want. To forge a Golden Ticket, we need the KRBTGT account's password hash so that we can sign a TGT for any user account we want.

**Silver Tickets** are forged TGS, meaning they skip all communication from step 1 through 4 that we normally have with the KDC on the DC, and we interface directly with the service we want to access.

## Persistence through Certificates

If we have administrator access, we can steal the private key of the root CA's certificate to generate our own certificates to use as required. Additionally, since these certificates were not issued by the CA, they cannot be revoked.

## Persistence through SID History

Security Identifiers (SIDs) are used to track the security principal and the account's access when connecting to resource. The SID history is an attribute for accounts that can be used to enable access for an account to be cloned to another.

SID history is useful for migrations, such as when an organization is performing an AD migration, as it allows users to retain access to the original domain while they are migrated to the new one. In this new domain, the user would have a new SID, but we can add the user's existing SID in the SID history, meaning they can have access to resources in the previous domain using their new account.

## Persistence through Group Membership

A lot of organisations need to use a significant amount of recursive groups, which refers to groups that are members of another group. This is also referred to as group nesting.

Nested Groups are commonly used to maintain an organized AD structure. An example would be a group called "IT Support", which might contain subgroups such as "Helpdesk", "Access Card Managers", and "Network Managers".

This presents a monitoring problem, since the blue team might get alerted when a new member is added to the Domain Admins group, however it won't receive an alert if a user is added to a subgroup within the Domain Admins Group.

## Persistence through ACLs

Persisting through AD Group Templates - such as the AdminSDHolder container. This is a container that is found in all AD domains, and its Access Control List (ACL) is used as a template to copy permissions to all protected groups (which includes privileged groups such as Domain Admins, Administrators, Enterprise Admins, Schema Admins, etc.)

A process called SDProp Takes the ACL of the AdminSDHolder container and applies it to all protected groups every 60 minutes. This means that we can write an Access Control Entry (ACE) that will grant us full permissions on all protected groups.

## Persistence through GPOs

Persistence through Group Policy Objects (GPOs) can be used to gain domain wide persistence. Additionally, an attacker can often hide the GPO in such a way that it becomes almost impossible to remove it. Common techniques are:

* Restricted Group Membership - This could allow us administrative access to all hosts in the domain
* Logon Script Deployment - This will ensure that we get a shell callback every time a user authenticates to a host in the domain