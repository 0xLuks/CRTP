# Certified Red Team Professional (Pentester Academy)

Cheatsheet for the [CRTP exam](https://www.pentesteracademy.com/activedirectorylab)

*All the commands below have been tested.*

:heart: Powershell

# Summary

 - [Domain Enumeration](#-domain-enumeration)
   - [Domain](#-domain)
   - [Users](#-users)
   - [Computers](#-computers)
   - [Groups](#-groups)
   - [Logged-in users](#-logged-in-users)
   - [Share and sensitive files](#-share-and-sensitive-files)
   - [Group policy objects](#-group-policy-objects)
 * [Local Privilege Escalation](#-local-privilege-escalation)
 * [BloodHound](#-bloodhound)
 * [Lateral Movement](#-lateral-movement)
 * [Domain PrivEsc](#-domain-privesc)
 * [Domain Persistence](#-domain-persistence)
 * [Enterprise PrivEsc](#-enterprise-privesc)
 * [Enterprise Persistence](#-enterprise-persistence)
 * [Cross Forest Attacks](#-cross-forest-attacks)
 * [Detection And Defense](#-detection-and-defense)

## [](#summary) Domain Enumeration

Two ways:
- [Powerview](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) - `@harmj0y`
- [AD Module](https://github.com/samratashok/ADModule) - `@nikhil_mitt`

### [](#-domain) Domain

| Powerview | AD Module | Information |
|-----------|-----------|-------------|
| `Get-NetDomain` | `Get-ADDomain` | domain |
| `Get-NetDomain -Domain {DOMAIN}` | `Get-ADDomain -Identity {DOMAIN}` | other domain |
| `Get-DomainSID` | `(Get-ADDomain).DomainSID` | domain SID |
| `Get-DomainPolicy` | / | domain policy |
| `Get-DomainPolicy -Domain {DOMAIN}` | / | policy for another domain |
| `Get-NetDomainController` | `Get-ADDomainController` | domain controllers |
| `Get-NetDomainController -Domain {DOMAIN}` | `Get-ADDomainController -DomainName {DOMAIN} -Discover` | domain controllers for another domain |

### [](#-users) Users

| Powerview | AD Module | Information |
|-----------|-----------|-------------|
| `Get-NetUser` | `Get-ADUser -Filter * -Properties *` | domain users |
| `Get-NetUser -UserName {USER}` | `Get-ADUser -Identity {USER} -Properties *` | specific user |
| `Get-UserProperty` | `Get-ADUser -Filter * -Properties * \| select -First 1 \| Get-Member -MemberType *Property \| select Name` | list user properties |
| `Get-UserProperty -Properties {PROPERTY}` | `Get-ADUser -Filter * -Properties * \| select name,@{expression={[datetime]::fromFileTime($_.{PROPERTY})}}` | specific property |

### [](#-computers) Computers

| Powerview | AD Module | Information |
|-----------|-----------|-------------|
| `Get-Netcomputer` | `Get-ADComputer -Filter * \| select Name` | domain computers |
| `Get-NetComputer -OperatingSystem "*Server 2016*"` | `Get-ADComputer -Filter 'OperatingSystem -like "*Server 2016*"' -Properties OperatingSystem \| select Name,OperatingSystem` | list the machines whose OS is server 2016 |
| `Get-NetComputer -Ping` | `Get-ADComputer -Filter * -Properties DNSHostName \| %{Test-Connection -Count 1 -ComputerName $_.DNSHostName}` | ping hosts |
| `Get-NetComputer -FullData` | `Get-ADComputer -Filter * -Properties *` | get all properties |

### [](#-groups) Groups

| Powerview | AD Module | Information |
|-----------|-----------|-------------|
| `Get-Netgroup` | `Get-ADGroup -Filter * \| select Name` | domain groups |
| `Get-Netgroup -Domain {DOMAIN}` | `/` | domain groups for another domain |
| `Get-Netgroup -FullData` | `Get-ADGroup -Filter * -Properties *` | all properties |
| `Get-Netgroup *{WORD}*` | `Get-ADGroup -Filter 'Name -like "*{WORD}*"' \| select Name` | get all groups containing a particular word in the name |
| `Get-NetGroupMember -GroupName "{GROUP}" -Recurse` | `Get-ADGroupMember -Identity "{GROUP}" -Recursive` | get all members of a group |
| `Get-NetGroup -UserName {USER}` | `Get-ADPrincipalGroupMembership -Identity {USER}` | list the groups of a user |
| `Get-NetLocalGroup -ComputerName {TARGET} -ListGroups` | `/` | list all the local groups on a machine :warning: need admin priv |
| `Get-NetLocalGroup -ComputerName {TARGET} -Recurse` | `/` | get members of all the local groups on a machine :warning: need admin priv |

### [](#-logged-in-users) Logged-in users

| Powerview | Information |
|-----------|-----------|
| `Get-NetLoggedon -ComputerName {TARGET}` | return the logged users on a local (or a remote) machine :warning: need admin priv |
| `Get-LoggedonLocal -ComputerName {TARGET}` | get locally loggued users on a machine :warning: need remote registry |
| `Get-LastLoggedOn -ComputerName {TARGET}` | get the last loggued user on a machine :warning: need admin priv and remote registry |

### [](#-share-and-sensitive-files) Share and sensitive files

| Powerview | Information |
|-----------|-----------|
| `Invoke-ShareFinder -Verbose` | finds (non-standard) shares on hosts in the local domain |
| `Invoke-FileFinder -Verbose` | find sensitive files on hosts in the local domain |
| `Get-NetFileServer` | get a list of file servers used by current domain users |

### [](#-group-policy-objects) Group policy objects

#### What's a GPO ?

[Wiki](https://en.wikipedia.org/wiki/Group_Policy)

## [↑](#table-of-contents) Local Privilege Escalation

## [↑](#table-of-contents) BloodHound

## [↑](#table-of-contents) Lateral Movement

## [↑](#table-of-contents) Domain PrivEsc

## [↑](#table-of-contents) Domain Persistence

## [↑](#table-of-contents) Enterprise PrivEsc

## [↑](#table-of-contents) Enterprise Persistence

## [↑](#table-of-contents) Cross Forest Attacks

## [↑](#table-of-contents) Detection And Defense

