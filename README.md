# Certified Red Team Professional (Pentester Academy)

Cheatsheet for the [CRTP exam](https://www.pentesteracademy.com/activedirectorylab)

*All the commands below have been tested.*

# Summary

 - [Domain Enumeration](#-domain-enumeration)
   - [Domain](#-domain)
   - [Users](#-users)
   - [Computers](#-computers)
   - [Groups](#-groups)
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

Soon

## [↑](#table-of-contents) Local Privilege Escalation

## [↑](#table-of-contents) BloodHound

## [↑](#table-of-contents) Lateral Movement

## [↑](#table-of-contents) Domain PrivEsc

## [↑](#table-of-contents) Domain Persistence

## [↑](#table-of-contents) Enterprise PrivEsc

## [↑](#table-of-contents) Enterprise Persistence

## [↑](#table-of-contents) Cross Forest Attacks

## [↑](#table-of-contents) Detection And Defense

