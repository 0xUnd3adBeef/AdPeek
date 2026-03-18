# AdPeek

![image](AdPeekIMG.png)

![PyPI](https://img.shields.io/pypi/v/adpeek-cli?label=pypi%20package)

AdPeek is a Python tool for extracting useful information from Active Directory over LDAP.

It focuses on fast enumeration and identifying ACL-based privilege paths without requiring a database or UI.

**Current version:** `v0.1.2`

---

## What it’s for

AdPeek is built for quick AD visibility when you want usable results without setting up heavier tooling.

* Fast LDAP enumeration
* Direct ACL inspection
* Inbound and outbound privilege visibility
* Output that stays readable

> [!TIP]
> Useful as a first pass before switching to graph-based tools.

---

## Features

### Enumeration

* Domain users
* Domain machines
* SPN users (Kerberoast targets)
* AS-REP roastable users

---

### ACL Analysis

* Outbound ACLs
  What a user, group, or machine can control

* Inbound ACLs (`findinboundacl`)
  Who has rights over a target

* Full ACE decoding including:

  * WriteDACL, WriteOwner, WriteProperty
  * AllExtendedRights
  * Password reset rights
  * DCSync-related rights
  * RBCD
  * Shadow Credentials
  * GMSA password access
  * SPN write access

> [!TIP]
> Inbound and outbound views together give a much clearer picture of privilege paths.

---

### Targeting

* `-tu` user targets
* `-tg` group targets
* `-tm` machine targets

---

### Output

* Minimal and readable
* Deduplicated ACL results
* Focus on high-impact rights

---

## Installation

```bash
pipx install adpeek-cli
```

> [!TIP]
> Keeps the tool isolated and avoids dependency issues.

---

## Usage

```bash
adpeek <command> [options]
```

**Options**

```
-dc <domain controller IP>
-d  <domain>
-u  <username>
-p  <password>
-tu <target user>
-tg <target group>
-tm <target machine>
```

> [!WARNING]
> Credentials are passed via CLI arguments. Be aware of shell history and process visibility.

---

## Examples

### Enumerating domain users

```bash
adpeek enumdomusers -dc 10.10.10.10 -u AC001 -p Password123 -d xundeadbeef.local
```

```
AdPeek v0.1.2

Enumerating domain users...

[ + ] - XUNDEADBEEF\Administrator - "CN=Administrator,CN=Users,DC=xundeadbeef,DC=local" - S-1-5-21-1000-1000-1000-500 - Enabled
[ - ] - XUNDEADBEEF\Guest        - "CN=Guest,CN=Users,DC=xundeadbeef,DC=local"        - S-1-5-21-1000-1000-1000-501 - Disabled
[ - ] - XUNDEADBEEF\krbtgt       - "CN=krbtgt,CN=Users,DC=xundeadbeef,DC=local"       - S-1-5-21-1000-1000-1000-502 - Disabled
[ + ] - XUNDEADBEEF\AC001        - "CN=AC001,OU=Finance,OU=Corp,DC=xundeadbeef,DC=local" - S-1-5-21-1000-1000-1000-1716 - Enabled
[ + ] - XUNDEADBEEF\BR214        - "CN=BR214,OU=Finance,OU=Corp,DC=xundeadbeef,DC=local" - S-1-5-21-1000-1000-1000-1717 - Enabled
[ + ] - XUNDEADBEEF\CT059        - "CN=CT059,CN=Users,DC=xundeadbeef,DC=local"           - S-1-5-21-1000-1000-1000-4611 - Enabled
```

---

### Enumerating domain machines

```bash
adpeek enumdommachines -dc 10.10.10.10 -u AC001 -p Password123 -d xundeadbeef.local
```

```
AdPeek v0.1.2

Enumerating domain machines...

[ + ] - XUNDEADBEEF\DC01$      - "CN=DC01,OU=Domain Controllers,DC=xundeadbeef,DC=local" - S-1-5-21-1000-1000-1000-1000
[ + ] - XUNDEADBEEF\SQL01$     - "CN=SQL01,CN=Computers,DC=xundeadbeef,DC=local"         - S-1-5-21-1000-1000-1000-1103
[ + ] - XUNDEADBEEF\WS-LAPTOP$ - "CN=WS-LAPTOP,CN=Computers,DC=xundeadbeef,DC=local"     - S-1-5-21-1000-1000-1000-1104
[ + ] - XUNDEADBEEF\DEV-SRV01$ - "CN=DEV-SRV01,CN=Computers,DC=xundeadbeef,DC=local"     - S-1-5-21-1000-1000-1000-1105
```

---

### Checking group membership

```bash
adpeek checkgroup -tu Administrator -dc 10.10.10.10 -u AC001 -p Password123 -d xundeadbeef.local
```

```
[ + ] - XUNDEADBEEF\Administrator - "CN=Administrator,CN=Users,DC=xundeadbeef,DC=local" - S-1-5-21-1000-1000-1000-500
 -> Group Policy Creator Owners
 -> Domain Admins
 -> Enterprise Admins
 -> Schema Admins
 -> Administrators
```

---

### Outbound ACLs

```bash
adpeek findinterestingacl -tu CT059 -dc 10.10.10.10 -u AC001 -p Password123 -d xundeadbeef.local
```

```
AdPeek v0.1.2

Finding interesting ACL-based rights for target user (including group-based)...

[ * ] Target user: XUNDEADBEEF\CT059
      DN  : CN=CT059,CN=Users,DC=xundeadbeef,DC=local
      SIDs considered (user + groups): 1

[ * ] Scanning DACLs for ACEs involving these SIDs...

=== Interesting ACL rights for XUNDEADBEEF\CT059 ===

CT059 -> AllExtendedRights -> CN=Administrator,CN=Users,DC=xundeadbeef,DC=local
CT059 -> WriteProperty     -> CN=Administrator,CN=Users,DC=xundeadbeef,DC=local
CT059 -> WRITE_DAC         -> CN=Administrator,CN=Users,DC=xundeadbeef,DC=local
CT059 -> WRITE_OWNER       -> CN=Administrator,CN=Users,DC=xundeadbeef,DC=local
```

> [!IMPORTANT]
> All privileges might not be shown !

---

### Inbound ACLs (who controls the target)

```bash
adpeek findinboundacl -tu CT059 -dc 10.10.10.10 -u AC001 -p Password123 -d xundeadbeef.local
```

```
AdPeek v0.1.2

Finding inbound ACL-based rights...

Target: XUNDEADBEEF\CT059

Administrator -> GenericAll      -> CT059
HELPDESK      -> ResetPassword   -> CT059
```

---

### SPN users

```bash
adpeek enumspnusers -dc 10.10.10.10 -u AC001 -p Password123 -d xundeadbeef.local
```

```
Enumerating SPN users...

[ + ] XUNDEADBEEF\SQL02   - CN=SQL02,OU=Servers,DC=xundeadbeef,DC=local
      SPN: MSSQLSvc/sql02.xundeadbeef.local:1433

[ + ] XUNDEADBEEF\WEBAPP  - CN=WEBAPP,OU=Servers,DC=xundeadbeef,DC=local
      SPN: HTTP/webapp.xundeadbeef.local
```

---

### AS-REP roastable users

```bash
adpeek enumasreproastusers -dc 10.10.10.10 -u AC001 -p Password123 -d xundeadbeef.local
```

```
Enumerating AS-REP roastable users...

[ + ] XUNDEADBEEF\SRVBACKUP - CN=SRVBACKUP,OU=Service,DC=xundeadbeef,DC=local
      (DONT_REQ_PREAUTH set)
```

---

## Notes

> [!NOTE]
>
> * Active development
> * Intended for testing and assessments
