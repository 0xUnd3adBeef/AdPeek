# AdPeek
![image](AdPeekIMG.png)


AdPeek is a small Python tool for extracting useful information from Active Directory over LDAP.
It focuses on fast enumeration and identifying misconfigured ACL paths without requiring a database or GUI (Poor man's bloodhound-ce).

Current version: `v0.1.2`

---
## Why AdPeek?

AdPeek is built for operators who want quick, effective AD intelligence without dragging around heavy tooling. It delivers the essentials:\
Fast LDAP enumeration of users, machines, SPNs, and AS-REP roastables\
Direct ACL checks that show escalation paths like WriteDACL, WriteOwner, password-reset rights, RBCD, and Shadow Credentials\
Inbound/outbound access checks to show who a target can control and who can control them\
Output that’s short and immediately useful\
AdPeek aims to keep things simple.

---
## Features

* Enumerate domain users
* Enumerate domain machines
* List SPN users (Kerberoastable)
* List AS-REP roastable users
* Check group membership
* Identify interesting ACL-based privilege paths (WriteProperty, WriteOwner, WriteDACL, AllExtendedRights, etc.)

Output is minimal and designed for quick consumption during reconnaissance.

---

## Installation

### **Using `pipx` (recommended)**

`pipx` installs AdPeek in an isolated environment and exposes the `adpeek` command globally.

```bash
pipx install adpeek-cli
```

After installation, run:

```bash
adpeek --help
```

---

### **Using `pip` (not recommended, works too)**

```bash
python3 -m pip install --user adpeek-cli
```

Make sure `~/.local/bin` is on your PATH:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

---

### **Upgrade to the latest version**

```bash
pipx upgrade adpeek-cli
```

or:

```bash
python3 -m pip install --upgrade adpeek-cli
```

---

### **Uninstall**

```bash
pipx uninstall adpeek-cli
```

or:

```bash
python3 -m pip uninstall adpeek-cli
```

---
## Usage

```
./adpeek.py <command> [options]

Options:
    -dc <domain controller IP>
    -d  <domain>
    -u  <username>
    -p  <password>
    -tu <target user>         (for commands that require one)
```

Run the tool without arguments to display the command list.

---

# Examples

---

## Enumerating domain users

```
$ ./adpeek.py enumdomusers -dc 10.10.10.10 -u AC001 -p Password123 -d xundeadbeef.local
AdPeek v0.0.1dev - Made by 0xUnd3adBeef

Enumerating domain users...
[ + ] - XUNDEADBEEF\Administrator - "CN=Administrator,CN=Users,DC=xundeadbeef,DC=local" - S-1-5-21-1000-1000-1000-500 - Enabled
[ - ] - XUNDEADBEEF\Guest        - "CN=Guest,CN=Users,DC=xundeadbeef,DC=local"        - S-1-5-21-1000-1000-1000-501 - Disabled
[ - ] - XUNDEADBEEF\krbtgt       - "CN=krbtgt,CN=Users,DC=xundeadbeef,DC=local"       - S-1-5-21-1000-1000-1000-502 - Disabled
[ + ] - XUNDEADBEEF\AC001        - "CN=AC001,OU=Finance,OU=Corp,DC=xundeadbeef,DC=local" - S-1-5-21-1000-1000-1000-1716 - Enabled
[ + ] - XUNDEADBEEF\BR214        - "CN=BR214,OU=Finance,OU=Corp,DC=xundeadbeef,DC=local" - S-1-5-21-1000-1000-1000-1717 - Enabled
[ + ] - XUNDEADBEEF\CT059        - "CN=CT059,CN=Users,DC=xundeadbeef,DC=local"           - S-1-5-21-1000-1000-1000-4611 - Enabled
```

---

## Enumerating domain machines

```
$ ./adpeek.py enumdommachines -dc 10.10.10.10 -u AC001 -p Password123 -d xundeadbeef.local
AdPeek v0.0.1dev - Made by 0xUnd3adBeef

Enumerating domain machines...

[ + ] - XUNDEADBEEF\DC01$        - "CN=DC01,OU=Domain Controllers,DC=xundeadbeef,DC=local" - S-1-5-21-1000-1000-1000-1000
[ + ] - XUNDEADBEEF\SQL01$       - "CN=SQL01,CN=Computers,DC=xundeadbeef,DC=local"         - S-1-5-21-1000-1000-1000-1103
[ + ] - XUNDEADBEEF\WS-LAPTOP$   - "CN=WS-LAPTOP,CN=Computers,DC=xundeadbeef,DC=local"     - S-1-5-21-1000-1000-1000-1104
[ + ] - XUNDEADBEEF\DEV-SRV01$   - "CN=DEV-SRV01,CN=Computers,DC=xundeadbeef,DC=local"     - S-1-5-21-1000-1000-1000-1105
```

---

## Checking group membership

### Regular user

```
$ ./adpeek.py checkgroup -tu CT059 -dc 10.10.10.10 -u AC001 -p Password123 -d xundeadbeef.local

Checking groups for (CT059)
[ - ] - XUNDEADBEEF\CT059 - "CN=CT059,CN=Users,DC=xundeadbeef,DC=local" - S-1-5-21-1000-1000-1000-4611
 -> None
```

### Administrator

```
$ ./adpeek.py checkgroup -tu Administrator -dc 10.10.10.10 -u AC001 -p Password123 -d xundeadbeef.local

[ + ] - XUNDEADBEEF\Administrator - "CN=Administrator,CN=Users,DC=xundeadbeef,DC=local" - S-1-5-21-1000-1000-1000-500
 -> Group Policy Creator Owners
 -> Domain Admins
 -> Enterprise Admins
 -> Schema Admins
 -> Administrators
```

---

## Finding interesting ACL rights

```
$ ./adpeek.py findinterestingacl -tu CT059 -dc 10.10.10.10 -u AC001 -p Password123 -d xundeadbeef.local
AdPeek v0.0.1dev - Made by 0xUnd3adBeef

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

---

## SPN Users

```bash
$ ./adpeek.py enumspnusers -dc 10.10.10.10 -u AC001 -p Password123 -d xundeadbeef.local

Enumerating SPN users...

[ + ] XUNDEADBEEF\SQL02   - CN=SQL02,OU=Servers,DC=xundeadbeef,DC=local
      SPN: MSSQLSvc/sql02.xundeadbeef.local:1433

[ + ] XUNDEADBEEF\WEBAPP  - CN=WEBAPP,OU=Servers,DC=xundeadbeef,DC=local
      SPN: HTTP/webapp.xundeadbeef.local
```

---

## AS-REP Roastable Users

```bash
$ ./adpeek.py enumasreproastusers -dc 10.10.10.10 -u AC001 -p Password123 -d xundeadbeef.local

Enumerating AS-REP roastable users...

[ + ] XUNDEADBEEF\SRVBACKUP - CN=SRVBACKUP,OU=Service,DC=xundeadbeef,DC=local
      (DONT_REQ_PREAUTH set)
```

---

# Notes

* AdPeek is in active development.
* Output formats may change as functionality expands.
* Intended for testing environments and research.

---

# Author

Created by **0xUnd3adBeef**
If it breaks, you get to keep both pieces.
