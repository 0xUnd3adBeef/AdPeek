#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import argparse
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
from ldap3.core.exceptions import LDAPException, LDAPSocketOpenError
from ldap3.protocol.microsoft import security_descriptor_control
import struct
import uuid
from collections import defaultdict, deque
# adpeek/cli.py
from . import __version__

BANNER = f"AdPeek v{__version__} - Brought to you by 0xUnd3adBeef\n"
print(BANNER)


# ---------- general helpers ----------

def sid_to_string(sid_value):
    if sid_value is None:
        return "N/A"
    if isinstance(sid_value, str):
        return sid_value

    sid_bytes = bytes(sid_value)
    if len(sid_bytes) < 8:
        return "Invalid SID"

    revision = sid_bytes[0]
    sub_authority_count = sid_bytes[1]
    authority = int.from_bytes(sid_bytes[2:8], byteorder="big")

    sub_authorities = []
    for i in range(sub_authority_count):
        start = 8 + (i * 4)
        end = start + 4
        if end > len(sid_bytes):
            break
        sub_auth = int.from_bytes(sid_bytes[start:end], byteorder="little")
        sub_authorities.append(str(sub_auth))

    sid_str = f"S-{revision}-{authority}"
    if sub_authorities:
        sid_str += "-" + "-".join(sub_authorities)
    return sid_str

def connect_to_ad(domain, dc, username, password):
    netbios_domain = domain.split(".")[0].upper()
    login_user = f"{netbios_domain}\\{username}"
    try:
        server = Server(dc, get_info=ALL)
        conn = Connection(
            server,
            user=login_user,
            password=password,
            authentication=NTLM,
            auto_bind=True,
        )
        return conn, netbios_domain
    except (LDAPSocketOpenError, LDAPException):
        return None, netbios_domain

def get_base_dn(conn):
    conn.search(
        search_base="",
        search_filter="(objectClass=*)",
        search_scope="BASE",
        attributes=["*"],
    )
    if not conn.entries:
        return None

    entry = conn.entries[0]
    if "defaultNamingContext" in entry:
        return entry["defaultNamingContext"].value
    if "namingContexts" in entry and entry["namingContexts"].values:
        return entry["namingContexts"].values[0]
    return None

def is_disabled(user_account_control):
    """
    userAccountControl is an int bitmask.
    Bit 0x2 (2) means 'ACCOUNTDISABLE'.
    """
    try:
        uac = int(user_account_control)
    except (TypeError, ValueError):
        return False
    return bool(uac & 0x2)

# ---- helper: SID string "S-1-5-21-..." -> binary SID bytes ----
def sid_string_to_bytes(sid_str):
    parts = sid_str.split("-")
    if parts[0] != "S":
        raise ValueError("Invalid SID format")

    revision = int(parts[1])
    authority = int(parts[2])
    subauth = [int(x) for x in parts[3:]]

    sid_bytes = struct.pack("BB", revision, len(subauth))
    sid_bytes += authority.to_bytes(6, byteorder="big")

    for sa in subauth:
        sid_bytes += struct.pack("<I", sa)

    return sid_bytes

# ---- helper: parse SD -> DACL info ----
def get_dacl_info(sd_bytes):
    # SECURITY_DESCRIPTOR_RELATIVE is at least 20 bytes
    if len(sd_bytes) < 20:
        return None

    # DACL offset is at byte 16 (4 bytes, little-endian)
    dacl_offset = struct.unpack_from("<I", sd_bytes, 16)[0]
    if dacl_offset == 0:
        return None
    if len(sd_bytes) < dacl_offset + 8:
        return None

    # ACL header at DACL offset:
    # 0-1: AclRevision + Sbz1
    # 2-3: AclSize
    # 4-5: AceCount
    # 6-7: Sbz2
    acl_size = struct.unpack_from("<H", sd_bytes, dacl_offset + 2)[0]
    ace_count = struct.unpack_from("<H", sd_bytes, dacl_offset + 4)[0]
    return dacl_offset, acl_size, ace_count

# ---- helper: decode rights from mask + objectType GUID ----
def decode_ace_rights(access_mask, object_type_guid_bytes):
    """
    Decode access_mask + optional objectType GUID into human-readable rights.

    Covers:
      - Generic & standard rights (GenericAll, GenericWrite, WriteDacl, WriteOwner, ...)
      - DS-specific flags (ReadProperty, WriteProperty, Self, AllExtendedRights, ...)
      - High-value extended rights (ResetPassword, DCSync, Validated-SPN, LAPS, ...)
      - High-value attribute/object writes (RBCD, gMSA password, shadow creds, SPN, self-membership)
    """

    # ----- Generic rights -----
    GENERIC_READ    = 0x80000000
    GENERIC_WRITE   = 0x40000000
    GENERIC_EXECUTE = 0x20000000
    GENERIC_ALL     = 0x10000000

    # ----- Standard rights -----
    DELETE       = 0x00010000
    READ_CONTROL = 0x00020000
    WRITE_DAC    = 0x00040000
    WRITE_OWNER  = 0x00080000

    # ----- Directory-service specific rights -----
    ADS_RIGHT_DS_CREATE_CHILD   = 0x00000001
    ADS_RIGHT_DS_DELETE_CHILD   = 0x00000002
    ADS_RIGHT_DS_LIST           = 0x00000004
    ADS_RIGHT_DS_SELF           = 0x00000008
    ADS_RIGHT_DS_READ_PROP      = 0x00000010
    ADS_RIGHT_DS_WRITE_PROP     = 0x00000020
    ADS_RIGHT_DS_LIST_OBJECT    = 0x00000080
    ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100

    rights = []

    # ----- Generic / standard flags -----
    if access_mask & GENERIC_ALL:
        rights.append("GenericAll")
    if access_mask & GENERIC_WRITE:
        rights.append("GenericWrite")
    if access_mask & GENERIC_READ:
        rights.append("GenericRead")
    if access_mask & GENERIC_EXECUTE:
        rights.append("GenericExecute")

    if access_mask & DELETE:
        rights.append("Delete")
    if access_mask & READ_CONTROL:
        rights.append("ReadDacl")
    if access_mask & WRITE_DAC:
        rights.append("WriteDacl")
    if access_mask & WRITE_OWNER:
        rights.append("WriteOwner")

    # ----- DS-specific base flags -----
    if access_mask & ADS_RIGHT_DS_CREATE_CHILD:
        rights.append("CreateChild")
    if access_mask & ADS_RIGHT_DS_DELETE_CHILD:
        rights.append("DeleteChild")
    if access_mask & ADS_RIGHT_DS_LIST:
        rights.append("List")
    if access_mask & ADS_RIGHT_DS_SELF:
        rights.append("Self")
    if access_mask & ADS_RIGHT_DS_READ_PROP:
        rights.append("ReadProperty")
    if access_mask & ADS_RIGHT_DS_WRITE_PROP:
        rights.append("WriteProperty")
    if access_mask & ADS_RIGHT_DS_LIST_OBJECT:
        rights.append("ListObject")
    if access_mask & ADS_RIGHT_DS_CONTROL_ACCESS:
        rights.append("AllExtendedRights")

    # Convert objectType GUID to string if present / non-null
    object_guid_str = None
    if object_type_guid_bytes:
        try:
            if any(b != 0 for b in object_type_guid_bytes):
                import uuid
                object_guid_str = str(uuid.UUID(bytes_le=bytes(object_type_guid_bytes))).lower()
        except Exception:
            object_guid_str = None

    # ----- Extended rights (CONTROL_ACCESS with rightsGuid) -----
    # These fire when ADS_RIGHT_DS_CONTROL_ACCESS is set AND the GUID matches.
    ext_rights_map = {
        # Password reset / change
        # User-Force-Change-Password (Reset Password)
        "00299570-246d-11d0-a768-00aa006e0529": [
            "ResetPassword",
            "User-Force-Change-Password",
        ],
        # User-Change-Password
        "ab721a53-1e2f-11d0-9819-00aa0040529b": [
            "ChangePassword",
            "User-Change-Password",
        ],

        # DCSync (replication rights) – these three together on the domain NC = full DCSync
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": [
            "DS-Replication-Get-Changes",
            "DCSync",
        ],
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": [
            "DS-Replication-Get-Changes-All",
            "DCSync",
        ],
        "89e95b76-444d-4c62-991a-0facbeda640c": [
            "DS-Replication-Get-Changes-In-Filtered-Set",
            "DCSync",
        ],

        # Validated write to SPN (also connected to SPN abuses)
        "f3a64788-5306-11d1-a9c5-0000f80367c1": [
            "Validated-SPN",
            "ValidatedWriteSPN",
        ],

        # Reanimate deleted schema objects
        "45ec5156-db7e-47bb-b53f-dbeb2d03c40f": [
            "Reanimate-Tombstones",
        ],

        # Windows LAPS (new) – extended right that guards encrypted LAPS password attributes
        "f3531ec6-6330-4f8e-8d39-7a671fbac605": [
            "LAPS-Encrypted-Password-Attributes",
            "LAPS-ExtendedRight",
        ],

        # (Optional) “Write secret attributes” extended right – can be abused in some niche cases
        "94825a8d-b171-4116-8146-1e34d8f54401": [
            "WriteSecretAttributes",
        ],
    }

    # ----- Attribute / object-specific writes (schemaIdGuid of attributes/classes) -----
    # These fire when ADS_RIGHT_DS_WRITE_PROP and/or ADS_RIGHT_DS_SELF is set.
    attr_write_map = {
        # member attribute -> group membership; can be used for self-membership / AddMember
        # schemaIdGuid for "member" attribute
        "bf9679c0-0de6-11d0-a285-00aa003049e2": [
            "Write-member",
            "AddMember",
            "SelfMembership",
        ],

        # msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD / resource-based constrained delegation)
        "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79": [
            "Write-msDS-AllowedToActOnBehalfOfOtherIdentity",
            "RBCD",
        ],

        # msDS-GroupMSAMembership (controls which principals can read gMSA password)
        "888eedd6-ce04-df40-b462-b8a50e41ba38": [
            "Write-msDS-GroupMSAMembership",
            "ReadGMSAPassword",
        ],

        # msDS-KeyCredentialLink (shadow credentials / PKINIT abuse)
        "5b47d60f-6090-40b2-9f37-2a4de88f3063": [
            "Write-msDS-KeyCredentialLink",
            "ShadowCredentials",
        ],

        # servicePrincipalName (attribute schemaIdGuid == f3a64788-...)
        # Write access here = SPN abuse → Kerberoast / impersonation
        "f3a64788-5306-11d1-a9c5-0000f80367c1": [
            "Write-servicePrincipalName",
            "WriteSPN",
        ],

        # You can add more schemaIdGuid mappings here if you want to go even deeper.
    }

    # ----- Apply GUID-based mappings -----
    if object_guid_str:
        # Extended rights
        if access_mask & ADS_RIGHT_DS_CONTROL_ACCESS:
            extra = ext_rights_map.get(object_guid_str)
            if extra:
                rights.extend(extra)

        # Attribute / object-specific writes
        if access_mask & (ADS_RIGHT_DS_WRITE_PROP | ADS_RIGHT_DS_SELF):
            extra = attr_write_map.get(object_guid_str)
            if extra:
                rights.extend(extra)

    # De-duplicate while preserving order
    seen = set()
    deduped = []
    for r in rights:
        if r not in seen:
            deduped.append(r)
            seen.add(r)

    return deduped

# --- helper:  generic target resolver ----
def resolve_single_principal(conn, base_dn, name, preferred_kind="USER"):
    """
    Resolve one principal by sAMAccountName into (dn, kind, sam).

    preferred_kind: "USER" / "GROUP" / "MACHINE" – we try that first,
    but we fall back to "any kind" with that sAMAccountName.
    """

    if not name:
        return None

    upper_name = name.upper()

    # 1) Try via cached name_index if present
    # (if you don't have a global name_index, you can remove this section)
    try:
        name_index  # noqa
        for k in (preferred_kind, "USER", "GROUP", "MACHINE"):
            key = (k, upper_name)
            dn = name_index.get(key)
            if dn:
                meta = nodes.get(dn, {"type": k, "sam": name})
                return dn, meta["type"], meta.get("sam", name)
    except NameError:
        pass  # name_index / nodes not defined in this context, fall back to LDAP search

    # 2) Direct LDAP search on sAMAccountName
    user_filter = f"(sAMAccountName={name})"
    conn.search(
        search_base=base_dn,
        search_filter=user_filter,
        search_scope=SUBTREE,
        attributes=["sAMAccountName", "objectClass"],
    )

    if not conn.entries:
        return None

    entry = conn.entries[0]
    dn = entry.entry_dn
    obj_classes = [c.lower() for c in entry["objectClass"].values] if "objectClass" in entry else []

    if "group" in obj_classes:
        kind = "GROUP"
    elif "computer" in obj_classes:
        kind = "MACHINE"
    else:
        kind = "USER"

    sam = entry["sAMAccountName"].value if "sAMAccountName" in entry else name
    return dn, kind, sam

# ----  ----

def checkgroup(args):
    """
    checkgroup:
      - Connect to DC
      - Get base DN
      - For each target user:
          * find by sAMAccountName
          * show DOMAIN\\user, DN, SID, and groups (memberOf)
    """

    users = [u.strip() for u in args.target_users.split(",") if u.strip()]
    print("Checking groups for " + ",".join(f"({u})" for u in users))

    conn, netbios_domain = connect_to_ad(args.domain, args.dc, args.username, args.password)
    if conn is None:
        print(f"[ - ] Couldn't connect to {args.domain} using {args.username}:{args.password}")
        return

    base_dn = get_base_dn(conn)
    if not base_dn:
        print("[ - ] Could not determine base DN from RootDSE")
        return

    for user in users:
        search_filter = f"(sAMAccountName={user})"
        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["objectSid", "memberOf"],
        )

        if not conn.entries:
            print(f"[ - ] - {netbios_domain}\\{user}")
            print(" -> None (user not found)")
            continue

        entry = conn.entries[0]
        dn = entry.entry_dn

        raw_sid = entry["objectSid"].value if "objectSid" in entry else None
        sid_str = sid_to_string(raw_sid)

        member_of = entry["memberOf"].values if "memberOf" in entry else []

        if not member_of:
            print(f'[ - ] - {netbios_domain}\\{user} - "{dn}" - {sid_str}')
            print(" -> None")
            continue

        groups = []
        for group_dn in member_of:
            first_part = group_dn.split(",", 1)[0]
            if first_part.upper().startswith("CN="):
                groups.append(first_part[3:])
            else:
                groups.append(first_part)

        print(f'[ + ] - {netbios_domain}\\{user} - "{dn}" - {sid_str}')
        for g in groups:
            print(f" -> {g}")

def enumdomusers(args):
    """
    enumdomusers:
      - Connect to DC
      - Get base DN
      - Enumerate all user objects in the domain
      - For each user:
          * show DOMAIN\\sAMAccountName - "DN" - SID - Enabled/Disabled
    """


    print("Enumerating domain users...")

    conn, netbios_domain = connect_to_ad(args.domain, args.dc, args.username, args.password)
    if conn is None:
        print(f"[ - ] Couldn't connect to {args.domain} using {args.username}:{args.password}")
        return

    base_dn = get_base_dn(conn)
    if not base_dn:
        print("[ - ] Could not determine base DN from RootDSE")
        return

    # Filter for user objects (not computers)
    search_filter = "(&(objectCategory=person)(objectClass=user))"

    conn.search(
        search_base=base_dn,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=["sAMAccountName", "objectSid", "userAccountControl"],
    )

    if not conn.entries:
        print("[ - ] No users found in domain (search returned 0 entries)")
        return

    for entry in conn.entries:
        sam = entry["sAMAccountName"].value if "sAMAccountName" in entry else None
        if not sam:
            # Skip weird entries without sAMAccountName
            continue

        dn = entry.entry_dn

        raw_sid = entry["objectSid"].value if "objectSid" in entry else None
        sid_str = sid_to_string(raw_sid)

        uac = entry["userAccountControl"].value if "userAccountControl" in entry else 0
        disabled = is_disabled(uac)
        status = "Disabled" if disabled else "Enabled"

        prefix = "[ - ]" if disabled else "[ + ]"
        print(f'{prefix} - {netbios_domain}\\{sam} - "{dn}" - {sid_str} - {status}')

def enumdommachines(args):
    """
    enumdommachines:
      - Connect to AD
      - Get base DN
      - Enumerate all machine accounts (objects ending with $)
      - Print DOMAIN\\hostname$ - "DN" - SID
    """



    print("Enumerating domain machines...\n")

    conn, netbios_domain = connect_to_ad(args.domain, args.dc, args.username, args.password)
    if conn is None:
        print(f"[ - ] Failed to connect to {args.domain} using {args.username}:{args.password}")
        return

    base_dn = get_base_dn(conn)
    if not base_dn:
        print("[ - ] Could not determine base DN")
        return

    # All AD machine accounts: (objectCategory=computer)
    search_filter = "(objectCategory=computer)"

    conn.search(
        search_base=base_dn,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=["sAMAccountName", "objectSid"],
    )

    if not conn.entries:
        print("[ - ] No machines found")
        return

    for entry in conn.entries:
        sam = entry["sAMAccountName"].value if "sAMAccountName" in entry else None
        if not sam:
            continue

        dn = entry.entry_dn
        sid = sid_to_string(entry["objectSid"].value if "objectSid" in entry else None)

        print(f"[ + ] - {netbios_domain}\\{sam} - \"{dn}\" - {sid}")

def enumspnusers(args):
    """
    enumspnusers:
      - Connect to AD
      - Get base DN
      - Enumerate all user accounts with at least one SPN
      - For each:
          [ + ] - DOMAIN\\user - "DN" - SID
             -> SPN1
             -> SPN2
    """

    # ---- local helpers ----

    def sid_to_string(sid_value):
        if sid_value is None:
            return "N/A"
        if isinstance(sid_value, str):
            return sid_value

        sid_bytes = bytes(sid_value)
        if len(sid_bytes) < 8:
            return "Invalid SID"

        revision = sid_bytes[0]
        sub_authority_count = sid_bytes[1]
        authority = int.from_bytes(sid_bytes[2:8], byteorder="big")

        sub_authorities = []
        for i in range(sub_authority_count):
            start = 8 + (i * 4)
            end = start + 4
            if end > len(sid_bytes):
                break
            sub_auth = int.from_bytes(sid_bytes[start:end], byteorder="little")
            sub_authorities.append(str(sub_auth))

        sid_str = f"S-{revision}-{authority}"
        if sub_authorities:
            sid_str += "-" + "-".join(sub_authorities)
        return sid_str

    def connect_to_ad(domain, dc, username, password):
        netbios_domain = domain.split(".")[0].upper()
        login_user = f"{netbios_domain}\\{username}"
        try:
            server = Server(dc, get_info=ALL)
            conn = Connection(
                server,
                user=login_user,
                password=password,
                authentication=NTLM,
                auto_bind=True,
            )
            return conn, netbios_domain
        except (LDAPSocketOpenError, LDAPException):
            return None, netbios_domain

    def get_base_dn(conn):
        conn.search(
            search_base="",
            search_filter="(objectClass=*)",
            search_scope="BASE",
            attributes=["*"],
        )
        if not conn.entries:
            return None

        entry = conn.entries[0]
        if "defaultNamingContext" in entry:
            return entry["defaultNamingContext"].value
        if "namingContexts" in entry and entry["namingContexts"].values:
            return entry["namingContexts"].values[0]
        return None

    # ---- main logic ----

    print("Enumerating user accounts with SPNs...\n")

    conn, netbios_domain = connect_to_ad(args.domain, args.dc, args.username, args.password)
    if conn is None:
        print(f"[ - ] Couldn't connect to {args.domain} using {args.username}:{args.password}")
        return

    base_dn = get_base_dn(conn)
    if not base_dn:
        print("[ - ] Could not determine base DN from RootDSE")
        return

    # Find users that have servicePrincipalName set
    search_filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"

    conn.search(
        search_base=base_dn,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=["sAMAccountName", "objectSid", "servicePrincipalName"],
    )

    if not conn.entries:
        print("[ - ] No users with SPNs found in domain")
        return

    for entry in conn.entries:
        sam = entry["sAMAccountName"].value if "sAMAccountName" in entry else None
        if not sam:
            continue

        dn = entry.entry_dn
        raw_sid = entry["objectSid"].value if "objectSid" in entry else None
        sid_str = sid_to_string(raw_sid)
        spns = entry["servicePrincipalName"].values if "servicePrincipalName" in entry else []

        print(f'[ + ] - {netbios_domain}\\{sam} - "{dn}" - {sid_str}')
        for spn in spns:
            print(f" -> {spn}")

def enumasreproastusers(args):
    """
    enumasreproastusers:
      - Connect to AD
      - Get base DN
      - Enumerate user accounts with 'Do not require Kerberos preauthentication' set
      - For each:
          [ + ] - DOMAIN\\user - "DN" - SID - Enabled/Disabled
    """

    # ---- local helpers ----

    def sid_to_string(sid_value):
        if sid_value is None:
            return "N/A"
        if isinstance(sid_value, str):
            return sid_value

        sid_bytes = bytes(sid_value)
        if len(sid_bytes) < 8:
            return "Invalid SID"

        revision = sid_bytes[0]
        sub_authority_count = sid_bytes[1]
        authority = int.from_bytes(sid_bytes[2:8], byteorder="big")

        sub_authorities = []
        for i in range(sub_authority_count):
            start = 8 + (i * 4)
            end = start + 4
            if end > len(sid_bytes):
                break
            sub_auth = int.from_bytes(sid_bytes[start:end], byteorder="little")
            sub_authorities.append(str(sub_auth))

        sid_str = f"S-{revision}-{authority}"
        if sub_authorities:
            sid_str += "-" + "-".join(sub_authorities)
        return sid_str

    def connect_to_ad(domain, dc, username, password):
        netbios_domain = domain.split(".")[0].upper()
        login_user = f"{netbios_domain}\\{username}"
        try:
            server = Server(dc, get_info=ALL)
            conn = Connection(
                server,
                user=login_user,
                password=password,
                authentication=NTLM,
                auto_bind=True,
            )
            return conn, netbios_domain
        except (LDAPSocketOpenError, LDAPException):
            return None, netbios_domain

    def get_base_dn(conn):
        conn.search(
            search_base="",
            search_filter="(objectClass=*)",
            search_scope="BASE",
            attributes=["*"],
        )
        if not conn.entries:
            return None

        entry = conn.entries[0]
        if "defaultNamingContext" in entry:
            return entry["defaultNamingContext"].value
        if "namingContexts" in entry and entry["namingContexts"].values:
            return entry["namingContexts"].values[0]
        return None

    def is_disabled(user_account_control):
        try:
            uac = int(user_account_control)
        except (TypeError, ValueError):
            return False
        # 0x2 = ACCOUNTDISABLE
        return bool(uac & 0x2)

    # ---- main logic ----

    print("Enumerating AS-REP roastable users (Do not require Kerberos preauthentication)...\n")

    conn, netbios_domain = connect_to_ad(args.domain, args.dc, args.username, args.password)
    if conn is None:
        print(f"[ - ] Couldn't connect to {args.domain} using {args.username}:{args.password}")
        return

    base_dn = get_base_dn(conn)
    if not base_dn:
        print("[ - ] Could not determine base DN from RootDSE")
        return

    # userAccountControl bit 0x400000 (4194304) = DONT_REQUIRE_PREAUTH
    # Bitwise filter using LDAP matching rule 1.2.840.113556.1.4.803
    search_filter = (
        "(&(objectCategory=person)(objectClass=user)"
        "(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
    )

    conn.search(
        search_base=base_dn,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=["sAMAccountName", "objectSid", "userAccountControl"],
    )

    if not conn.entries:
        print("[ - ] No AS-REP roastable users found in domain")
        return

    for entry in conn.entries:
        sam = entry["sAMAccountName"].value if "sAMAccountName" in entry else None
        if not sam:
            continue

        dn = entry.entry_dn
        raw_sid = entry["objectSid"].value if "objectSid" in entry else None
        sid_str = sid_to_string(raw_sid)
        uac = entry["userAccountControl"].value if "userAccountControl" in entry else 0
        disabled = is_disabled(uac)
        status = "Disabled" if disabled else "Enabled"
        prefix = "[ - ]" if disabled else "[ + ]"

        print(f'{prefix} - {netbios_domain}\\{sam} - "{dn}" - {sid_str} - {status}')

def findinterestingacl(args):
    """
    findinterestingacl (SINGLE target principal):
      - Connect to AD
      - Resolve target (-tu / -tg / -tm) to SID
      - Resolve all group SIDs via memberOf recursion (nested groups)
      - Scan objects' nTSecurityDescriptor DACLs (user/group/computer/gMSA/OU/domain/container)
      - For ACEs whose trustee SID matches target SID OR any group SID:
          - Decode access mask + objectType GUID
      - Output:
          target_sAM -> RightName -> DN1,DN2,...
    """

    # ---- figure out which target option was used ----

    target_name = None
    target_kind = None  # "USER" / "GROUP" / "MACHINE" (for messages only)

    if getattr(args, "target_user", None):
        target_name = args.target_user
        target_kind = "USER"
    elif getattr(args, "target_group", None):
        target_name = args.target_group
        target_kind = "GROUP"
    elif getattr(args, "target_machine", None):
        target_name = args.target_machine
        target_kind = "MACHINE"
    else:
        print("[ - ] You must specify one of -tu / -tg / -tm.")
        return

    print("Finding interesting ACL-based rights for target principal (including group-based)...\n")

    conn, netbios_domain = connect_to_ad(args.domain, args.dc, args.username, args.password)
    if conn is None:
        print(f"[ - ] Couldn't connect to {args.domain} using {args.username}:{args.password}")
        return

    base_dn = get_base_dn(conn)
    if not base_dn:
        print("[ - ] Could not determine base DN from RootDSE")
        return

    # 1) Resolve target principal SID + groups via memberOf recursion
    user_filter = f"(sAMAccountName={target_name})"
    print(f"[DEBUG] base_dn      = {base_dn}")
    print(f"[DEBUG] principal_filter  = {user_filter}")

    conn.search(
        search_base=base_dn,
        search_filter=user_filter,
        search_scope=SUBTREE,
        attributes=["sAMAccountName", "objectSid", "distinguishedName", "memberOf"],
    )

    print(f"[DEBUG] search result code = {conn.result.get('result')}")
    print(f"[DEBUG] search description = {conn.result.get('description')}")
    print(f"[DEBUG] entries returned   = {len(conn.entries)}")

    if not conn.entries:
        print(f"[ - ] Target {target_kind or 'principal'} {target_name} not found in domain\n")
        return

    user_entry = conn.entries[0]
    print(f"[DEBUG] first entry DN  = {user_entry.entry_dn}")
    print(f"[DEBUG] first entry obj = {user_entry}\n")

    target_dn = user_entry.entry_dn
    sid_value = user_entry["objectSid"].value if "objectSid" in user_entry else None
    if sid_value is None:
        print(f"[ - ] Target {target_name} has no objectSid?\n")
        return

    trustee_sids = set()

    # target SID
    if isinstance(sid_value, str):
        trustee_sids.add(sid_string_to_bytes(sid_value))
    else:
        trustee_sids.add(bytes(sid_value))

    # Resolve group SIDs via memberOf recursion
    group_dns = []
    if "memberOf" in user_entry:
        group_dns = list(user_entry["memberOf"].values)

    visited_dns = set()
    queue = deque(group_dns)

    while queue:
        gdn = queue.popleft()
        if gdn in visited_dns:
            continue
        visited_dns.add(gdn)

        conn.search(
            search_base=gdn,
            search_filter="(objectClass=group)",
            search_scope="BASE",
            attributes=["objectSid", "memberOf"],
        )
        if not conn.entries:
            continue

        g_entry = conn.entries[0]
        g_sid_val = g_entry["objectSid"].value if "objectSid" in g_entry else None
        if g_sid_val is not None:
            if isinstance(g_sid_val, str):
                trustee_sids.add(sid_string_to_bytes(g_sid_val))
            else:
                trustee_sids.add(bytes(g_sid_val))

        if "memberOf" in g_entry:
            for parent_dn in g_entry["memberOf"].values:
                if parent_dn not in visited_dns:
                    queue.append(parent_dn)

    target_sam = user_entry["sAMAccountName"].value if "sAMAccountName" in user_entry else target_name

    print(f"[ * ] Target principal: {netbios_domain}\\{target_sam}")
    print(f"      DN  : {target_dn}")
    print(f"      SIDs considered (principal + groups): {len(trustee_sids)}\n")

    rights_map = defaultdict(set)

    print("[ * ] Scanning DACLs for ACEs involving these SIDs...\n")

    # 2) Scan candidate objects (include container to catch adminSDHolder-like stuff)
    search_filter = "(|(" + ")(".join([
        "objectClass=user",
        "objectClass=group",
        "objectClass=computer",
        "objectClass=msDS-GroupManagedServiceAccount",
        "objectClass=organizationalUnit",
        "objectClass=domainDNS",
        "objectClass=container",
    ]) + "))"

    # Ask explicitly for DACL in the SD
    sd_control = security_descriptor_control(sdflags=0x04)  # DACL only

    conn.search(
        search_base=base_dn,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=["nTSecurityDescriptor", "objectClass"],
        controls=sd_control,
    )

    objects = list(conn.entries)

    if not objects:
        print("[ - ] No candidate objects returned for ACL inspection\n")
        return

    for entry in objects:
        if "nTSecurityDescriptor" not in entry:
            continue
        sd_val = entry["nTSecurityDescriptor"].value
        if sd_val is None:
            continue

        try:
            sd_bytes = bytes(sd_val)
        except TypeError:
            continue

        dacl_info = get_dacl_info(sd_bytes)
        if not dacl_info:
            continue

        dacl_offset, acl_size, ace_count = dacl_info
        ace_pos = dacl_offset + 8  # skip ACL header

        for _ in range(ace_count):
            if ace_pos + 4 > len(sd_bytes):
                break

            ace_type = sd_bytes[ace_pos]
            ace_size = struct.unpack_from("<H", sd_bytes, ace_pos + 2)[0]

            if ace_size <= 4 or ace_pos + ace_size > len(sd_bytes):
                break

            if ace_type not in (0, 5):  # ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_OBJECT_ACE
                ace_pos += ace_size
                continue

            access_mask = None
            object_type_guid_bytes = None
            sid_start = None

            if ace_type == 0:
                # ACCESS_ALLOWED_ACE
                access_mask = struct.unpack_from("<I", sd_bytes, ace_pos + 4)[0]
                sid_start = ace_pos + 8

            elif ace_type == 5:
                # ACCESS_ALLOWED_OBJECT_ACE
                access_mask = struct.unpack_from("<I", sd_bytes, ace_pos + 4)[0]
                obj_flags = struct.unpack_from("<I", sd_bytes, ace_pos + 8)[0]
                cur = ace_pos + 12
                ACE_OBJECT_TYPE_PRESENT = 0x1
                ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x2

                if obj_flags & ACE_OBJECT_TYPE_PRESENT:
                    object_type_guid_bytes = sd_bytes[cur:cur + 16]
                    cur += 16
                if obj_flags & ACE_INHERITED_OBJECT_TYPE_PRESENT:
                    cur += 16

                sid_start = cur

            if sid_start is None or sid_start >= len(sd_bytes):
                ace_pos += ace_size
                continue

            # Grab the SID bytes from sid_start to end of ACE
            sid_bytes = sd_bytes[sid_start:ace_pos + ace_size]

            if sid_bytes not in trustee_sids:
                ace_pos += ace_size
                continue

            right_labels = decode_ace_rights(access_mask, object_type_guid_bytes)
            if not right_labels:
                ace_pos += ace_size
                continue

            obj_dn = entry.entry_dn
            for r in right_labels:
                rights_map[r].add(obj_dn)

            ace_pos += ace_size

    print(f"=== Interesting ACL rights for {netbios_domain}\\{target_sam} ===\n")

    if not rights_map:
        print(f"{target_sam} -> None -> (no ACEs with interesting rights found)\n")
        return

    for right_label in sorted(rights_map.keys()):
        dns = sorted(rights_map[right_label])
        dn_list = ",".join(dns) if dns else "None"
        print(f"{target_sam} -> {right_label} -> {dn_list}")
    print()

def findinboundacl(args):
    """
    findinboundacl:
      Given one or more targets (-tu / -tg / -tm),
      list who has interesting ACL rights *against* them.

      Example:
        adpeek.py findinboundacl -d inlanefreight.local -dc DC01 \
          -u owneduser -p 'Pass' -tu CT059

      Output (conceptually):
        SOMEGROUP -> GenericAll,ResetPassword -> INLANEFREIGHT\CT059
    """

    conn, netbios_domain = connect_to_ad(args.domain, args.dc, args.username, args.password)
    if conn is None:
        print(f"[ - ] Couldn't connect to {args.domain} using {args.username}:{args.password}")
        return

    base_dn = get_base_dn(conn)
    if not base_dn:
        print("[ - ] Could not determine base DN from RootDSE")
        return

    print(f"[DEBUG] base_dn          = {base_dn}")

    # cache from SID bytes -> DN
    sid_to_dn = {}
    # minimal metadata for pretty-printing
    nodes = {}

    def remember_entry(entry):
        dn = entry.entry_dn
        obj_classes = [c.lower() for c in entry["objectClass"].values] if "objectClass" in entry else []
        if "group" in obj_classes:
            kind = "GROUP"
        elif "computer" in obj_classes:
            kind = "MACHINE"
        else:
            kind = "USER"
        sam = entry["sAMAccountName"].value if "sAMAccountName" in entry else None
        if dn not in nodes:
            nodes[dn] = {"type": kind, "sam": sam}
        return dn, kind, sam

    def format_node(dn):
        meta = nodes.get(dn, {"type": "UNKNOWN", "sam": None})
        kind = meta["type"]
        sam = meta["sam"]
        if kind == "USER":
            return f"{netbios_domain}\\{sam}" if sam else f"USER:{dn}"
        if kind == "MACHINE":
            return f"{netbios_domain}\\{sam}" if sam else f"MACHINE:{dn}"
        if kind == "GROUP":
            return f"GROUP:{sam}" if sam else f"GROUP:{dn}"
        return dn

    def dn_for_sid_bytes(sid_bytes):
        # fast path: already cached
        dn = sid_to_dn.get(sid_bytes)
        if dn:
            return dn

        # try converting to string SID and doing a targeted LDAP lookup
        try:
            sid_str = sid_to_string(sid_bytes)
        except Exception:
            return None

        sid_filter = f"(objectSid={sid_str})"
        print(f"[DEBUG] SID lookup filter = {sid_filter}")
        conn.search(
            search_base=base_dn,
            search_filter=sid_filter,
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "objectClass", "objectSid"],
        )


        if not conn.entries:
            return None

        entry = conn.entries[0]
        dn, kind, sam = remember_entry(entry)

        # normalise and cache SID for future fast matches
        sid_val = entry["objectSid"].value if "objectSid" in entry else None
        if sid_val is not None:
            if isinstance(sid_val, str):
                cache_sid_bytes = sid_string_to_bytes(sid_val)
            else:
                cache_sid_bytes = bytes(sid_val)
            sid_to_dn[cache_sid_bytes] = dn

        sid_to_dn[sid_bytes] = dn
        return dn

    # 1) Resolve targets: -tu / -tg / -tm (each can be comma-separated)
    target_dns = []

    if getattr(args, "target_users", None):
        for raw in args.target_users.split(","):
            name = raw.strip()
            if not name:
                continue
            print(f"[DEBUG] resolving USER   = {name}")
            resolved = resolve_single_principal(conn, base_dn, name, preferred_kind="USER")
            if not resolved:
                print(f"[ - ] USER '{name}' not found in domain (no sAMAccountName match)")
                continue
            dn, kind, sam = resolved
            print(f"[DEBUG] USER resolved DN = {dn} (type={kind}, sam={sam})")
            nodes.setdefault(dn, {"type": kind, "sam": sam})
            target_dns.append(dn)

    if getattr(args, "target_groups", None):
        for raw in args.target_groups.split(","):
            name = raw.strip()
            if not name:
                continue
            print(f"[DEBUG] resolving GROUP  = {name}")
            resolved = resolve_single_principal(conn, base_dn, name, preferred_kind="GROUP")
            if not resolved:
                print(f"[ - ] GROUP '{name}' not found in domain (no sAMAccountName match)")
                continue
            dn, kind, sam = resolved
            print(f"[DEBUG] GROUP resolved DN= {dn} (type={kind}, sam={sam})")
            nodes.setdefault(dn, {"type": kind, "sam": sam})
            target_dns.append(dn)

    if getattr(args, "target_machines", None):
        for raw in args.target_machines.split(","):
            name = raw.strip()
            if not name:
                continue
            print(f"[DEBUG] resolving MACHINE= {name}")
            resolved = resolve_single_principal(conn, base_dn, name, preferred_kind="MACHINE")
            if not resolved:
                print(f"[ - ] MACHINE '{name}' not found in domain (no sAMAccountName match)")
                continue
            dn, kind, sam = resolved
            print(f"[DEBUG] MACHINE resolved = {dn} (type={kind}, sam={sam})")
            nodes.setdefault(dn, {"type": kind, "sam": sam})
            target_dns.append(dn)

    print(f"[DEBUG] total target DNs   = {len(target_dns)}")
    for tdn in target_dns:
        print(f"[DEBUG] target DN         = {tdn}")
    print()

    if not target_dns:
        print("[ - ] No valid target principals resolved (use -tu / -tg / -tm)")
        return

    # 2) For each target, fetch its DACL and list inbound rights
    sd_control = security_descriptor_control(sdflags=0x04)  # DACL only

    for tdn in target_dns:
        label = format_node(tdn)
        print(f"\n[ * ] Finding inbound ACL rights against {label}")
        print(f"      DN: {tdn}\n")

        print("[DEBUG] requesting nTSecurityDescriptor (DACL only) for target\n")

        conn.search(
            search_base=tdn,
            search_filter="(objectClass=*)",
            search_scope="BASE",
            attributes=["nTSecurityDescriptor"],
            controls=sd_control,
        )


        if not conn.entries or "nTSecurityDescriptor" not in conn.entries[0]:
            print("    [ - ] No nTSecurityDescriptor returned (no DACL / insufficient rights?).")
            continue

        sd_val = conn.entries[0]["nTSecurityDescriptor"].value
        try:
            sd_bytes = bytes(sd_val)
        except TypeError:
            print("    [ - ] Could not interpret security descriptor bytes.")
            continue

        dacl_info = get_dacl_info(sd_bytes)
        if not dacl_info:
            print("    [ - ] No DACL present or failed to parse.")
            continue

        dacl_offset, acl_size, ace_count = dacl_info
        ace_pos = dacl_offset + 8

        inbound = {}  # trustee_dn -> set(rights)

        while ace_count > 0:
            if ace_pos + 4 > len(sd_bytes):
                print("[DEBUG] ACE parsing break: insufficient bytes for ACE header")
                break

            ace_type = sd_bytes[ace_pos]
            ace_size = struct.unpack_from("<H", sd_bytes, ace_pos + 2)[0]

            if ace_size <= 4 or ace_pos + ace_size > len(sd_bytes):
                print("[DEBUG] ACE parsing break: invalid ace_size or truncated ACE")
                break

            if ace_type not in (0, 5):  # ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_OBJECT_ACE
                ace_pos += ace_size
                ace_count -= 1
                continue

            access_mask = None
            object_type_guid_bytes = None
            sid_start = None

            if ace_type == 0:
                # ACCESS_ALLOWED_ACE
                access_mask = struct.unpack_from("<I", sd_bytes, ace_pos + 4)[0]
                sid_start = ace_pos + 8
            elif ace_type == 5:
                # ACCESS_ALLOWED_OBJECT_ACE
                access_mask = struct.unpack_from("<I", sd_bytes, ace_pos + 4)[0]
                obj_flags = struct.unpack_from("<I", sd_bytes, ace_pos + 8)[0]
                cur = ace_pos + 12
                ACE_OBJECT_TYPE_PRESENT = 0x1
                ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x2

                if obj_flags & ACE_OBJECT_TYPE_PRESENT:
                    object_type_guid_bytes = sd_bytes[cur:cur + 16]
                    cur += 16
                if obj_flags & ACE_INHERITED_OBJECT_TYPE_PRESENT:
                    cur += 16

                sid_start = cur

            if sid_start is None or sid_start >= len(sd_bytes):
                print("[DEBUG] ACE parsing: invalid SID start, skipping ACE")
                ace_pos += ace_size
                ace_count -= 1
                continue

            sid_bytes = sd_bytes[sid_start:ace_pos + ace_size]

            rights = decode_ace_rights(access_mask, object_type_guid_bytes)
            if not rights:
                ace_pos += ace_size
                ace_count -= 1
                continue

            trustee_dn = dn_for_sid_bytes(sid_bytes)
            if not trustee_dn:
                ace_pos += ace_size
                ace_count -= 1
                continue

            if trustee_dn not in inbound:
                inbound[trustee_dn] = set()
            inbound[trustee_dn].update(rights)

            ace_pos += ace_size
            ace_count -= 1

        if not inbound:
            print("    [ - ] No interesting inbound ACEs resolved (or no known principals as trustees).")
            continue

        print(f"=== Inbound ACL rights against {label} ===\n")
        for trustee_dn, rights_set in sorted(inbound.items(), key=lambda x: format_node(x[0])):
            rights_list = sorted(rights_set)
            print(f"{format_node(trustee_dn)} -> {','.join(rights_list)} -> {label}")
        print()


def build_parser():
    parser = argparse.ArgumentParser(description="AdPeek - Active Directory enumeration tool, for privilege escalation and more.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # checkgroup
    cg = subparsers.add_parser(
        "checkgroup",
        help="Check group membership for one or more users.",
    )
    cg.add_argument(
        "-tu",
        "--target-users",
        required=True,
        help="Comma-separated list of target users (sAMAccountName), e.g. 'testuser,testuser2'.",
    )
    cg.add_argument(
        "-d",
        "--domain",
        required=True,
        help="AD domain, e.g. 'undeadbeef.local'.",
    )
    cg.add_argument(
        "-dc",
        "--dc",
        required=True,
        help="Domain controller hostname or IP, e.g. 'DC01.undeadbeef.local' or '172.16.7.3'.",
    )
    cg.add_argument(
        "-u",
        "--username",
        required=True,
        help="Owned username (without domain suffix).",
    )
    cg.add_argument(
        "-p",
        "--password",
        required=True,
        help="Password for owned username.",
    )
    cg.set_defaults(func=checkgroup)

    # enumdomusers
    ed = subparsers.add_parser(
        "enumdomusers",
        help="Enumerate all user accounts in the domain.",
    )
    ed.add_argument(
        "-d",
        "--domain",
        required=True,
        help="AD domain, e.g. 'undeadbeef.local'.",
    )
    ed.add_argument(
        "-dc",
        "--dc",
        required=True,
        help="Domain controller hostname or IP, e.g. 'DC01.undeadbeef.local' or '172.16.7.3'.",
    )
    ed.add_argument(
        "-u",
        "--username",
        required=True,
        help="Owned username (without domain suffix).",
    )
    ed.add_argument(
        "-p",
        "--password",
        required=True,
        help="Password for owned username.",
    )
    ed.set_defaults(func=enumdomusers)

    md = subparsers.add_parser(
        "enumdommachines",
        help="Enumerate all machine (computer) accounts in the domain.",
    )
    md.add_argument(
        "-d", "--domain", required=True,
        help="AD domain, e.g. undeadbeef.local"
    )
    md.add_argument(
        "-dc", "--dc", required=True,
        help="Domain controller hostname/IP"
    )
    md.add_argument(
        "-u", "--username", required=True,
        help="Owned username"
    )
    md.add_argument(
        "-p", "--password", required=True,
        help="Password for owned username"
    )
    md.set_defaults(func=enumdommachines)

    spn = subparsers.add_parser(
        "enumspnusers",
        help="Enumerate all user accounts that have SPNs set.",
    )
    spn.add_argument(
        "-d",
        "--domain",
        required=True,
        help="AD domain, e.g. 'undeadbeef.local'.",
    )
    spn.add_argument(
        "-dc",
        "--dc",
        required=True,
        help="Domain controller hostname or IP, e.g. 'DC01.undeadbeef.local' or '172.16.7.3'.",
    )
    spn.add_argument(
        "-u",
        "--username",
        required=True,
        help="Owned username (without domain suffix).",
    )
    spn.add_argument(
        "-p",
        "--password",
        required=True,
        help="Password for owned username.",
    )
    spn.set_defaults(func=enumspnusers)

    asrep = subparsers.add_parser(
        "enumasreproastusers",
        help="Enumerate AS-REP roastable user accounts (no preauth required).",
    )
    asrep.add_argument(
        "-d",
        "--domain",
        required=True,
        help="AD domain, e.g. 'undeadbeef.local'.",
    )
    asrep.add_argument(
        "-dc",
        "--dc",
        required=True,
        help="Domain controller hostname or IP, e.g. 'DC01.undeadbeef.local' or '172.16.7.3'.",
    )
    asrep.add_argument(
        "-u",
        "--username",
        required=True,
        help="Owned username (without domain suffix).",
    )
    asrep.add_argument(
        "-p",
        "--password",
        required=True,
        help="Password for owned username.",
    )
    asrep.set_defaults(func=enumasreproastusers)

    ii = subparsers.add_parser(
        "findinterestingacl",
        help="Find interesting ACL-based rights *from* a target user/group/machine to other objects.",
    )
    ii.add_argument(
        "-tu",
        "--target-user",
        help="Target user (sAMAccountName).",
    )
    ii.add_argument(
        "-tg",
        "--target-group",
        help="Target group (sAMAccountName).",
    )
    ii.add_argument(
        "-tm",
        "--target-machine",
        help="Target machine (sAMAccountName, usually ending with $).",
    )
    ii.add_argument(
        "-d",
        "--domain",
        required=True,
        help="AD domain, e.g. 'inlanefreight.local'.",
    )
    ii.add_argument(
        "-dc",
        "--dc",
        required=True,
        help="Domain controller hostname or IP.",
    )
    ii.add_argument(
        "-u",
        "--username",
        required=True,
        help="Owned username (without domain suffix).",
    )
    ii.add_argument(
        "-p",
        "--password",
        required=True,
        help="Password for owned username.",
    )
    ii.set_defaults(func=findinterestingacl)


    fi = subparsers.add_parser(
        "findinboundacl",
        help="Find principals who have ACL rights against a target user/group/machine.",
    )
    fi.add_argument(
        "-tu",
        "--target-users",
        help="Comma-separated list of target users (sAMAccountName).",
    )
    fi.add_argument(
        "-tg",
        "--target-groups",
        help="Comma-separated list of target groups (sAMAccountName).",
    )
    fi.add_argument(
        "-tm",
        "--target-machines",
        help="Comma-separated list of target machines (sAMAccountName, usually ending with $).",
    )
    fi.add_argument(
        "-d",
        "--domain",
        required=True,
        help="AD domain, e.g. 'inlanefreight.local'.",
    )
    fi.add_argument(
        "-dc",
        "--dc",
        required=True,
        help="Domain controller hostname or IP, e.g. 'DC01.inlanefreight.local' or '172.16.7.3'.",
    )
    fi.add_argument(
        "-u",
        "--username",
        required=True,
        help="Owned username (without domain suffix).",
    )
    fi.add_argument(
        "-p",
        "--password",
        required=True,
        help="Password for owned username.",
    )
    fi.set_defaults(func=findinboundacl)


    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
