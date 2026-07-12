# Veyon GPO Pack — Design A (IMPLEMENTED as `catalog/10-veyon-schule.yaml`)

Status: **implemented + server-side verified on the crabbox** (apply/idempotent/remove, MULTI_SZ,
firewall location lock, bind-PW hex). The only thing still open is the real Windows client test (`gpupdate`/
`gpresult`) — as with all packs. Implemented via our registry engine (`samba-tool gpo load`).

Usage: put `veyon_binddn` + `veyon_bindpw_hex` into `site.yaml` (the wizard asks for them; hex via
`lmgpo-cli veyon-encrypt-password` or from a configurator export). Then pack `10-veyon-schule` applies
per school. The bind password is reversible (§5) → keep `global-veyon` tightly permissioned + rotate the password.

## 0. config.json vs. plain registry — decision

**Plain registry** (not `veyon-cli config import`). Rationale: the real config uses
`AccessControlRulesProcessingEnabled=false` → no `@JsonValue` rule arrays, so the only real
disadvantage of the registry route falls away. Registry fits our idempotent engine, needs no
`veyon-cli`/startup script on the client, and is generated per school from AD. (config.json is only needed for
complex rule sets/golden config — not the case here. Security is identical, since the bind PW would either way
lie in world-readable sysvol or NETLOGON.)

Config lives under `HKLM\SOFTWARE\Veyon Solutions\Veyon\<Sektion>` (64-bit view, tattooing). Takes effect after reboot.

## 1. Principle

- Auth = **logon authentication + LDAP directory** (fileless, no key-file problem).
- One GPO **per school** (`scope: school`, on `OU=Devices,OU=<schule>`).
- Directory = only the school's **student computers** (`ComputersFilter=(sophomorixRole=classroom-studentcomputer)`).
- Room mapping via the **`sophomorixComputerRoom` attribute** of the computer object
  (`ComputerLocationsByAttribute=true`, `LocationNameAttribute=sophomorixComputerRoom`) — cleaner than by-container.
- LDAP directory plugin UUID (confirmed): **`6f0a491e-c1c6-4338-8244-f823b0bf8670`** (for `NetworkObjectDirectory\Plugin` and `UserGroups\Backend`).
- **Teacher notebook master: deferred.**

## 2. Design A — Roaming (CHOSEN)

Veyon has **no location-based** access control, only identity-based (is-teacher). "Only at the
school where I am" therefore has to be enforced at the **network level** — here the **OPNsense** (§3).

- Auth global: every teacher may in principle be master.
- `BaseDN = DC=…` (root), `UserTree = OU=SCHOOLS`, `GroupTree = OU=Groups,OU=GLOBAL`.
- `AccessControl\AuthorizedUserGroups = ["CN=all-teachers,OU=Groups,OU=GLOBAL", "CN=role-teacher,OU=Groups,OU=GLOBAL"]`.
  **CRITICAL — BaseDN-RELATIVE DNs (without `,DC=…` suffix!):** Veyon stores and compares
  group DNs base-relative (`LdapClient::stripBaseDn`, verified against the source code + against a real
  config produced by the Configurator). A FULL DN therefore matches NO teacher → "teachers missing from
  the authorized group", the master won't open. That was the actual bug. Implementation:
  `apply._reldn()` strips the BaseDN; the reps `@role-teacher`/`@all-teachers` deliver relative DNs.
  Both teacher groups: `role-teacher` (direct members) + `all-teachers` (nested via
  `<schule>-teachers`), hence additionally **`LDAP\QueryNestedUserGroups=true`**. If a group is missing,
  its empty entry is dropped from the MULTI_SZ.
- `ComputerTree` per school → room list scoped to the school.
- **Location lock = OPNsense** (§3): the Windows firewall stays open for Veyon; the separation between
  school subnets/VLANs is done by the OPNsense.

> Rejected alternative (Design B, strict per school): `UserTree`/`GroupTree = OU=<schule>`,
> `AuthorizedUserGroups` = school teacher group → no roaming. Not chosen.

**Student roaming (uncritical, no adjustment needed):** "login for teachers only" concerns the Veyon *master*,
not the Windows logon — students log in normally and are monitored. Veyon's AccessControl checks the
*connecting* user (teacher) against `role-teacher` (`AccessControlProvider::processAuthorizedGroups`:
intersection of the accessing user's groups), **not** the locally logged-in student. A student is
never in `role-teacher` → can never control, regardless of which school. The computer list hangs off the computer object
(`classroom-studentcomputer` + `sophomorixComputerRoom`), not the student; config is purely HKLM. The only
external prerequisite: linuxmuster/AD must allow cross-school Windows logon.

## 3. Location lock = OPNsense (not Windows firewall)

The Windows firewall stays **completely open** for Veyon: Veyon opens port 11100 itself
(`Network\FirewallExceptionEnabled=1`), the pack sets **no** Windows firewall rule of its own.
The separation between schools (no remote-controlling another school) is done by the **OPNsense** between
the school subnets/VLANs. → No `subnets.csv`/netmask handling needed in the toolkit.

## 4. Master — current room as default, others selectable

- `Master\AutoSelectCurrentLocation = true` (soft preselection of one's own location).
- `Master\ShowCurrentLocationOnly = false` (do NOT set — would be a hard lock).
- also sensible from the real config: `Master\HideLocalComputer=true`, `Master\HideEmptyLocations=true`,
  `Master\AccessControlForMasterEnabled=true`.
- Prerequisite: the master PC is present as a computer object with the correct `sophomorixComputerRoom`; DNS forward/reverse clean.

## 5. SECURITY — bind password (key finding)

Veyon's `BindPassword` is **NOT hashed** — RSA with a **static key that lies publicly in the Veyon repo**
(`default-pkey.pem`, identical in every installation) → **trivially reversible**
(proven with `openssl`). Readable in **(1) sysvol `Registry.pol`** (Authenticated Users/students) and
**(2) client registry** (`HKLM\SOFTWARE\Veyon Solutions`, `BUILTIN\Users` read, since Veyon sets no restrictive
registry DACL).

Measures (the underlying problem remains, only damage limitation):
- **Dedicated read-only bind user `global-veyon`** (NOT `global-binduser`), read rights as tight as possible
  (computer objects + `sophomorixComputerRoom`/MAC/`dNSHostName` + `role-teacher`) → on compromise
  no student PII, only machine names/rooms + teacher list.
- Security-filter the GPO on **`Domain Computers`** (students out → closes the sysvol route; mind MS16-072).
- **Harden the client registry DACL** (revoke Users read on `HKLM\SOFTWARE\Veyon Solutions`; SYSTEM keeps it).
- **Enforce LDAPS** (`ConnectionSecurity=2`, port 636, CA `/etc/linuxmuster/ssl/cacert.pem`, `TLSVerifyMode=1`).
- Anonymous bind (linuxmuster forbids it) / Kerberos bind (Veyon can't do SASL) → not options.

## 6. Config inventory (from the real export config, school "msg" as template)

```
[Authentication] Method = 0                       (Logon)   ; DWORD
[NetworkObjectDirectory] Plugin = 6f0a491e-c1c6-4338-8244-f823b0bf8670
[UserGroups] Backend = 6f0a491e-...   UseDomainUserGroups = false
[LDAP]
  BaseDN                    = DC=<schule>,DC=<...>          ; Wurzel
  ServerHost                = server.<realm>                ; FQDN
  ServerPort                = 636      ConnectionSecurity = 2   TLSVerifyMode = 1
  BindDN                    = CN=global-veyon,OU=Management,OU=GLOBAL,DC=...
  BindPassword              = <RSA-Hex>                     ; UNSICHER (siehe §5)
  UseBindCredentials        = true     RecursiveSearchOperations = true
  ComputerTree              = OU=Devices,OU=<schule>,OU=SCHOOLS
  ComputersFilter           = (sophomorixRole=classroom-studentcomputer)
  ComputerHostNameAttribute = dNSHostName    ComputerHostNameAsFQDN = true
  ComputerMacAddressAttribute = sophomorixComputerMAC
  ComputerLocationsByAttribute = true   ComputerLocationsByContainer = false
  ComputerLocationAttribute = sophomorixComputerRoom
  LocationNameAttribute     = sophomorixComputerRoom
  UserLoginNameAttribute    = sAMAccountName               ; (Real-Config: 'sAMAccountname' — verify)
  GroupMemberAttribute      = member
  UserTree                  = OU=SCHOOLS                   ; Design A (Roaming)
  GroupTree                 = OU=Groups,OU=GLOBAL          ; Design A (Roaming)
[AccessControl]
  AccessRestrictedToUserGroups        = true
  AccessControlRulesProcessingEnabled = false
  AuthorizedUserGroups                = [ CN=role-teacher,OU=Groups,OU=GLOBAL,DC=... ]   (Design A)
[Master]
  AutoSelectCurrentLocation = true   ShowCurrentLocationOnly = false
  HideLocalComputer = true   HideEmptyLocations = true   AccessControlForMasterEnabled = true
[Network] VeyonServerPort = 11100   FirewallExceptionEnabled = 1
[Service] RemoteConnectionNotifications = true
[Windows] SoftwareSASEnabled = 1
```
Types: strings=SZ, ports/enums=DWORD, bool="true"/"false"(SZ), group list=MULTI_SZ.
Do NOT roll out `Core\*` (InstallationID, PluginVersions) (Veyon-internal/per-machine).

## 7. What the toolkit provides vs. new setup questions

Auto: realm/BaseDN/schools/`OU=Devices`/serverip/`server.<realm>`/cacert path/`role-teacher` DN/subnets.
To be clarified anew: `global-veyon` (have it created? rights scope?), Design A vs. B, LDAPS CA file distribution
(GPP files/share), security filter + registry DACL hardening on/off, TLSCACertificateFile path on the client.

## 8. Caveats / limits

- **WLAN devices** (role `wlan`) are not computer objects → not in the directory.
- `dNSHostName` case-sensitive (real config shows `sAMAccountname` lowercase — check against a real export).
- Veyon reads config at service start → reboot needed.
- Reconcile exact location/UUID values finally against a `veyon-cli config export` of a GUI-configured master.
- Verification only with a real Windows client (extend `lmgpo-check.ps1`).

## 9. Deferred

Veyon master on teacher notebooks (not all noPXE devices) — including separate handling of the bind-PW risk.
