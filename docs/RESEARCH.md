# Research & Rationale

Consolidated, source-backed foundation for the toolkit. All mechanism and
structure statements are verified against the sophomorix4 source code **and** a real
linuxmuster.net 7.3 instance (Samba 4.19.5).

## 1. The Core Mechanism (Windows GPO from the Samba DC)

A Windows client only applies a GPO when **three** things are consistent:
`Registry.pol` (PReg format) · version identical in `GPT.INI` **and** AD attribute
`versionNumber` · matching **client-side extension GUID** in
`gPCMachineExtensionNames`/`gPCUserExtensionNames`. If the CSE GUID is missing, the
client ignores the file (most common source of errors).

- **Registry/Admin Templates + Firewall** → `samba-tool gpo load --content=json` handles
  all three steps atomically (verified Samba 4.19). CSE `{35378EAC-683F-11D2-A89A-00C04FBBCFA2}`.
- **GptTmpl.inf** (user rights, restricted groups) → write the file yourself, CSE
  `{827D319E-6EAC-11D2-A4EA-00C04F79F83A}`, bump the version.
- **Groups.xml** (GPP local admins, additive) → CSE `{17D89FEC-5C44-4972-B12D-241CAEF74509}`.
- **Startup scripts** (WoL) → `Machine/Scripts/psscripts.ini`, CSE `{42B5FAAE-6536-11D2-AE5A-0000F87571E3}`.
- **Security filtering**: `samba-tool dsacl set` (right "Apply Group Policy"
  `edacfd8f-ffb3-11d1-b41d-00a0c968f939`). After DACL changes `samba-tool ntacl sysvolreset`
  (harmless, as long as `Domain Admins` has no `gidNumber`) → `gpo aclcheck` stays green.

Sources: [MS-GPREG](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpreg/5c092c22-bf6b-4e7f-b180-b20743d368f5) ·
[Samba policies.py](https://raw.githubusercontent.com/samba-team/samba/master/python/samba/policies.py) ·
[SambaWiki Group Policy](https://wiki.samba.org/index.php/Group_Policy) ·
[MS-GPFAS (firewall rule grammar)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpfas/2efe0b76-7b4a-41ff-9050-1023f8196d16) ·
[CSE GUID list](https://www.infrastructureheroes.org/microsoft-infrastructure/microsoft-windows/guid-list-of-group-policy-client-extensions/)

## 2. linuxmuster.net 7.x Structure (verified)

- Base DN from RootDSE (`DC=…`); OUs `OU=SCHOOLS` and `OU=GLOBAL` directly beneath it.
- School: `OU=<schule>,OU=SCHOOLS` (default `default-school`, empty prefix; otherwise `<schule>-`).
- Devices: `CN=<host>,OU=<raum>,OU=Devices,OU=<schule>,OU=SCHOOLS` — **per-room OUs exist**
  (targetable via GPO link). In addition, each room is a security group (`sophomorixType=room`).
- **PXE/LINBO status is not stored in AD.** Non-LINBO devices land in the device group
  **`d_nopxe`** (`sophomorixType=devicegroup`, column `dgr` of devices.csv) → targetable via security filtering.
- Admin groups: `global-admins` (member of `Domain Admins` and every `<schule>-admins`),
  `all-admins`, `role-globaladministrator` (under `OU=GLOBAL`); per school `<prefix>admins`.
- Never touch linuxmuster's own `sophomorix:school:<schule>` (on the school OU) — it gets overwritten on
  updates. Use your own GPOs with prefix `LMN-`.

Sources: [sophomorix4](https://github.com/linuxmuster/sophomorix4) (`SophomorixSambaAD.pm`, `sophomorix.ini`) ·
[docs.linuxmuster.net GPO](https://docs.linuxmuster.net/de/latest/systemadministration/gpo/gpo.html) ·
[paedML "Advanced GPO"](https://wiki.linuxmuster.net/community/_media/anwenderwiki:windowsclient_lmn7:gpo_fortgeschrittene.pdf)

## 3. Targeting Model

- **Global** (all schools): link on `OU=SCHOOLS` (inherited by all device OUs; non-Windows servers
  ignore GPOs anyway).
- **Per school**: link on `OU=Devices,OU=<schule>` (multi-school: loop over all schools).
- **Update split & teacher notebooks**: **deny-apply** on the group (`d_nopxe` or teacher group) →
  these devices fall back to the Windows default. (No exclusive filter needed, aclcheck-clean.)
- **Loopback = Merge** (`UserPolicyMode=1`) for user settings that should follow the machine.
  Microsoft's values (GroupPolicy.admx, client event 5311): **1 = Merge**, **2 = Replace**.
  Replace drops every GPO linked in the *user's* own OU path, so Merge is the only safe
  value here; up to lmn-gpo 7.3.1 the mapping was inverted (measured on a Windows 11 client).
- A `scope: school` pack is linked to `OU=Devices,OU=<school>`, a **sibling** of `OU=Students`
  and `OU=Teachers`. Its **user** settings therefore only reach a user via loopback. A
  `scope: global` pack is linked to `OU=SCHOOLS`, the common ancestor of devices *and* users,
  and its user settings apply without loopback.

## 4. Settings & Rationale (Brief)

| Pack | Why / source |
|---|---|
| Updates | LINBO machines are maintained via image → `NoAutoUpdate=1`; noPXE via deny → Windows default. [waas-wu-settings](https://learn.microsoft.com/en-us/windows/deployment/update/waas-wu-settings) |
| Power | Network reachability: standby=never, display 1800 s, hybrid standby off. Power setting GUIDs. [admx.help Power](https://admx.help/) |
| Lock | `InactivityTimeoutSecs=1800` (computer-wide, tamper-proof) instead of screensaver. |
| WoL | Fast Startup off (`HiberbootEnabled=0`) for real S5 + startup script arms the NICs. |
| Remote mgmt | RDP+NLA, firewall (RDP/SMB/RPC/ICMP) only from server IP; `net rpc … shutdown` (this is also how the linuxmuster WebUI does it). |
| Admins | `global-admins` (via Domain Admins anyway) explicit + `<schule>-admins` per school → local admins + RDP users. |

## 5. Volume Activation: Windows vs Office (verified)

Windows and Office are **separate products with separate KMS client keys** — configuring one
does not configure the other:

| Product | Registry key (HKLM), both values `REG_SZ` |
|---|---|
| Windows | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform` |
| Office | `Software\Microsoft\OfficeSoftwareProtectionPlatform` |

Values: `KeyManagementServiceName` (host) and `KeyManagementServicePort` (default `1688`).
The Office key applies to volume-licensed **Office LTSC 2024 / LTSC 2021 / 2019 / 2016**,
MSI *and* Click-to-Run, including Project and Visio; it is exactly what `ospp.vbs /sethst`
and `/setprt` write.

- **No ADMX exists.** The official Office administrative templates (2010, 2013 and the
  2016/2019/LTSC set up to build 5556.1000) contain **zero** occurrences of `kms` or
  `keymanagement`. The only volume-activation policies present concern *Token* activation.
  Raw registry values are therefore the only Group Policy route — which is what this toolkit
  writes anyway. (`Office\16.0\Common\OfficeSoftwareProtectionPlatform` appears in no
  Microsoft source and is **not** a valid key.)
- **GVLK preinstalled.** All volume Office builds ship their key, so no `/inpkey` is needed.
- **Microsoft 365 Apps is out of scope.** Since version 1910 it left the Office Software
  Protection Platform, so `ospp.vbs` and the KMS key do not apply to it.
- **Activation thresholds differ:** Office activates at a KMS count of **≥ 5**, Windows
  needs **≥ 25** — a small pilot lab can therefore activate Office but not Windows.
- **Detection is language-neutral via CIM.** On Windows 8+ (so all Windows 11 clients) Office
  licences live in `root\CIMV2:SoftwareLicensingProduct` — the *same* class as Windows,
  discriminated by `ApplicationId` `0ff1ce15-a989-479d-af46-f275c6370663` (Windows:
  `55c92734-…`). `OfficeSoftwareProtectionProduct` is an Office-2010-era class.
  The gate must be `LicenseStatus -ne 1`; a fresh GVLK install sits at **2** (OOBGrace),
  never 0, so testing for 0 makes an activation script a permanent no-op.
- **`ospp.vbs` is unusable from a startup script**, hence `Invoke-CimMethod Activate` (which
  is what `/act` does internally): every ospp.vbs exit is a bare `WScript.Quit`, so it
  returns 0 even on total failure; error paths can raise a **modal dialog** that nobody can
  dismiss in session 0; it refuses to run unless launched by `cscript`; and its folder
  differs between MSI, Click-to-Run and 32/64-bit installs.
- **Both keys tattoo.** They sit outside the four true-policy branches
  (`HKLM|HKCU\Software\Policies` and `…\Windows\CurrentVersion\Policies`), so Group Policy
  never withdraws them from a client. Removing the GPO stops *new* assignments only;
  clearing a provisioned client needs `slmgr.vbs /ckms` / `ospp.vbs /remhst`.
- Setting an explicit host **disables** `_vlmcs._tcp` SRV auto-discovery — so a renamed or
  rebuilt KMS host requires a GPO change, not just a DNS change.

Sources: [Activate Office by KMS](https://learn.microsoft.com/en-us/office/volume-license-activation/activate-office-by-using-kms) ·
[Tools to manage volume activation of Office](https://learn.microsoft.com/en-us/office/volume-license-activation/tools-to-manage-volume-activation-of-office) ·
[Registry settings for volume activation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-8.1-and-8/dn502532(v=ws.11)) ·
[KMS activation planning (thresholds)](https://learn.microsoft.com/en-us/windows-server/get-started/kms-activation-planning) ·
[SoftwareLicensingProduct class](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/sppwmi/softwarelicensingproduct)

## 6. Time Sync: why plain NTP, not NT5DS (field-verified)

`NT5DS` is Microsoft's domain-hierarchy mode, and a domain member **rejects any reply that is
not signed with its computer session key**. A Samba DC can only produce that signature by
handing the request to Samba over `ntpd`'s `ntpsigndsocket`. When that chain fails the client
does not error — it silently keeps `Local CMOS Clock` and drifts past the 5-minute Kerberos
limit. Observed on a production linuxmuster 7.3 site: the GPO applied correctly, the secure
channel was healthy (`nltest /sc_query` → `NERR_Success`), `w32tm /stripchart` against the DC
returned valid offsets — and the client was still 307 s off with no time source.

Two independent server-side causes, both verified:

1. **`restrict` shadowing.** `ntpd` applies the flags of the *most specific* matching entry
   and **replaces** the flag set — it does not inherit. `ntp_restrict.c` `restrictions()`
   does a plain `flags = match->flags;` with no OR across entries. A bare
   `restrict 10.10.40.0/24` therefore strips `mssntp` for exactly that subnet even though
   `restrict -4 default … mssntp` is present. linuxmuster's generated `ntp.conf` contains one
   such bare line per school subnet.
2. **ntpsec 1.2.2 drops the request outright.** Ubuntu 24.04 ships
   `ntpsec 1.2.2+dfsg1-4build2` (confirmed on a live box). A Windows MS-SNTP request is
   NTP(48) + key-id(4, the machine-account RID) + 16 zero bytes, i.e. a 20-byte MAC. In the
   1.2.2 `ntp_proto.c` that parses at `case 20:` and sets `keyid_present`; the auth block
   then calls `authlookup(keyid, true)`, finds no such key in `ntp.keys`, increments
   `sys_badauth` and **returns** — so `fast_xmit()` and its
   `if (flags & RES_MSSNTP) send_via_ntp_signd(...)` branch are never reached. Fixed
   upstream in 1.2.3 by clearing `keyid_present` for a 16-byte all-zero authenticator inside
   an MS-SNTP restrict range; the Debian/Ubuntu 1.2.2 patch series does not backport it.

Because of (2) fixing (1) alone will most likely NOT help on Ubuntu 24.04, so the toolkit
defaults to `ntp_mode: ntp`:
`Type=NTP` + `NtpServer=<serverfqdn>,0x9`, which needs no signing and works out of the box.
**Trade-off:** the time is then unauthenticated — an attacker on the LAN could spoof NTP
replies. `nt5ds` remains available for sites with a working signing chain.

Note: the log line `MS-SNTP signd operations currently block ntpd…` appears at config-parse
time whenever `mssntp` occurs anywhere in `ntp.conf`. It does **not** prove the flag reaches
any client, so it cannot be used to rule cause (1) out.

Sources: [W32Time: how the service works](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/how-the-windows-time-service-works) ·
[Samba wiki: time synchronisation](https://wiki.samba.org/index.php/Time_Synchronisation) ·
[ntpsec access control](https://docs.ntpsec.org/latest/access.html) · `ntpd/ntp_restrict.c`

### 6a. Secure Time Seeding off (pack 17, since 7.3.7)

**Field case (2026-11-11, a production linuxmuster 7.3 school).** Students were shown the
squid proxy's login dialog again and again; squid's `cache.log` had
`gss_accept_sec_context() failed ... Clock skew too great` more than 26,000 times in six days,
while proxy and DC agreed to the second. On one client the logon worked at 13:03 and broke at
13:20: the client clock jumped by more than 5 minutes in the middle of a session. That
school's own time GPO set `UtilizeSslTimeData = 1`. Whether switching it off ends the jumps
was **not yet confirmed on that client** when 7.3.7 was made; the change rests on the
Microsoft facts below.

What Microsoft documents (checked 2026-11-11):

| Fact | Source |
|---|---|
| STS is "a heuristic-based timekeeping mechanism" that takes the approximate time from the metadata of outbound SSL/TLS connections and uses it "to detect and correct any large errors in the system clock". | STS recommendations |
| On by default on every Windows client from Windows 10 1511 on and on Windows Server 2016/2019/2022; **off** by default on Windows Server 2025. Registry reference: "The default out-of-box value for all Windows versions with this feature is 1 except for Windows Server 2025, where the default value is 0. Domain membership doesn't affect this setting." | STS recommendations; W32Time tools and settings (`UtilizeSslTimeData`) |
| Reported incidents: W32Time "sets the system time to a random incorrect value, with a time error varying from days and weeks to years", usually self-corrected after a while, not reproducible on demand; some were persistent and ended only after STS was switched off. Microsoft recommends disabling STS on Windows Server (DCs, time-sensitive servers, VM hosts, and to consider it on all servers). | STS recommendations |
| For client SKUs (Windows 10/11) Microsoft has **no** general recommendation: it received no similar feedback there, calls client incidents "a small but distinct possibility" and leaves the decision to the admin; devices with drained batteries "might rely on STS to automatically correct gross time errors". | STS recommendations, "Scope" |
| Windows 10 and later: after a restart in a network without outbound SSL traffic, STS sets the clock from stale stored data into the past; listed symptoms include "Kerberos authentication fails". | Computer clock resets to a previous date and time (KB3160312) |
| Policy: Computer Configuration > Administrative Templates > System > Windows Time Service > **Global Configuration Settings**, setting `UtilizeSslTimeData`, "Values (Reboot required): 0 = STS disabled, 1 = STS enabled". ADMX `W32Time.admx`, policy `W32TIME_POLICY_CONFIG`, registry key `Software\Policies\Microsoft\W32Time\Config`, boolean, default 1. The local value is `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Config\UtilizeSslTimeData`, REG_DWORD. | STS recommendations; ADMX_W32Time Policy CSP; W32Time tools and settings |
| Policy values for W32Time live under `HKLM\SOFTWARE\Policies\Microsoft` and "the values defined by Group Policy overwrite any preexisting values in the W32Time section of the registry". | W32Time tools and settings |
| When the policy reaches a client, "W32Time is notified and it stops time monitoring and enforcement by using SSL time data. The SSL time data collection stops when each machine reboots." Locally `W32tm.exe /config /update` has the same effect without a reboot. Microsoft suggests excluding "portable slim laptops/tablets" whose batteries drain, because they "need the Secure Time Seeding feature to bootstrap their time". | Time accuracy improvements for Windows Server 2016, "Secure Time Seeding" |
| What the running service uses: the latest of events 257, 260, 263 in `Microsoft-Windows-Time-Service/Operational` contains `UtilizeSslTimeData: 0` when STS is off ("not available on all editions and releases"); the W32Time debug log shows `ReadConfig: 'UtilizeSslTimeData'=0x00000000`. | STS recommendations |

Trade-off: school clients get their time from the school server by NTP, and pack 17 lets
W32Time correct any offset (`MaxPos/NegPhaseCorrection = 0xFFFFFFFF`), so a dead CMOS battery
is corrected on the school network without STS. A device that leaves the network with a dead
battery loses STS as its fallback; that is accepted, the jumping clocks were the bigger harm.

So pack 17 writes `UtilizeSslTimeData = 0` (REG_DWORD, machine) next to its existing
`MaxPos/NegPhaseCorrection` values under `Software\Policies\Microsoft\W32Time\Config`, and
`lmn-gpo-check.ps1` (6e) reads both the policy value and the event Microsoft names.

**Not documented by Microsoft: a partial `Config` policy.** The ADMX policy "Global
Configuration Settings" writes all of its values at once when it is enabled in the GPMC, and the
CSP text only says: "If this policy setting is enabled, W32time Service on target machines use
the settings provided here. Otherwise, the service on target machines use locally configured
settings values." Pack 17 writes only three of those values (`MaxPos/NegPhaseCorrection`
already before 7.3.7). That W32Time takes a single value from the policy key and keeps the local
value for the others is **not stated** in any Microsoft document found; it has to be confirmed
on a client: after `gpupdate /force` and a reboot, the latest event 257/260/263 (or the
W32Time debug log) must show `UtilizeSslTimeData: 0`. `lmn-gpo-check.ps1` prints
that event line next to the policy value for exactly this reason.

**Upgrade.** `lmn-gpo apply` passes all registry values of a pack to `samba-tool gpo load`
unless every one of them is already in the GPO's `Registry.pol` with the same type and data
(`lmn_gpo/regpol.py` `_all_present`). On a GPO written by 7.3.6 `UtilizeSslTimeData` is
missing, so the next apply loads the pack; Samba's `RegistryGroupPolicies.merge_s()` replaces
or appends the entries in `Machine/Registry.pol` and `increment_gpt_ini(machine_changed=True)`
raises the computer half of GPT.INI and `versionNumber` by one
(`python/samba/policies.py` and `netcmd/gpo.py` `cmd_load`, read in the Samba 4.22 source of the
development machine; the lab test checks it on the 7.3 DC). `tests/test_apply_ntp.py` replays this on the
fake domain. The postinst does not run `apply`, so the admin has to.

Sources: [Secure Time Seeding recommendations for Windows Server](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/sts-recommendations-for-windows-server) ·
[Windows Time service tools and settings](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings) ·
[ADMX_W32Time Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-w32time) ·
[Computer clock resets to a previous date and time (KB3160312)](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/client-clock-reverts-to-previous-time) ·
[Time accuracy improvements for Windows Server 2016](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-server-2016-improvements)

## 7. Data Protection / GDPR (Evidence)

DSK resolution on Windows: **Enterprise/Education + `AllowTelemetry=0` (Security) +
Restricted Traffic Baseline** → no telemetry outflow in lab testing. On **Pro**, `0` is treated
as `1` → HKCU fallbacks there. Additionally blocked: MS accounts, OneDrive (optional), advertising ID,
activity history, location, Copilot/Recall, cloud sync.

Sources: [DSK resolution Windows 10 (PDF)](https://www.datenschutzkonferenz-online.de/media/dskb/TOP_30_Beschluss_Windows_10_mit_Anlagen.pdf) ·
[DSK annex 1 – technical aspects](https://www.datenschutzkonferenz-online.de/media/ah/20191106_win10_pruefschema_hinweise_dsk.pdf) ·
[LfD Lower Saxony](https://www.lfd.niedersachsen.de/) ·
[MS – manage-connections](https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services)

> Note: Every setting is documented in the catalog (`catalog/*.yaml`) with plain-text names and
> can be inspected before rollout with `lmn-gpo apply --dry-run`.

## 8. Drive Maps and the processing order (pack 20-drives)

**Processing order** ([MS-GPOL] 3.2.5.1.5 GPO Search): the SOM list starts at the object's OU
and walks up to the domain, the site last. For every SOM and every gPLink entry in stored
order, a link with option bit 1 (disabled) is ignored, a non-enforced link is *prepended* to
the non-enforced list, an enforced one *appended* to the enforced list; `gPOptions=1` (block
inheritance) drops the non-enforced links of the parents only. Result = non-enforced +
enforced, processed in that order, the last one wins. Hence: inside one SOM the **first**
gPLink entry is processed **last**, and Samba's `setlink` inserts a new link at the front
(`gplist.insert(0, …)`, netcmd/gpo.py `cmd_setlink`, 4.19 and 4.22) — the newest link wins
there. An **enforced link at `OU=SCHOOLS`** comes after every non-enforced link below it,
i.e. after `sophomorix:school:<school>` (linked at `OU=<school>`). Loopback Merge = the
user's list followed by the computer's list (the lab measured both halves, duplicates
included, in event 5312), Replace = the computer's list only. `lmn_gpo/gporder.py` is this
algorithm; `tests/test_gporder.py` reproduces the lab's 5312 list.

**samba-tool cannot change a link**: `gpo setlink` raises "already linked to this container"
for a GPO that is linked, and there is no command for the options of an existing link.
`GpoEngine.set_link_options()` rewrites the gPLink in sam.ldb instead — only the own entry,
position kept — as a compare-and-swap (delete old value + add new value in one modify).

**Drive Maps semantics** ([Drive Map item](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn581924(v=ws.11))):
Replace = delete and create, overwriting an existing mapping; Update changes only the
configured settings; Delete with `useLetter=1` removes the mapping of that letter and
"ignores the instruction and does not report an error" when the letter is not mapped;
`useLetter=0` deletes from that letter through Z: (KB3091116, never written); `removePolicy`
requires action R. **Item-level targeting** ([MS-GPPREF] Targeting): items in order, each
combined by its `bool` (AND/OR), `not` inverts, `FilterCollection` is a parenthesised group;
security-group items are evaluated by SID, not by the display name.

**sophomorix' default drives** (template
`sophomorix-samba/config-devel/gpo/school/User/Preferences/Drives/Drives.xml`): K: program,
P: share\projects, S: students (teachers only), T: share, R: iso, all action U. S: carries
a fixed SID from sophomorix' development domain; `smb_file_rewrite` replaces only the name
(`@@TEACHERGROUP@@`), so on Windows S: never matches (linuxclient7 filters by name and maps it).
`sophomorix-school --gpo-create` rewrites the file, the WebUI (Clients → Drives) edits
`disabled`/`letter` in place without a version bump. lmn-gpo only reads these files.

**Measured on a Windows 11 client** (lab, 2026-10-23): a Delete item with an empty `path` on a
letter that is not mapped raises no error; `&#252;` in a label shows as "ü" in Explorer;
`reconnect: true` (R + `removePolicy`) maps persistently and the mapping is gone after the GPO
is removed. `action: update` does **not** re-point a letter the user already mapped elsewhere,
although event 4096 reports the item as applied; Replace does — hence Replace is the default.
Explorer labels are stored per UNC path (`MountPoints2\##server#…\_LabelFromReg`), so two
letters on one path share a label. For a teacher of school A, a letter on `\\server\<schoolB>` is
not mapped at all (Application log, source "Group Policy Drive Maps": 4117 "Access denied", 4098
0x80070005; `net use` does not list it) until that group is given rights there: the school
folders' NT ACLs come
from sophomorix' templates (`ntacl/school.ntacl.template`: only the school's own groups) and
`sophomorix-repair` re-applies them.

## 9. Office trusted locations for the network drives (pack 21-office-trusted-schule)

**Why.** Office blocks VBA macros in files from the internet, and also in files "on a network
share that isn't in the **Local intranet** zone or isn't a trusted site"; for such a share
"selecting the [Unblock] checkbox won't have any effect". "Saving files from the internet to a
Trusted Location on a user's device ignores the check for Mark of the Web and opens with VBA
macros enabled" — the check that a trusted location skips. "Network locations can also be set
as a Trusted Location, but it's not recommended." The block covers Access, Excel, PowerPoint,
Project, Publisher, Visio and Word.
([Macros from the internet are blocked by default in Office](https://learn.microsoft.com/en-us/microsoft-365-apps/security/internet-macros-blocked),
ms.date 2026-07-17, read 2026-11-10.)

**Registry names, verified against Microsoft's ADMX** (read 2026-11-10): *Administrative Template
files (ADMX/ADML) and Office Customization Tool for Microsoft 365 Apps for enterprise, Office LTSC
2021, Office 2019, and Office 2016*, version **5568.1000**, published 2026-08-10,
[download id 49030](https://www.microsoft.com/en-us/download/details.aspx?id=49030), file
`admintemplates_x64_5568_1000_en-us.exe` (sha256 `a775828c86808bed55343c4738bed9458825d6fb7fa1948c2726e0b38dc45cfa`), unpacked with cabextract.
All policies are `class="User"`. Key and value names below are spelled exactly as in the ADMX
(the registry is case-insensitive; lmn-gpo writes this spelling).

| ADMX policy (file) | Key under `software\policies\microsoft\office\16.0\` | Value | Type / data |
|---|---|---|---|
| L_AllowTrustedLocationsOnTheNetwork "Allow Trusted Locations on the network" (`access16.admx`, same in `excel16`, `word16`, `ppt16` with `excel`, `word`, `powerpoint`) | `access\security\trusted locations` | `allownetworklocations` | enabled = decimal 1 |
| L_TrustedLoc01 … L_TrustedLoc20 "Trusted Location #1" … "#20" (each app file) | `access\security\trusted locations\location1` … `location20` | `path` (`<text expandable="true">` → REG_EXPAND_SZ), `date` (text), `description` (text), `allowsubfolders` (boolean, true = decimal 1) | |
| L_Allowmixofpolicyanduserlocations "Allow mix of policy and user locations" (`office16.admx`) | `common\security\trusted locations` | `allow user locations` | enabled = decimal 1 |
| L_DisableTrustedLoc "Disable all trusted locations" (each app file) | `access\security\trusted locations` | `alllocationsdisabled` | not written |

sha256 of the files used:
`access16.admx` `8a4f1a5db453e86aaf217117172f2dd7c901419c5e5f7210b35f3417cdffd9d6`,
`excel16.admx` `792e3ccf98abcf63ea17db94fbca361bdf354fe3b57fe1a55a917580194f44b8`,
`word16.admx` `9e818c0ebc624cd733c5c241b89b311d2aa08899970fef92f05c700d146a97cd`,
`ppt16.admx` `d857bcb5e80541c72bace16e42a5db9a23b4bafbde8101a574e6882405257ef9`,
`office16.admx` `8d1992feb234d680d3fce83e6ce6e16ef731fccb09a1221a62ae1e0d51d8f3c5`.

- **20 per application.** Every app file defines exactly `L_TrustedLoc01`–`L_TrustedLoc20`
  (counted: 20 `valueName="path"` per file); Learn: "There are 20 instances of this policy". A
  21st location has no policy, so lmn-gpo refuses a plan with more than 20 instead of cutting.
  (`office16.admx` has another 20 under `common\security\trusted locations\all applications\`
  for every app at once; not used, because the default is Access only.)
- **Network locations need `allownetworklocations`.** ADML (en-US): "If any of them are remote
  locations and you do not allow remote locations via this policy setting, those policy keys
  that point to remote locations will be ignored on client computers."
- **`allow user locations`.** ADML: "If you do not configure this policy setting, the behavior is
  the equivalent of setting the policy to Enabled"; disabled = "all trusted locations that are not
  created by Group Policy are disabled". Learn's table says the same ("Not Configured … Provides
  the same behavior as Enabled"). So writing 1 keeps Office's default rather than restoring
  something a policy location would switch off; it is written anyway (task decision) to pin it.
  Note: the Microsoft 365 Apps security baseline recommends *Disabled* for this and for
  `allownetworklocations` — a site that applies the baseline gets whichever GPO is processed last.
- **`date`** is informational (ADML label "Date:") and left out: a changing value would turn every
  apply into a change.
- Default locations Office keeps (Learn): Access `Program Files\Microsoft Office\Root\Office16\ACCWIZ`
  (wizard databases, subfolders not trusted); Excel/Word/PowerPoint templates, startup, add-ins.
  Policy locations appear under **Policy Locations** in the Trust Center.
([Trusted Locations for Office files](https://learn.microsoft.com/en-us/microsoft-365-apps/security/trusted-locations),
ms.date 2025-05-12, read 2026-11-10.)

**Which paths.** sophomorix builds `homeDirectory` from `HOMEDIRECTORY_HOST=ServerDNS`
(`sophomorix.ini:51`), and `ServerDNS` is smb.conf's `netbios name` **in lower case**
(`SophomorixBase.pm`, `$server_dns=…{'netbios name'}; $server_dns=~tr/A-Z/a-z/`), so a home is
`\\server\<school>\students\<class>\<user>` — the NetBIOS name, no dots. The school GPO's default
drives use the same host (`@@SERVER@@` → `ServerDNS`). lmn-gpo reads `homeDirectory` from AD
anyway and trusts its **share root** (`\\server\<school>\`); a default drive or a drives.yaml
path below a trusted path adds no second UNC location (subfolders are allowed). Different host
spellings (`\\server\x`, `\\server.<domain>\x`) stay separate: Office compares strings.
**Not yet measured:** whether a dotless `\\server\…` share counts as Local intranet on the lab's
Windows 11 client (then a file on it without a Mark of the Web is not blocked at all, and the
trusted location matters for files that carry one, e.g. downloads saved to H:), and whether
Office matches a file opened via `H:\…` against the UNC location, the letter location, or both.
**DFS:** with linuxmuster-fileserver the DC's school share is a DFS proxy (lab: `[default-school]`
`msdfs proxy = //fs.dev.lmschule.de/default-school`; `Get-SmbConnection` on the client shows the
connection to `fs.dev.lmschule.de`, while urlmon still rates the mapped `\\server\…` name, see
`work/gpo-office-trusted/lab-baseline.md` in the hub). lmn-gpo reads `msdfs proxy` per share with
`testparm -s --section-name <share> --parameter-name "msdfs proxy"` (output format checked with
testparm 4.22 against a test smb.conf: the bare value, exit 0; unknown section: exit 1) and adds
the same path on the target. Until the lab says which form Office checks, all three are written
(`office_trusted_forms: [unc, letter, dfs]`).

**Samba side.** `samba-tool gpo load` (merge, `policies.py merge_s`) keeps every value already in
the Registry.pol, so a drive removed from drives.yaml would keep its `locationN`. The pack is
therefore loaded with `--replace` (`replace_s`): every class it is given starts from an empty
Registry.pol; the other class's file and every other GPO stay untouched. A `REG_EXPAND_SZ` string
round-trips through `samba.dcerpc.preg` (checked locally with python3-samba 4.22.11; `__set_data`
passes it through unchanged, identical in samba-4.19.5 `python/samba/policies.py`).

**Access: the SHIFT key.** Holding SHIFT while opening skips the startup properties and the
AutoExec macro — unless the database itself sets `AllowBypassKey` to False
([AllowBypassKey property](https://learn.microsoft.com/en-us/office/vba/access/concepts/miscellaneous/allowbypasskey-property),
read 2026-11-10). A student's database can do that, so SHIFT is advice, not a safeguard.

## 10. A website in the Trusted sites zone (pack 22-edulution-trusted-schule)

**Why.** "Here's a list of ZoneId values … 2 = Trusted sites, 3 = Internet … if the ZoneId is 2,
VBA macros in that file won't be blocked by default. But if the ZoneId is 3, macros in that file
will be blocked by default" (internet-macros-blocked, section 9). Microsoft names the "Site to
Zone Assignment List" policy as the way to put a location into Trusted sites.

**Registry form, verified against Microsoft's ADMX** (read 2026-11-10): *Administrative Templates
(.admx) for Windows 11 Jan 2026 Update-V3*, version 3.0, published 2026-02-02,
[download id 108542](https://www.microsoft.com/en-us/download/details.aspx?id=108542) (msi sha256
`49a603cdc543558ab46f3774a562cc0d21868d75df5b3caefd6a1c3efd4ee7e5`), `inetres.admx` revision 11.0
(sha256 `6afc278479047b0b0d81d638ce80a652c9c0632a0ae9e00222a8ea0dc0f0f64e`):

```xml
<policy name="IZ_Zonemaps" class="Both" … key="Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" valueName="ListBox_Support_ZoneMapKey">
  <enabledValue><decimal value="1" /></enabledValue> …
  <list id="IZ_ZonemapPrompt" clientExtension="{4CFB60C1-FAA6-47f1-89AA-0B18730C9FD3}"
        key="Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMapKey"
        additive="true" explicitValue="true" />
```

- **Value name = the site, data = the zone** (`explicitValue="true"`: two columns, name and data;
  a list writes REG_SZ). ADML `IZ_ExplainZonemaps` (en-US): "Valuename – A host for an intranet
  site, or a fully qualified domain name for other sites. The valuename may also include a
  specific protocol. For example, if you enter http://www.contoso.com as the valuename, other
  protocols are not affected. If you enter just www.contoso.com, then all protocols are affected
  … do not include additional characters after the domain such as trailing slashes or URL path."
  The Policy CSP page says the same with `https://www.contoso.com`
  ([Policy CSP – InternetExplorer, AllowSiteToZoneAssignmentList](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-internetexplorer),
  ms.date 2026-10-14, read 2026-11-10). lmn-gpo writes **`https://<host>`** = zone `2`, so
  plain http to that host stays in its old zone; a path, port or wildcard in `edulution_host`
  is refused.
- **No `**delvals`.** `additive="true"`: "If this option is specified true, existing subkeys are
  not deleted, and the values set in the list box are appended to the existing subkeys"
  ([list Element](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc725892(v=ws.10)),
  ms.date 2012-07-02, read 2026-11-10). lmn-gpo never writes a `**del…` entry at all (pytest
  checks every catalog value name), so 12-proxy-zone-schule (proxy host → 1) and this pack
  (edulution → 2) coexist in one `ZoneMapKey`. This pack's own Registry.pol is loaded with
  `--replace` (a changed host must not leave the old one behind); that rewrites only this GPO.
- **Not written, deliberately like 12-proxy-zone-schule:** the policy's own value
  `ListBox_Support_ZoneMapKey=1` and the list's `clientExtension` {4CFB60C1-…} (not registered in
  `gPCMachineExtensionNames`). lmn-gpo has written ZoneMapKey values this way since 12-proxy-zone
  and the lab saw them arrive in `HKLM\…\ZoneMapKey`; that a download then gets **ZoneId=2** is
  **not yet measured** — it is the lab's check (Edge, Chrome, Firefox: `Zone.Identifier` with and
  without the GPO). If it stays 3, these two are the next thing to add.
- **Side effect:** the zone is Windows-wide, not Office-only ("These zone numbers have associated
  security settings that apply to all of the sites in the zone"); the Trusted Sites zone uses the
  Low template by default (ADML).
