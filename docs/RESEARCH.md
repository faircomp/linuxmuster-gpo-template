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
- **Loopback = Merge** (`UserPolicyMode=2`) for user settings that should follow the machine.

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
