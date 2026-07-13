# linuxmuster-gpo-template

[![Latest release](https://img.shields.io/github/v/release/faircomp/linuxmuster-gpo-template)](https://github.com/faircomp/linuxmuster-gpo-template/releases/latest)
[![License: GPL-3.0](https://img.shields.io/github/license/faircomp/linuxmuster-gpo-template)](https://github.com/faircomp/linuxmuster-gpo-template/blob/HEAD/LICENSE)

*(English first — deutsche Version weiter unten / German version below.)*

A reusable **Group Policy template toolkit** for **linuxmuster.net 7.x** (Ubuntu 24.04 +
Samba 4.19 Active Directory DC). It creates, links and permissions Windows 11 Group
Policies **directly from the Linux server** – without the Windows GPMC – and is
**multi-school capable** (several schools per server, and identical rollout across many
customer servers).

> **Status: complete & verified.** 30 policy packages, idempotent, with `--dry-run`.
> Tested end-to-end against a real linuxmuster 7.3 instance: create → idempotent re-run
> (0 changes) → `sysvolcheck`/`aclcheck`/`dbcheck` clean → fully removable.

> **Command name:** the examples below use `lmn-gpo` (the installed Debian package — the
> recommended way). From a source checkout the command is `./lmn-gpo-cli` instead — same
> commands, same behaviour.

## Contents

- [What the toolkit does](#why-this-works) · [Concept](#concept)
- [Features (30 packages)](#features-30-packages)
- **Guide:** [Installation](#installation) → [Quick start](#quick-start) → [Usage](#usage) → [Configuration](#configuration-siteyaml)
- **Setting up features:** [KMS](#kms) · [Branding](#branding-wallpaper--logon-background) · [Firefox](#firefox) · [Proxy](#role-based-proxy) · [Wi-Fi](#wi-fi-multiple-networks--roaming) · [Veyon](#veyon-classroom-management) · [Student lockdown](#student-lockdown) · [Boot order](#uefi-boot-order-pxe-first) · [Time sync](#time-synchronisation) · [Point and Print](#point-and-print-printer-drivers-for-students)
- [Rolling out to clients](#rolling-out-to-clients) · [Checking on the client](#checking-on-the-client) · [Updating the toolkit](#updating-the-toolkit) · [Troubleshooting](#troubleshooting)
- [Requirements](#requirements) · [Directory layout](#directory-layout)

## Why this works

For a Windows client to apply a GPO set by the Samba DC, three things must be consistent:
the `Registry.pol` (PReg format), the version in `GPT.INI` **and** in the AD attribute
`versionNumber`, plus the matching **Client-Side-Extension GUID** in
`gPCMachineExtensionNames`. `samba-tool gpo load` does exactly that atomically for
registry-based policies; for security settings (user rights, restricted groups), local
admins (GPP) and startup/shutdown scripts the toolkit writes the files itself and
registers the corresponding CSE GUID. Details: [`docs/`](docs/).

## Concept

- **Declarative YAML catalog** (`catalog/`): one package per concern, with scope
  (global / per school) and target (computer/user), optionally filtered exclusively to
  device or role groups.
- **`lmn-gpo` CLI** with an interactive **setup assistant**, **idempotent** (run as often
  as you like), `--dry-run` everywhere, persistent parameters in `site.yaml`.
- **Dynamic detection**: realm, base DN, server IP/subnet, schools and their prefixes,
  admin groups, the `d_nopxe` device group, role groups and rooms are read live from AD –
  nothing is hardcoded to `default-school`.
- **Gentle**: never touches `sophomorix:*` or default GPOs, checks ACLs
  (`aclcheck`/`sysvolcheck`) after every change and reconciles sysvol permissions via
  `sysvolreset`.

## Features (30 packages)

**Always active** (no extra parameter needed):

| Package | Effect |
|---|---|
| **Privacy / telemetry** | telemetry, advertising ID, activity history, location, input collection, "Find my device", AI data analysis off |
| **Block Microsoft accounts** | no MS-account sign-in, only local/domain accounts |
| **Disable OneDrive** | OneDrive autostart & file sync off |
| **First-run / OOBE / consumer** | "finish setup", Spotlight, Cortana, consumer features, Edge/first-run assistants off |
| **Windows Update split** | **off for LINBO machines**, **on for non-LINBO devices** (`d_nopxe`) |
| **Power** | no standby, display off after 30 min — *relaxed for teacher notebooks* |
| **Screen lock** | lock after 30 min idle — *relaxed for teacher notebooks* |
| **Hibernation off** | hibernate disabled — *except `d_nopxe`* |
| **Wake-on-LAN + Fast Startup off** | WoL armed (startup script), `HiberbootEnabled=0` |
| **Remote management** | RDP on, firewall exceptions (RDP/SMB/RPC/ICMP), remote-shutdown right |
| **Global admins** | `global-admins` as local admins + RDP **everywhere** |
| **School admins** | `<school>-admins` as local admins + RDP **per school** |
| **Block mobile hotspot** | Windows hotspot / ICS blocked on **all** machines (toggle greyed out) — no exception |
| **Student lockdown** | students (`role-student`) cannot change sensitive settings — above all **cannot remove the proxy** (+ Connections tab/PAC & Registry Editor locked); **teachers/admins unrestricted** (loopback + filter) |
| **Time synchronisation (W32Time)** | clients sync from the domain server (NT5DS, "the Samba way"); **also corrects large offsets** (dead CMOS battery); switchable to explicit NTP via `ntp_mode` |

**Optional** (enabled via `site.yaml` / the setup assistant):

| Package | Enabled by | Effect |
|---|---|---|
| **KMS activation** | `kmshost` | activate Windows against the KMS host (startup script) |
| **Branding per school** | wallpaper file | desktop **and** logon background per school (from NETLOGON) |
| **Veyon** | `veyon_binddn` + password | classroom management, LDAP directory, roaming, **teachers only** (`role-teacher` + `all-teachers`) |
| **Firefox hardening** | `firefox_enabled` | first-run off, clean new-tab (search + shortcuts, no ads) |
| **Firefox homepage** | `firefox_homepage` | global default **or per school**, optionally locked |
| **Role-based proxy** | `proxy_enabled` + host | **address follows the device** (school), **port follows the user** (teacher/student/staff), roaming-proof; all browsers on the system proxy; proxy host as Intranet zone (SSO) |
| **Wi-Fi PSK (students)** | `wlan_psk_networks` | any number of PSK networks as machine profiles → connect **before login**, **roaming across sites**; *not* on teacher notebooks |
| **Wi-Fi Enterprise (teachers)** | `wlan_enterprise_ssid` + CA cert | WPA2-Enterprise/PEAP with RADIUS, CA cert installed; **teachers only** (RADIUS enforces the group), exclusive to `d_nopxe` |
| **UEFI boot order PXE first** | `bootorder_pxe_first: true` | scheduled task (SYSTEM/highest) forces network/PXE to the top (→ LINBO) if Windows pushes itself forward; robust pattern detection, idempotent. **Hardware-dependent — test on 1 machine first** |
| **Allow Point and Print** | `pointandprint_enabled: true` | lets students auto-install printer drivers from your print server(s) — the printers linuxmuster/sophomorix already connects — which patched Windows 11 otherwise blocks (PrintNightmare). Trusts **only** your servers (auto-detected `\\SERVER` + FQDN + IP, plus `printservers_extra`) |

---

# Guide

## Installation

On the **linuxmuster server (Samba AD DC)** as **root**. Two ways to install — pick one.

### Install the released `.deb` (recommended)

Download the latest release asset and install it. The command is then **`lmn-gpo`**
(`/usr/bin/lmn-gpo`), usable from any directory:

```bash
# download the latest release .deb (via the GitHub CLI):
gh release download --repo faircomp/linuxmuster-gpo-template --pattern '*.deb'
# — or download lmn-gpo_*_all.deb by hand from the releases page:
#   https://github.com/faircomp/linuxmuster-gpo-template/releases/latest

# install on the linuxmuster server:
apt install ./lmn-gpo_*_all.deb          # or: dpkg -i lmn-gpo_*_all.deb
lmn-gpo doctor                               # environment self-check – must be green
```

### From a source checkout (alternative)

Clone the repo and run it in place; here the command stays **`./lmn-gpo-cli`** (from the repo
folder, not `lmn-gpo`):

```bash
cd /opt
git clone https://github.com/faircomp/linuxmuster-gpo-template.git
cd linuxmuster-gpo-template
./lmn-gpo-cli doctor          # environment self-check – must be green
```

You can also build the `.deb` yourself from the checkout (needs only `dpkg-deb`, no
debhelper) and install it — the command is then `lmn-gpo` as above:

```bash
sh packaging/build-deb.sh                    # -> dist/lmn-gpo_*_all.deb
apt install ./dist/lmn-gpo_*_all.deb     # or: dpkg -i dist/lmn-gpo_*_all.deb
```

No extra packages are required (see [Requirements](#requirements) – Python, the `samba`
bindings and `samba-tool` come with linuxmuster).

The package installs the CLI to `/usr/bin/lmn-gpo` and the catalog/scripts to
`/usr/share/lmn-gpo/`, and reads the **same** config `/etc/linuxmuster/lmn-gpo/site.yaml`. An
existing `site.yaml` from a source checkout is **migrated automatically** on install and is
**never removed** on upgrade/remove — no settings are lost. It installs entirely inside its
own namespace (`lmn-gpo`) and touches no linuxmuster files.

> **Important – where does `site.yaml` live?**
> The assistant saves your settings by default to **`/etc/linuxmuster/lmn-gpo/site.yaml`** —
> deliberately **outside** the repo. Only there does it survive every `git pull`/`git
> clean`. **Keep it there and always apply from there**, then updates can never lose your
> configuration (including Wi-Fi passwords).

## Quick start

```bash
lmn-gpo doctor                     # 1. check the environment
lmn-gpo setup                      # 2. configure interactively (asks only the decisions)
                                       #    -> saves /etc/linuxmuster/lmn-gpo/site.yaml, shows dry-run
lmn-gpo apply --yes                # 3. apply (uses the saved site.yaml automatically)
```

Then on a client `gpupdate /force` + reboot, and check with
[`lmn-gpo-check.ps1`](#checking-on-the-client).

## Usage

All commands: `lmn-gpo <command>`. Everywhere: **read-only commands change nothing**,
writing ones need `--yes` (or the prompt in the assistant).

| Command | Purpose |
|---|---|
| `doctor` | environment self-check (realm, groups, sysvol, secret) — read-only |
| `env` | print the detected environment (schools, groups, SIDs) |
| `list` | existing GPOs + their links |
| `setup` | interactive assistant → writes `site.yaml`, optionally applies right away |
| `apply` | apply the catalog from a `site.yaml` (non-interactive) |
| `remove` | remove the toolkit's `LMN-*` GPOs again |
| `selftest --yes` | non-destructive end-to-end test of the engine (throwaway GPO) |
| `veyon-encrypt-password` | encrypt the Veyon bind password (hex for `site.yaml`) |

### Configuring with the assistant

```bash
lmn-gpo setup
```

The assistant detects the environment itself and only asks the **decisions** (schools,
packages, firewall source, teacher-notebook group, KMS, wallpaper, Veyon, Firefox, proxy,
Wi-Fi, boot order). Each question shows its default in `[…]` — **Enter = keep**. On a
re-run **all previous answers are pre-filled** (including Wi-Fi SSIDs + passwords). At the
end: dry-run preview, save, optionally apply.

### Applying unattended

```bash
# preview without changing anything (always recommended first):
lmn-gpo apply --config /etc/linuxmuster/lmn-gpo/site.yaml --dry-run

# actually apply:
lmn-gpo apply --config /etc/linuxmuster/lmn-gpo/site.yaml --yes

# only specific schools or packages:
lmn-gpo apply --school schule1 --pack 02-updates --pack 17-ntp-zeit --yes
```

Without `--config`, `apply`/`setup` use `/etc/linuxmuster/lmn-gpo/site.yaml` automatically.

**Idempotent:** run `apply` as often as you like – a second run creates no new GPOs,
rewrites no registry values and bumps no versions; only real deviations are corrected.

### Removing again

```bash
lmn-gpo remove --dry-run    # shows what would be removed
lmn-gpo remove --yes        # removes ALL LMN-* GPOs (default/sophomorix GPOs stay)
```

## Configuration (`site.yaml`)

The assistant creates the file; you can also maintain it by hand and reuse it per customer.
Full reference:

```yaml
schools: null                 # null = all detected schools, otherwise [schule1, schule2]
packs: null                   # null = whole catalog, otherwise a list of pack IDs
fwsource: serverip            # firewall source for remote mgmt: serverip | subnet | <IP/CIDR>
teachernb: nopxe              # teacher-notebook group (relaxed power/lock): nopxe | skip | <CN>

kmshost: "kms.school.de"      # empty = no KMS
wallpaper_dir: ""             # empty = repo wallpapers/  (file: <school>.jpg, fallback default.jpg)

firefox_enabled: true
firefox_homepage: "https://start.school.de"
firefox_homepage_locked: true
firefox_homepage_by_school: { schule1: "https://schule1.school.de" }

proxy_enabled: true
proxy_host: "proxy.school.de"
proxy_host_by_school: { schule2: "proxy-schule2.school.de" }
proxy_port_by_role: { teacher: 3128, student: 3129, staff: 3130 }
proxy_exceptions: ""          # empty = sensible default (<local> + *.<realm> + private nets)

veyon_binddn: "CN=global-veyon,OU=Management,OU=GLOBAL,DC=..."
veyon_bindpw_hex: "…"         # via lmn-gpo veyon-encrypt-password

wlan_psk_networks:                       # any number — one entry per site
  - { ssid: "SCHULE1-LINBO", psk: "…" }
  - { ssid: "SCHULE2-LINBO", psk: "…" }
wlan_enterprise_ssid: "Teacher-WiFi"     # empty = no enterprise Wi-Fi
wlan_enterprise_servernames: "radius.school.de"
wlan_enterprise_ca_cert: "/path/to/radius-ca.pem"

bootorder_pxe_first: false    # true = force UEFI boot order to network/PXE first (opt-in!)
ntp_mode: nt5ds               # time sync: nt5ds (domain / Samba way) | ntp (explicit server = @serverfqdn)

pointandprint_enabled: false  # true = allow students to install printer drivers from the print server(s) (opt-in)
printservers_extra: []        # extra/external print-server FQDNs to also trust (the local server is auto-detected)
```

> `site.yaml` contains **secrets** (Wi-Fi PSKs, encrypted bind password) and is in
> `.gitignore` — do **not** commit it. Best kept under `/etc/linuxmuster/lmn-gpo/` (outside
> the repo).

---

# Setting up features

The **always-active** packages need no configuration. For the **optional** ones here are
the short guides (key in `site.yaml`, then `apply`).

## KMS

```yaml
kmshost: "kms.school.de"
```
Sets the KMS host and activates Windows via a startup script (`slmgr /ato`).

## Branding (wallpaper & logon background)

Put the images as `wallpapers/<school>.jpg` (fallback `wallpapers/default.jpg`), or set
`wallpaper_dir` to your own directory. The toolkit copies them to NETLOGON and sets the
**desktop and logon background** per school. (The images themselves are not in the repo.)

## Firefox

```yaml
firefox_enabled: true
firefox_homepage: "https://start.school.de"      # optional
firefox_homepage_locked: true                     # optional, locks the homepage
firefox_homepage_by_school: { schule1: "https://schule1.school.de" }   # optional, per school
```
First-run/import assistants off, clean new-tab page (search + shortcuts, no ads), optional
locked homepage.

## Role-based proxy

```yaml
proxy_enabled: true
proxy_host: "proxy.school.de"
proxy_host_by_school: { schule2: "proxy-schule2.school.de" }   # optional
proxy_port_by_role: { teacher: 3128, student: 3129, staff: 3130 }
```
**Address follows the device** (proxy host per school, via loopback), **port follows the
user** (teacher/student/staff per port, filtered exclusively to `role-*`) — roaming-ready.
Edge, Chrome and Firefox are set to the Windows system proxy; the proxy host is placed in
the Intranet zone for automatic SSO. The [student lockdown](#student-lockdown) prevents
students from removing the proxy.

## Wi-Fi: multiple networks & roaming

Multiple student Wi-Fis (e.g. one per site) are simply **multiple entries** in
`wlan_psk_networks`:

```yaml
wlan_psk_networks:
  - { ssid: "SCHULE1-LINBO", psk: "PSK-for-SCHULE1" }
  - { ssid: "SCHULE2-LINBO", psk: "PSK-for-SCHULE2" }
```

The package `13-wlan-psk` is deliberately **global**: **all** PSK profiles land as machine
profiles (`connectionMode auto`, connect before login) on **every** student device — except
teacher notebooks (`d_nopxe`). This makes a notebook **roam** automatically: at each site it
connects to the SSID in range. Effective after a client **reboot**.

> The price of roaming: every device carries **all** PSKs in its local profile store. Strict
> per-school isolation and roaming are mutually exclusive.

**Teacher Wi-Fi (WPA2-Enterprise):**
```yaml
wlan_enterprise_ssid: "Teacher-WiFi"
wlan_enterprise_servernames: "radius.school.de"    # name(s) in the RADIUS server certificate
wlan_enterprise_ca_cert: "/path/to/radius-ca.pem"  # CA cert is installed on the client
```
PEAP-MSCHAPv2 with user auth + SSO; **teachers only** (RADIUS enforces the group), exclusive
to `d_nopxe`. Note: the very first teacher login on a notebook needs a wired/other network
once (pure user auth), after that Wi-Fi SSO.

## Veyon (classroom management)

Entirely via registry GPO (no `config.json`, file-less LDAP directory), multi-school capable
with roaming: `BaseDN` = domain root, `ComputerTree` per school (room list stays per-school),
groups/users global — so a teacher may open the Master at **any** school.

**Setup:**
```bash
lmn-gpo veyon-encrypt-password        # encrypt the bind password -> copy the hex
```
```yaml
veyon_binddn: "CN=global-veyon,OU=Management,OU=GLOBAL,DC=..."
veyon_bindpw_hex: "<hex>"
```

- **Access for teachers only:** authorises `all-teachers` **and** `role-teacher` as
  **BaseDN-relative DNs** (`CN=role-teacher,OU=Groups,OU=GLOBAL`, without `,DC=…`), because
  Veyon compares that way internally; `QueryNestedUserGroups=true` also resolves nested
  membership. A student is in neither group → can never control.
- Keep the **bind user** `global-veyon` dedicated and read-only: Veyon's bind password is
  encrypted with a static, public key — i.e. reversible (details:
  [`docs/VEYON-PLAN.md`](docs/VEYON-PLAN.md)).
- The **Windows firewall** stays open for Veyon (port 11100); the site separation is done by
  OPNsense.
- **After rollout:** on the client `gpupdate /force` **and restart the Veyon service**
  (reboot) — Veyon reads its config only at service start.

## Student lockdown

Two packages make sure that **only students** (`role-student`) cannot change certain Windows
settings, while **teachers and admins stay unrestricted** (always active):

- `15-lockdown-base` (computer): enables **loopback merge** (`UserPolicyMode=2`) so that
  user-based, role-filtered policies take effect on shared classroom machines.
- `15-lockdown-student` (user, exclusive to `role-student`): pure HKCU policies —
  **proxy not changeable** (Settings app *and* Internet Options), Connections tab & PAC
  locked, **Registry Editor** locked.

Stricter is possible via extra HKCU entries in `catalog/15-lockdown-student.yaml`:

| Effect | Registry (`class: user`) |
|---|---|
| Hide Control Panel + Settings entirely | `…\Policies\Explorer\NoControlPanel = 1` |
| Lock Command Prompt | `…\Policies\Microsoft\Windows\System\DisableCMD = 1` |
| Lock Task Manager | `…\Policies\System\DisableTaskMgr = 1` |
| Lock wallpaper change | `…\Policies\ActiveDesktop\NoChangingWallPaper = 1` |

## UEFI boot order PXE first

Against Windows 11, which pushes its boot manager back to the top of the boot order after
every start (machines then boot straight into Windows instead of LINBO). **Opt-in:**
```yaml
bootorder_pxe_first: true
```

Because the GPO startup-script context has a reduced token (no access to the UEFI NVRAM),
it is **two-stage:** the GPO script registers a **scheduled task** (`SYSTEM`, highest
privileges, at system start) which, with a full token, does the actual `bcdedit` reorder
(network/PXE to the front, Windows Boot Manager to the end). Robust pattern detection
(IPV4/IPV6/PXE/…), idempotent, never breaks the boot.

> **Hardware-dependent — test on ONE machine first.** After `gpupdate /force` + 2 reboots:
> `schtasks /query /tn LMN-GPO-BootOrderPXE` (task there?) and
> `type %SystemRoot%\Temp\lmn-gpo-bootorder.log` (did the worker find the network entries and
> reorder?). Prerequisite: Fast Startup off (package `05-wol` / BIOS), no BitLocker forcing
> the Windows Boot Manager first.

## Time synchronisation

Fixes "not all clocks are correct" (always active). Default **NT5DS** ("the Samba way"):
clients sync via the domain from the DC (signed via its `mssntp`/`ntpsigndsocket`).
**Core fix:** `MaxPos/NegPhaseCorrection = 0xFFFFFFFF` → W32Time also corrects **large
offsets** (typical for dead BIOS/CMOS batteries). Clients only (linked at `OU=SCHOOLS`); the
DC stays untouched. Switchable:
```yaml
ntp_mode: nt5ds     # or: ntp  (then Type=NTP + NtpServer=<serverfqdn>,0x9)
```
Check on the client: `w32tm /query /source` and `w32tm /query /status`.

## Point and Print (printer drivers for students)

linuxmuster already **connects** the printers itself (sophomorix writes the school GPO's
`Printers.xml`). This pack only adds the missing piece: on patched Windows 11 a standard user
(student) may **not install the printer driver** (PrintNightmare, CVE-2021-34527), so a
connected printer fails on first use with *"administrator required"*. Enable it to allow the
driver install **automatically, but only from your print server(s)**:
```yaml
pointandprint_enabled: true
printservers_extra: []        # only for a dedicated/external print server (FQDN)
```
The trusted-server list is **auto-detected** to match how linuxmuster connects
(`\\SERVER` + FQDN + IP) — avoiding the classic short-name-vs-FQDN mismatch. Add
`printservers_extra` (FQDN, exactly as in the printer path) only for an external print server.

> **Security:** this sets `RestrictDriverInstallationToAdministrators=0` — a deliberate,
> scoped relaxation, bounded to your servers (`TrustedServers=1` + `ServerList`). The safest
> alternative is to pre-stage the drivers in the **LINBO image** and leave this disabled.

---

## Rolling out to clients

GPOs only take effect once the client fetches them and the respective service reads them:

1. **In general:** `gpupdate /force`, then **reboot** (computer policies + loopback +
   startup/shutdown scripts take effect at boot).
2. **Veyon:** additionally **restart the Veyon service** (reboot).
3. **Wi-Fi (PSK/Enterprise):** **reboot** (machine profiles are imported at boot).
4. **Boot order:** reboot twice, then check `…\Temp\lmn-gpo-bootorder.log`.
5. **Time:** `gpupdate /force` → `w32tm /config /update` → `w32tm /resync` (or reboot).

## Checking on the client

`scripts/lmn-gpo-check.ps1` checks **on the Windows client** (read-only) whether the policies
have arrived **and take effect** — covering all 30 packages: `gpresult` (computer **and**
user), registry actual values, firewall, local groups, KMS, hotspot, OneDrive, hibernation,
loopback, Firefox, role proxy, **student lockdown (HKCU)**, Veyon, Wi-Fi (+ RADIUS CA),
**time sync (w32tm)** and the **boot-order log**. It also produces an HTML report.

Best run **twice**:
```powershell
# 1) as ADMINISTRATOR → computer GPOs, firewall, groups, KMS, Veyon, time, boot order
powershell -ExecutionPolicy Bypass -File lmn-gpo-check.ps1 -Refresh -WlanCaSubject "RADIUS CA"

# 2) as the logged-in STUDENT (not elevated) → the user restrictions (lockdown/proxy)
powershell -ExecutionPolicy Bypass -File lmn-gpo-check.ps1
```
`-Refresh` runs `gpupdate /force` first (the only non-read-only action). Output: `[OK]`/`[!!]`
per check + a summary.

## Updating the toolkit

How you upgrade depends on how you installed. **Either way `/etc/linuxmuster/lmn-gpo/site.yaml`
is preserved** (Wi-Fi passwords and all) — so no settings are lost.

**Packaged install (`lmn-gpo`) — recommended.** Download the newer release `.deb` and install
it over the old one:

```bash
# fetch the latest release .deb (or download it from the releases page):
gh release download --repo faircomp/linuxmuster-gpo-template --pattern '*.deb'
apt install ./lmn-gpo_*_all.deb          # or: dpkg -i lmn-gpo_*_all.deb
lmn-gpo doctor                           # verify the environment
lmn-gpo apply --dry-run                   # what changes? (uses the saved site.yaml)
lmn-gpo apply --yes
```

Releases: <https://github.com/faircomp/linuxmuster-gpo-template/releases/latest>. On upgrade
your existing `/etc/linuxmuster/lmn-gpo/site.yaml` is **kept untouched** (it is never removed on
upgrade/remove), so your configuration carries over automatically.

**Source checkout (`./lmn-gpo-cli`).** Pull the new code and re-apply:

```bash
cd /opt/linuxmuster-gpo-template
git pull
./lmn-gpo-cli apply --config /etc/linuxmuster/lmn-gpo/site.yaml --dry-run   # what changes?
./lmn-gpo-cli apply --config /etc/linuxmuster/lmn-gpo/site.yaml --yes
```

- A `git pull` does **not** touch your `site.yaml` (it is gitignored and ideally lives under
  `/etc/linuxmuster/lmn-gpo/`). **Avoid** `git clean -fdx` / `git reset --hard` in the repo
  folder — they delete ignored files, and thus a `site.yaml` kept there.
- After the re-apply, do `gpupdate` + reboot on the clients as above.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `apply` says **"0 GPO(s) applied"** | an **opt-in package** is not enabled (e.g. `bootorder_pxe_first: true` missing), or filtered by `--pack`. `grep bootorder site.yaml`. |
| **Settings lost after an update** | `site.yaml` was **inside** the repo folder and deleted by `git clean`/`reset`. → move it to `/etc/linuxmuster/lmn-gpo/`. |
| **Two `site.yaml`** (assistant vs. `--config`) | `setup` saves to `/etc/linuxmuster/lmn-gpo/`. Always apply the **same** file. |
| **Teachers can't open the Veyon Master** | on the client `gpupdate /force` + **restart the Veyon service**. The toolkit already sets the correct **BaseDN-relative** group DNs. |
| **Boot-order log: "a required privilege is not held"** | old script version. The current package uses a **scheduled task** — re-roll out; check the log for `Worker (Scheduled Task…)` lines. |
| **Clocks wrong** | apply package `17-ntp-zeit`; on the client `w32tm /resync`. The `MaxPhaseCorrection` fix also corrects battery machines. |
| GPO supposedly not applied | on the client as admin `gpresult /r`; cross-check with [`lmn-gpo-check.ps1`](#checking-on-the-client); mind `-Refresh` + reboot. |

---

## Requirements

linuxmuster.net 7.x Samba AD DC, Python ≥ 3.10, `python3-yaml`, the `samba` Python bindings,
`samba-tool` (Samba ≥ 4.16 for `gpo load`), `openssl` (for Veyon/Wi-Fi certificates).
Runs as root on the DC.

Building the `.deb` yourself needs only `dpkg-deb` (no debhelper) — and can be done on any
machine, not just the DC. Installing the ready-made `.deb` from a release needs nothing extra.

## Directory layout

```
lmn_gpo/        Python engine + CLI (gpo, apply, env, catalog, veyon, wlan, scripts_ext, setup, paths, cli)
catalog/      30 YAML policy packages
scripts/      Windows startup/shutdown scripts + lmn-gpo-check.ps1 (client diagnostics)
lib/          veyon-default-pub.pem (Veyon's public key)
docs/         RESEARCH.md, VEYON-PLAN.md
wallpapers/   branding images per school (images not committed)
packaging/    Debian packaging (build-deb.sh, control, copyright, changelog, postinst/prerm/postrm)
.github/workflows/  GitHub Actions (release.yml builds the .deb and attaches it on a v* tag)
LICENSE       GPL-3.0
dist/         build output (the .deb) — gitignored
```

---
---

# 🇩🇪 linuxmuster-gpo-template (Deutsch)

[![Aktuelles Release](https://img.shields.io/github/v/release/faircomp/linuxmuster-gpo-template)](https://github.com/faircomp/linuxmuster-gpo-template/releases/latest)
[![Lizenz: GPL-3.0](https://img.shields.io/github/license/faircomp/linuxmuster-gpo-template)](https://github.com/faircomp/linuxmuster-gpo-template/blob/HEAD/LICENSE)

Ein wiederverwendbares **Group-Policy-Template-Toolkit** für **linuxmuster.net 7.x**
(Ubuntu 24.04 + Samba 4.19 Active-Directory-DC). Es erstellt, verlinkt und berechtigt
Windows-11-Gruppenrichtlinien **direkt vom Linux-Server aus** – ohne Windows-GPMC –
und ist **Multischule-fähig** (mehrere Schulen pro Server sowie identisches Ausrollen
über viele Kunden-Server hinweg).

> **Status: fertig & verifiziert.** 30 Policy-Pakete, idempotent, mit `--dry-run`.
> End-to-End gegen eine echte linuxmuster-7.3-Instanz getestet: anlegen → idempotenter
> Re-Run (0 Änderungen) → `sysvolcheck`/`aclcheck`/`dbcheck` sauber → restlos entfernen.

> **Befehlsname:** die Beispiele unten nutzen `lmn-gpo` (das installierte Debian-Paket — der
> empfohlene Weg). Aus einem Source-Checkout heißt das Kommando stattdessen `./lmn-gpo-cli` —
> gleiche Befehle, gleiches Verhalten.

## Inhalt

- [Was das Toolkit macht](#warum-das-funktioniert) · [Konzept](#konzept-1)
- [Features (30 Pakete)](#features-30-pakete)
- **Anleitung:** [Installation](#installation-1) → [Schnellstart](#schnellstart) → [Bedienung](#bedienung) → [Konfiguration](#konfiguration-siteyaml-1)
- **Features einrichten:** [KMS](#kms-1) · [Branding](#branding-wallpaper--anmeldebild) · [Firefox](#firefox-1) · [Proxy](#rollen-proxy) · [WLAN](#wlan-mehrere-netze--roaming) · [Veyon](#veyon-klassenraum-steuerung) · [Schüler-Lockdown](#schüler-lockdown) · [Bootreihenfolge](#uefi-bootreihenfolge-pxe-zuerst) · [Zeitsync](#zeitsynchronisation) · [Point and Print](#point-and-print-druckertreiber-für-schüler)
- [Ausrollen auf die Clients](#ausrollen-auf-die-clients) · [Prüfen am Client](#prüfen-am-client) · [Update des Toolkits](#update-des-toolkits) · [Troubleshooting](#troubleshooting-1)
- [Anforderungen](#anforderungen) · [Verzeichnisstruktur](#verzeichnisstruktur)

## Warum das funktioniert

Damit ein Windows-Client eine vom Samba-DC gesetzte GPO anwendet, müssen drei Dinge
konsistent sein: die `Registry.pol` (PReg-Format), die Version in `GPT.INI` **und** im
AD-Attribut `versionNumber`, sowie die passende **Client-Side-Extension-GUID** in
`gPCMachineExtensionNames`. `samba-tool gpo load` erledigt genau das atomar für
Registry-basierte Policies; für Sicherheitseinstellungen (Benutzerrechte, Restricted
Groups), lokale Admins (GPP) und Start-/Shutdown-Skripte schreibt das Toolkit die Dateien
selbst und registriert die jeweilige CSE-GUID. Details: [`docs/`](docs/).

## Konzept

- **Deklarativer YAML-Katalog** (`catalog/`): ein Paket pro Anliegen, mit Scope
  (global / pro Schule) und Ziel (Computer/User), optional exklusiv auf Geräte- oder
  Rollen-Gruppen gefiltert.
- **`lmn-gpo`-CLI** mit interaktivem **Setup-Assistenten**, **idempotent** (beliebig oft
  ausführbar), überall `--dry-run`, persistente Parameter in `site.yaml`.
- **Dynamische Erkennung**: Realm, Base-DN, Server-IP/Subnetz, Schulen, deren Präfixe,
  Admin-Gruppen, die `d_nopxe`-Gerätegruppe, Rollen-Gruppen und Räume werden live aus dem
  AD gelesen – nichts ist auf `default-school` hartkodiert.
- **Schonend**: rührt `sophomorix:*`- und Default-GPOs nie an, prüft nach jeder Änderung
  ACLs (`aclcheck`/`sysvolcheck`) und gleicht sysvol-Rechte per `sysvolreset` ab.

## Features (30 Pakete)

**Immer aktiv** (kein zusätzlicher Parameter nötig):

| Paket | Wirkung |
|---|---|
| **Datenschutz / Telemetrie** | Telemetrie, Werbe-ID, Aktivitätsverlauf, Standort, Input-Sammlung, „Find my device", KI-Datenanalyse aus |
| **Microsoft-Konten blockieren** | keine MS-Konten-Anmeldung, nur lokale/Domänen-Konten |
| **OneDrive deaktivieren** | OneDrive-Autostart & Datei-Sync aus |
| **First-Run / OOBE / Consumer** | „Fertig einrichten", Spotlight, Cortana, Consumer-Features, Edge-/Erstlauf-Assistenten aus |
| **Windows-Update-Split** | **aus für LINBO-Rechner**, **an für Nicht-LINBO-Geräte** (`d_nopxe`) |
| **Energie** | kein Standby, Display aus nach 30 Min — *lockerer für Lehrer-Notebooks* |
| **Bildschirmsperre** | Sperre nach 30 Min Inaktivität — *lockerer für Lehrer-Notebooks* |
| **Ruhezustand aus** | Hibernate deaktiviert — *außer `d_nopxe`* |
| **Wake-on-LAN + Fast Startup aus** | WoL scharf (Startskript), `HiberbootEnabled=0` |
| **Remote-Management** | RDP aktiv, Firewall-Ausnahmen (RDP/SMB/RPC/ICMP), Remote-Shutdown-Recht |
| **Globale Admins** | `global-admins` als lokale Admins + RDP **überall** |
| **Schul-Admins** | `<schule>-admins` als lokale Admins + RDP **je Schule** |
| **Mobiler Hotspot verbieten** | Windows-Hotspot / ICS auf **allen** Rechnern gesperrt (Schalter ausgegraut) — keine Ausnahme |
| **Schüler-Lockdown** | Schüler (`role-student`) können sensible Einstellungen nicht ändern — v. a. den **Proxy nicht rausnehmen** (+ Verbindungen-Tab/PAC & Registry-Editor gesperrt); **Lehrer/Admins uneingeschränkt** (Loopback + Filter) |
| **Zeitsynchronisation (W32Time)** | Clients synchen vom Domänen-Server (NT5DS, „Samba-Weg"); **korrigiert auch große Versätze** (leere CMOS-Batterie); umschaltbar auf expliziten NTP via `ntp_mode` |

**Optional** (per `site.yaml` / Setup-Assistent aktiviert):

| Paket | Aktiviert durch | Wirkung |
|---|---|---|
| **KMS-Aktivierung** | `kmshost` | Windows gegen den KMS-Host aktivieren (Startskript) |
| **Branding pro Schule** | Wallpaper-Datei | Desktop- **und** Anmelde-Hintergrund je Schule (aus NETLOGON) |
| **Veyon** | `veyon_binddn` + Passwort | Klassenraum-Steuerung, LDAP-Directory, Roaming, **nur Lehrer** (`role-teacher` + `all-teachers`) |
| **Firefox-Grundhärtung** | `firefox_enabled` | First-Run aus, saubere New-Tab (Suche + Verknüpfungen, kein Werbekram) |
| **Firefox-Startseite** | `firefox_homepage` | global-Default **oder pro Schule**, optional fest gesperrt |
| **Rollen-Proxy** | `proxy_enabled` + Host | **Adresse folgt dem Gerät** (Schule), **Port folgt dem Nutzer** (Lehrer/Schüler/Staff), roaming-fest; alle Browser auf System-Proxy; Proxy-Host als Intranet-Zone (SSO) |
| **WLAN PSK (Schüler)** | `wlan_psk_networks` | beliebig viele PSK-Netze als Maschinen-Profil → verbinden **vor dem Login**, **standortübergreifend roaming-fähig**; *nicht* auf Lehrer-Notebooks |
| **WLAN Enterprise (Lehrer)** | `wlan_enterprise_ssid` + CA-Cert | WPA2-Enterprise/PEAP mit RADIUS, CA-Zertifikat wird installiert; **nur Lehrer** (RADIUS erzwingt Gruppe), exklusiv auf `d_nopxe` |
| **UEFI-Bootreihenfolge PXE zuerst** | `bootorder_pxe_first: true` | Scheduled Task (SYSTEM/höchste Rechte) zwingt Netzwerk/PXE an die erste Stelle (→ LINBO), falls Windows sich vordrängt; robuste Muster-Erkennung, idempotent. **Hardwareabhängig — erst auf 1 Gerät testen** |
| **Point and Print erlauben** | `pointandprint_enabled: true` | lässt Schüler Druckertreiber von euren Druckservern automatisch installieren — die Drucker, die linuxmuster/sophomorix ohnehin verbindet — was gepatchtes Windows 11 sonst blockiert (PrintNightmare). Vertraut **nur** euren Servern (auto-erkannt `\\SERVER` + FQDN + IP, plus `printservers_extra`) |

---

# Anleitung

## Installation

Auf dem **linuxmuster-Server (Samba-AD-DC)** als **root**. Zwei Wege — einen wählen.

### Das veröffentlichte `.deb` installieren (empfohlen)

Das aktuelle Release-Asset herunterladen und installieren. Das Kommando ist dann
**`lmn-gpo`** (`/usr/bin/lmn-gpo`) und funktioniert aus jedem Verzeichnis:

```bash
# aktuelles Release-.deb laden (via GitHub-CLI):
gh release download --repo faircomp/linuxmuster-gpo-template --pattern '*.deb'
# — oder lmn-gpo_*_all.deb von Hand von der Releases-Seite holen:
#   https://github.com/faircomp/linuxmuster-gpo-template/releases/latest

# auf dem linuxmuster-Server installieren:
apt install ./lmn-gpo_*_all.deb          # oder: dpkg -i lmn-gpo_*_all.deb
lmn-gpo doctor                               # Umgebungs-Selbstcheck – muss grün sein
```

### Aus einem Source-Checkout (Alternative)

Das Repo klonen und direkt daraus fahren; hier bleibt das Kommando **`./lmn-gpo-cli`** (aus
dem Repo-Ordner, nicht `lmn-gpo`):

```bash
cd /opt
git clone https://github.com/faircomp/linuxmuster-gpo-template.git
cd linuxmuster-gpo-template
./lmn-gpo-cli doctor          # Umgebungs-Selbstcheck – muss grün sein
```

Optional das `.deb` selbst aus dem Checkout bauen (braucht nur `dpkg-deb`, kein debhelper)
und installieren — das Kommando ist dann `lmn-gpo` wie oben:

```bash
sh packaging/build-deb.sh                    # -> dist/lmn-gpo_*_all.deb
apt install ./dist/lmn-gpo_*_all.deb     # oder: dpkg -i dist/lmn-gpo_*_all.deb
```

Es sind keine zusätzlichen Pakete nötig (siehe [Anforderungen](#anforderungen) – Python,
`samba`-Bindings und `samba-tool` bringt linuxmuster mit).

Das Paket legt die CLI unter `/usr/bin/lmn-gpo` ab, Katalog/Skripte unter
`/usr/share/lmn-gpo/`, und liest **dieselbe** Config `/etc/linuxmuster/lmn-gpo/site.yaml`.
Eine vorhandene `site.yaml` aus einem Source-Checkout wird bei der Installation
**automatisch migriert** und bei Upgrade/Remove **nie gelöscht** — es gehen keine
Einstellungen verloren. Es installiert komplett im eigenen Namespace (`lmn-gpo`) und fasst
keine linuxmuster-Dateien an.

> **Wichtig – wo liegt die `site.yaml`?**
> Der Assistent speichert deine Einstellungen standardmäßig unter
> **`/etc/linuxmuster/lmn-gpo/site.yaml`** — bewusst **außerhalb** des Repos. Nur so
> überlebt sie jedes `git pull`/`git clean`. **Lege sie dort ab und wende immer von dort
> an**, dann können Updates deine Konfiguration (inkl. WLAN-Passwörter) nie verlieren.

## Schnellstart

```bash
lmn-gpo doctor                     # 1. Umgebung prüfen
lmn-gpo setup                      # 2. interaktiv einrichten (fragt nur die Entscheidungen)
                                       #    -> speichert /etc/linuxmuster/lmn-gpo/site.yaml, zeigt Dry-Run
lmn-gpo apply --yes                # 3. anwenden (nutzt automatisch die gespeicherte site.yaml)
```

Danach auf einem Client `gpupdate /force` + Neustart, dann mit
[`lmn-gpo-check.ps1`](#prüfen-am-client) kontrollieren.

## Bedienung

Alle Kommandos: `lmn-gpo <befehl>`. Überall gilt: **read-only-Befehle ändern nichts**,
schreibende brauchen `--yes` (oder die Rückfrage im Assistenten).

| Befehl | Zweck |
|---|---|
| `doctor` | Umgebungs-Selbstcheck (Realm, Gruppen, sysvol, Secret) — read-only |
| `env` | erkannte Umgebung ausgeben (Schulen, Gruppen, SIDs) |
| `list` | vorhandene GPOs + ihre Verlinkungen |
| `setup` | interaktiver Assistent → schreibt `site.yaml`, optional gleich anwenden |
| `apply` | Katalog aus einer `site.yaml` anwenden (nicht-interaktiv) |
| `remove` | die `LMN-*`-GPOs des Toolkits wieder entfernen |
| `selftest --yes` | nicht-destruktiver End-to-End-Test der Engine (Wegwerf-GPO) |
| `veyon-encrypt-password` | Bind-Passwort für Veyon verschlüsseln (Hex für `site.yaml`) |

### Einrichten mit dem Assistenten

```bash
lmn-gpo setup
```

Der Assistent erkennt die Umgebung selbst und fragt nur die **Entscheidungen** ab
(Schulen, Pakete, Firewall-Quelle, Lehrer-Notebook-Gruppe, KMS, Wallpaper, Veyon, Firefox,
Proxy, WLAN, Bootreihenfolge). Bei jeder Frage steht der Default in `[…]` — **Enter =
übernehmen**. Beim erneuten Lauf sind **alle bisherigen Antworten vorbefüllt** (inkl.
WLAN-SSIDs + Passwörter). Am Ende: Dry-Run-Vorschau, Speichern, optional anwenden.

### Unattended anwenden

```bash
# Vorschau ohne Änderung (immer zuerst empfohlen):
lmn-gpo apply --config /etc/linuxmuster/lmn-gpo/site.yaml --dry-run

# Wirklich anwenden:
lmn-gpo apply --config /etc/linuxmuster/lmn-gpo/site.yaml --yes

# Nur einzelne Schulen bzw. Pakete:
lmn-gpo apply --school schule1 --pack 02-updates --pack 17-ntp-zeit --yes
```

Ohne `--config` nutzt `apply`/`setup` automatisch `/etc/linuxmuster/lmn-gpo/site.yaml`.

**Idempotent:** `apply` beliebig oft ausführen – ein zweiter Lauf erzeugt keine neuen GPOs,
schreibt keine Registry-Werte neu und bumpt keine Versionen; nur echte Abweichungen werden
korrigiert.

### Wieder entfernen

```bash
lmn-gpo remove --dry-run    # zeigt, was entfernt würde
lmn-gpo remove --yes        # entfernt ALLE LMN-*-GPOs restlos (Default-/sophomorix-GPOs bleiben)
```

## Konfiguration (`site.yaml`)

Der Assistent erzeugt die Datei; sie lässt sich auch von Hand pflegen und pro Kunde
wiederverwenden. Vollständige Referenz:

```yaml
schools: null                 # null = alle erkannten Schulen, sonst [schule-a, schule-b]
packs: null                   # null = ganzer Katalog, sonst Liste von Pack-IDs
fwsource: serverip            # Firewall-Quelle für Remote-Mgmt: serverip | subnet | <IP/CIDR>
teachernb: nopxe              # Lehrer-Notebook-Gruppe (lockerere Energie/Sperre): nopxe | skip | <CN>

kmshost: "kms.schule.de"      # leer = kein KMS
wallpaper_dir: ""             # leer = repo wallpapers/  (Datei: <schule>.jpg, Fallback default.jpg)

firefox_enabled: true
firefox_homepage: "https://start.schule.de"
firefox_homepage_locked: true
firefox_homepage_by_school: { schule-a: "https://a.schule.de" }

proxy_enabled: true
proxy_host: "proxy.schule.de"
proxy_host_by_school: { schule-b: "proxy-b.schule.de" }
proxy_port_by_role: { teacher: 3128, student: 3129, staff: 3130 }
proxy_exceptions: ""          # leer = sinnvoller Default (<local> + *.<realm> + private Netze)

veyon_binddn: "CN=global-veyon,OU=Management,OU=GLOBAL,DC=..."
veyon_bindpw_hex: "…"         # via lmn-gpo veyon-encrypt-password

wlan_psk_networks:                       # beliebig viele — je Standort ein Eintrag
  - { ssid: "SCHULE1-LINBO", psk: "…" }
  - { ssid: "SCHULE2-LINBO", psk: "…" }
wlan_enterprise_ssid: "Lehrer-WLAN"      # leer = kein Enterprise-WLAN
wlan_enterprise_servernames: "radius.schule.de"
wlan_enterprise_ca_cert: "/pfad/zur/radius-ca.pem"

bootorder_pxe_first: false    # true = UEFI-Bootreihenfolge auf Netzwerk/PXE zuerst (opt-in!)
ntp_mode: nt5ds               # Zeitsync: nt5ds (Domäne/Samba-Weg) | ntp (expliziter Server = @serverfqdn)

pointandprint_enabled: false  # true = Schüler dürfen Druckertreiber von den Druckservern installieren (opt-in)
printservers_extra: []        # zusätzliche/externe Druckserver-FQDNs (der lokale Server wird automatisch erkannt)
```

> Die `site.yaml` enthält **Geheimnisse** (WLAN-PSKs, verschlüsseltes Bind-Passwort) und ist
> in `.gitignore` — **nicht** einchecken. Am besten unter `/etc/linuxmuster/lmn-gpo/` (außerhalb
> des Repos) halten.

---

# Features einrichten

Die **immer aktiven** Pakete brauchen keine Einstellung. Für die **optionalen** hier die
Kurzanleitungen (jeweils Schlüssel in `site.yaml`, dann `apply`).

## KMS

```yaml
kmshost: "kms.schule.de"
```
Setzt den KMS-Host und aktiviert Windows per Startskript (`slmgr /ato`).

## Branding (Wallpaper & Anmeldebild)

Lege die Bilder als `wallpapers/<schule>.jpg` ab (Fallback `wallpapers/default.jpg`), oder
setze `wallpaper_dir` auf ein eigenes Verzeichnis. Das Toolkit kopiert sie nach NETLOGON und
setzt **Desktop- und Anmelde-Hintergrund** je Schule. (Die Bilder selbst sind nicht im Repo.)

## Firefox

```yaml
firefox_enabled: true
firefox_homepage: "https://start.schule.de"     # optional
firefox_homepage_locked: true                    # optional, sperrt die Startseite
firefox_homepage_by_school: { schule-a: "https://a.schule.de" }   # optional, pro Schule
```
First-Run/Import-Assistenten aus, saubere New-Tab-Seite (Suche + Verknüpfungen, kein
Werbekram), optionale gesperrte Startseite.

## Rollen-Proxy

```yaml
proxy_enabled: true
proxy_host: "proxy.schule.de"
proxy_host_by_school: { schule-b: "proxy-b.schule.de" }   # optional
proxy_port_by_role: { teacher: 3128, student: 3129, staff: 3130 }
```
**Adresse folgt dem Gerät** (Proxy-Host je Schule, per Loopback), **Port folgt dem Nutzer**
(Lehrer/Schüler/Staff je Port, exklusiv auf `role-*` gefiltert) — roaming-tauglich. Edge,
Chrome und Firefox werden auf den Windows-System-Proxy gestellt; der Proxy-Host landet als
Intranet-Zone für automatisches SSO. Der [Schüler-Lockdown](#schüler-lockdown) verhindert,
dass Schüler den Proxy entfernen.

## WLAN: mehrere Netze & Roaming

Mehrere Schüler-WLANs (z. B. je Standort ein eigenes) sind einfach **mehrere Einträge** in
`wlan_psk_networks`:

```yaml
wlan_psk_networks:
  - { ssid: "SCHULE1-LINBO", psk: "PSK-für-SCHULE1" }
  - { ssid: "SCHULE2-LINBO", psk: "PSK-für-SCHULE2" }
```

Das Pack `13-wlan-psk` ist bewusst **global**: **alle** PSK-Profile landen als Maschinen-
Profile (`connectionMode auto`, verbinden vor dem Login) auf **jedem** Schüler-Gerät — außer
Lehrer-Notebooks (`d_nopxe`). Dadurch **roamt** ein Notebook automatisch: es verbindet sich an
jedem Standort mit der SSID, die dort in Reichweite ist. Wirksam nach **Neustart** des Clients.

> Preis des Roamings: jedes Gerät trägt **alle** PSKs im lokalen Profilspeicher. Strikte
> Pro-Schule-Isolierung und Roaming schließen sich technisch aus.

**Lehrer-WLAN (WPA2-Enterprise):**
```yaml
wlan_enterprise_ssid: "Lehrer-WLAN"
wlan_enterprise_servernames: "radius.schule.de"     # Name(n) im RADIUS-Serverzertifikat
wlan_enterprise_ca_cert: "/pfad/zur/radius-ca.pem"  # CA-Zert wird am Client installiert
```
PEAP-MSCHAPv2 mit User-Auth + SSO; **nur Lehrer** (der RADIUS erzwingt die Gruppe), exklusiv
auf `d_nopxe`. Hinweis: der allererste Lehrer-Login an einem Notebook braucht einmalig
Kabel/anderes Netz (reine User-Auth), danach WLAN-SSO.

## Veyon (Klassenraum-Steuerung)

Vollständig per Registry-GPO (kein `config.json`, dateiloses LDAP-Directory), Multischule-fähig
mit Roaming: `BaseDN` = Domänenwurzel, `ComputerTree` pro Schule (Raumliste schulscharf),
Gruppen/Nutzer global — ein Lehrer darf so an **jeder** Schule den Master öffnen.

**Einrichten:**
```bash
lmn-gpo veyon-encrypt-password        # Bind-Passwort verschlüsseln -> Hex kopieren
```
```yaml
veyon_binddn: "CN=global-veyon,OU=Management,OU=GLOBAL,DC=..."
veyon_bindpw_hex: "<Hex>"
```

- **Zugriff nur für Lehrer:** autorisiert `all-teachers` **und** `role-teacher` als
  **BaseDN-relative DNs** (`CN=role-teacher,OU=Groups,OU=GLOBAL`, ohne `,DC=…`), weil Veyon
  intern so vergleicht; `QueryNestedUserGroups=true` löst auch verschachtelte Mitgliedschaft
  auf. Ein Schüler ist in keiner Gruppe → kann nie steuern.
- **Bind-User** `global-veyon` dediziert und read-only halten: Veyons Bind-Passwort ist mit
  einem statischen, öffentlichen Schlüssel verschlüsselt — also umkehrbar
  (Details: [`docs/VEYON-PLAN.md`](docs/VEYON-PLAN.md)).
- **Windows-Firewall** bleibt für Veyon (Port 11100) offen; die Standort-Trennung macht die
  OPNsense.
- **Nach dem Ausrollen:** am Client `gpupdate /force` **und den Veyon-Dienst neu starten**
  (Reboot) — Veyon liest die Config nur beim Dienststart.

## Schüler-Lockdown

Zwei Pakete sorgen dafür, dass **nur Schüler** (`role-student`) bestimmte Windows-Einstellungen
nicht ändern können, **Lehrer und Admins aber uneingeschränkt** bleiben (immer aktiv):

- `15-lockdown-base` (Computer): aktiviert **Loopback-Merge** (`UserPolicyMode=2`), damit
  benutzerbasierte, rollengefilterte Richtlinien auf gemeinsam genutzten Klassenrechnern greifen.
- `15-lockdown-student` (User, exklusiv auf `role-student`): reine HKCU-Policies —
  **Proxy nicht änderbar** (Einstellungen-App *und* Internetoptionen), Verbindungen-Tab & PAC
  gesperrt, **Registry-Editor** gesperrt.

Strenger geht per zusätzlicher HKCU-Einträge in `catalog/15-lockdown-student.yaml`:

| Wirkung | Registry (`class: user`) |
|---|---|
| Systemsteuerung + Einstellungen ganz ausblenden | `…\Policies\Explorer\NoControlPanel = 1` |
| Eingabeaufforderung sperren | `…\Policies\Microsoft\Windows\System\DisableCMD = 1` |
| Task-Manager sperren | `…\Policies\System\DisableTaskMgr = 1` |
| Hintergrundbild-Wechsel sperren | `…\Policies\ActiveDesktop\NoChangingWallPaper = 1` |

## UEFI-Bootreihenfolge PXE zuerst

Gegen Windows 11, das seinen Boot Manager nach jedem Start wieder an die erste Stelle drängt
(Rechner booten dann direkt in Windows statt LINBO). **Opt-in:**
```yaml
bootorder_pxe_first: true
```

Weil der GPO-Startskript-Kontext ein abgespecktes Token hat (kein Zugriff auf die UEFI-NVRAM),
ist es **zweistufig gelöst:** das GPO-Skript registriert einen **Scheduled Task** (`SYSTEM`,
höchste Rechte, beim Systemstart), der mit vollem Token die eigentliche `bcdedit`-Umsortierung
macht (Netzwerk/PXE nach vorne, Windows Boot Manager ans Ende). Robuste Muster-Erkennung
(IPV4/IPV6/PXE/…), idempotent, bricht den Boot nie ab.

> **Hardwareabhängig — erst auf EINEM Gerät testen.** Nach `gpupdate /force` + 2× Neustart:
> `schtasks /query /tn LMN-GPO-BootOrderPXE` (Task da?) und
> `type %SystemRoot%\Temp\lmn-gpo-bootorder.log` (hat der Worker die Netzwerk-Einträge gefunden
> und umsortiert?). Voraussetzung: Fast Startup aus (Paket `05-wol` / BIOS), kein BitLocker mit
> Windows-Boot-Manager-Zwang.

## Zeitsynchronisation

Behebt „nicht alle Uhrzeiten stimmen" (immer aktiv). Default **NT5DS** („Samba-Weg"): die
Clients synchen über die Domäne vom DC (signiert über dessen `mssntp`/`ntpsigndsocket`).
**Kern-Fix:** `MaxPos/NegPhaseCorrection = 0xFFFFFFFF` → W32Time korrigiert **auch große
Versätze** (typisch bei leeren BIOS/CMOS-Batterien). Nur für Clients (an `OU=SCHOOLS`); der DC
bleibt unberührt. Umschaltbar:
```yaml
ntp_mode: nt5ds     # oder: ntp  (dann Type=NTP + NtpServer=<serverfqdn>,0x9)
```
Am Client prüfen: `w32tm /query /source` und `w32tm /query /status`.

## Point and Print (Druckertreiber für Schüler)

linuxmuster **verbindet** die Drucker schon selbst (sophomorix schreibt die `Printers.xml`
der Schul-GPO). Dieses Pack ergänzt nur das Fehlende: auf gepatchtem Windows 11 darf ein
Standard-User (Schüler) den **Druckertreiber nicht installieren** (PrintNightmare,
CVE-2021-34527) — der verbundene Drucker scheitert beim ersten Druck mit *„Administrator
erforderlich"*. Aktivieren erlaubt die Treiberinstallation **automatisch, aber nur von euren
Druckservern**:
```yaml
pointandprint_enabled: true
printservers_extra: []        # nur für einen dedizierten/externen Druckserver (FQDN)
```
Die Vertrauensliste wird **automatisch** so gefüllt, wie linuxmuster verbindet (`\\SERVER` +
FQDN + IP) — das vermeidet den klassischen Kurzname-vs-FQDN-Fehler. `printservers_extra`
(FQDN, exakt wie im Druckerpfad) nur für externe Druckserver.

> **Sicherheit:** setzt `RestrictDriverInstallationToAdministrators=0` — eine bewusste,
> eingegrenzte Lockerung, begrenzt auf eure Server (`TrustedServers=1` + `ServerList`). Am
> sichersten: Treiber ins **LINBO-Image** vorinstallieren und dies deaktiviert lassen.

---

## Ausrollen auf die Clients

GPOs wirken erst, wenn der Client sie holt und der jeweilige Dienst sie liest:

1. **Grundsätzlich:** `gpupdate /force`, dann **neu starten** (Computer-Policies + Loopback +
   Start-/Shutdown-Skripte greifen beim Boot).
2. **Veyon:** zusätzlich den **Veyon-Dienst neu starten** (Reboot).
3. **WLAN (PSK/Enterprise):** **Neustart** (Maschinen-Profile werden beim Boot importiert).
4. **Bootreihenfolge:** 2× neu starten, dann `…\Temp\lmn-gpo-bootorder.log` prüfen.
5. **Zeit:** `gpupdate /force` → `w32tm /config /update` → `w32tm /resync` (oder Neustart).

## Prüfen am Client

`scripts/lmn-gpo-check.ps1` prüft **auf dem Windows-Client** (rein lesend), ob die Richtlinien
angekommen sind **und wirken** — deckt alle 30 Pakete ab: `gpresult` (Computer **und** User),
Registry-Ist-Werte, Firewall, lokale Gruppen, KMS, Hotspot, OneDrive, Ruhezustand, Loopback,
Firefox, Rollen-Proxy, **Schüler-Lockdown (HKCU)**, Veyon, WLAN (+ RADIUS-CA), **Zeitsync
(w32tm)** und das **Bootorder-Log**. Erzeugt zusätzlich einen HTML-Report.

Am besten **zweimal** ausführen:
```powershell
# 1) als ADMINISTRATOR → Computer-GPOs, Firewall, Gruppen, KMS, Veyon, Zeit, Bootorder
powershell -ExecutionPolicy Bypass -File lmn-gpo-check.ps1 -Refresh -WlanCaSubject "RADIUS CA"

# 2) als angemeldeter SCHÜLER (nicht elevated) → die User-Sperren (Lockdown/Proxy)
powershell -ExecutionPolicy Bypass -File lmn-gpo-check.ps1
```
`-Refresh` macht vorher `gpupdate /force` (einzige nicht-lesende Aktion). Ausgabe: `[OK]`/`[!!]`
je Prüfung + Summe.

## Update des Toolkits

Wie du aktualisierst, hängt von der Installationsart ab. **In beiden Fällen bleibt
`/etc/linuxmuster/lmn-gpo/site.yaml` erhalten** (inkl. WLAN-Passwörter) — es gehen keine
Einstellungen verloren.

**Paket-Installation (`lmn-gpo`) — empfohlen.** Das neuere Release-`.deb` herunterladen und
über die alte Version installieren:

```bash
# das neueste Release-.deb holen (oder von der Releases-Seite herunterladen):
gh release download --repo faircomp/linuxmuster-gpo-template --pattern '*.deb'
apt install ./lmn-gpo_*_all.deb          # oder: dpkg -i lmn-gpo_*_all.deb
lmn-gpo doctor                           # Umgebung prüfen
lmn-gpo apply --dry-run                   # was ändert sich? (nutzt die gespeicherte site.yaml)
lmn-gpo apply --yes
```

Releases: <https://github.com/faircomp/linuxmuster-gpo-template/releases/latest>. Beim Upgrade
bleibt deine vorhandene `/etc/linuxmuster/lmn-gpo/site.yaml` **unangetastet** (sie wird bei
Upgrade/Remove nie gelöscht), deine Konfiguration wird also automatisch übernommen.

**Source-Checkout (`./lmn-gpo-cli`).** Neuen Code ziehen und neu anwenden:

```bash
cd /opt/linuxmuster-gpo-template
git pull
./lmn-gpo-cli apply --config /etc/linuxmuster/lmn-gpo/site.yaml --dry-run   # was ändert sich?
./lmn-gpo-cli apply --config /etc/linuxmuster/lmn-gpo/site.yaml --yes
```

- Ein `git pull` fasst deine `site.yaml` **nicht** an (sie ist gitignored und liegt idealerweise
  unter `/etc/linuxmuster/lmn-gpo/`). **Vermeide** `git clean -fdx` / `git reset --hard` im
  Repo-Ordner — die löschen ignorierte Dateien und damit eine dort liegende `site.yaml`.
- Nach dem Re-Apply auf den Clients wie oben `gpupdate` + Neustart.

## Troubleshooting

| Symptom | Ursache / Lösung |
|---|---|
| `apply` sagt **„0 GPO(s) angewandt"** | Ein **Opt-in-Pack** ist nicht aktiviert (z. B. `bootorder_pxe_first: true` fehlt), oder `--pack` gefiltert. `grep bootorder site.yaml`. |
| **Einstellungen nach Update weg** | `site.yaml` lag **im** Repo-Ordner und wurde von `git clean`/`reset` gelöscht. → nach `/etc/linuxmuster/lmn-gpo/` verschieben. |
| **Zwei `site.yaml`** (Assistent vs. `--config`) | `setup` speichert nach `/etc/linuxmuster/lmn-gpo/`. Immer **dieselbe** Datei anwenden. |
| **Lehrer können Veyon-Master nicht öffnen** | am Client `gpupdate /force` + **Veyon-Dienst neu starten**. Das Toolkit setzt bereits die korrekten **BaseDN-relativen** Gruppen-DNs. |
| **Bootorder-Log: „fehlt ein erforderliches Recht"** | alte Skript-Version. Aktuelles Pack nutzt einen **Scheduled Task** — neu ausrollen; Log auf `Worker (Scheduled Task…)`-Zeilen prüfen. |
| **Uhren falsch** | Pack `17-ntp-zeit` anwenden; am Client `w32tm /resync`. Der `MaxPhaseCorrection`-Fix korrigiert auch Batterie-Rechner. |
| GPO angeblich nicht angewandt | am Client als Admin `gpresult /r`; mit [`lmn-gpo-check.ps1`](#prüfen-am-client) gegenprüfen; auf `-Refresh` + Neustart achten. |

---

## Anforderungen

linuxmuster.net 7.x Samba-AD-DC, Python ≥ 3.10, `python3-yaml`, `samba` Python-Bindings,
`samba-tool` (Samba ≥ 4.16 für `gpo load`), `openssl` (für Veyon-/WLAN-Zertifikate).
Läuft als root auf dem DC.

Das `.deb` selbst zu bauen braucht nur `dpkg-deb` (kein debhelper) — und geht auf jedem
Rechner, nicht nur auf dem DC. Für das Installieren eines fertigen `.deb` aus einem Release
ist nichts Zusätzliches nötig.

## Verzeichnisstruktur

```
lmn_gpo/        Python-Engine + CLI (gpo, apply, env, catalog, veyon, wlan, scripts_ext, setup, paths, cli)
catalog/      30 YAML-Policy-Pakete
scripts/      Windows-Start-/Shutdown-Skripte + lmn-gpo-check.ps1 (Client-Diagnose)
lib/          veyon-default-pub.pem (öffentlicher Veyon-Schlüssel)
docs/         RESEARCH.md, VEYON-PLAN.md
wallpapers/   Branding-Bilder je Schule (Bilder nicht eingecheckt)
packaging/    Debian-Paketierung (build-deb.sh, control, copyright, changelog, postinst/prerm/postrm)
.github/workflows/  GitHub Actions (release.yml baut das .deb und hängt es an einen v*-Tag)
LICENSE       GPL-3.0
dist/         Build-Ausgabe (das .deb) — gitignored
```
