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
- [Features (32 packages)](#features-32-packages)
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

## Features (32 packages)

**Always active** (no extra parameter needed):

| Package | Effect |
|---|---|
| **Privacy / telemetry** | telemetry, advertising ID, activity history, location, input collection, "Find my device", AI data analysis off |
| **Block Microsoft accounts** | no MS-account sign-in, only local/domain accounts |
| **Disable OneDrive** | OneDrive autostart & file sync off |
| **First-run / OOBE / consumer** | "finish setup", Spotlight, Cortana, consumer features, Edge/first-run assistants off |
| **Windows Update split** | **off for LINBO machines**, **on for non-LINBO devices** (`d_nopxe`) |
| **Power** | no standby, **display never switches off** (`display_off_seconds`, 0 = never) — *relaxed for teacher notebooks* |
| **Screen lock** | lock after 30 min idle — *relaxed for teacher notebooks* |
| **Hibernation off** | hibernate disabled — *except `d_nopxe`* |
| **Wake-on-LAN + Fast Startup off** | WoL armed (startup script), `HiberbootEnabled=0` |
| **Remote management** | RDP on, firewall exceptions (RDP/SMB/RPC/ICMP), remote-shutdown right |
| **Global admins** | `global-admins` as local admins + RDP **everywhere** |
| **School admins** | `<school>-admins` as local admins + RDP **per school** |
| **Block mobile hotspot** | Windows hotspot / ICS blocked on **all** machines (toggle greyed out) — no exception |
| **Student lockdown** | students (`role-student`) cannot change sensitive settings — above all **cannot remove the proxy** (+ Connections tab/PAC & Registry Editor locked); **teachers/admins unrestricted** (loopback + filter) |
| **Time synchronisation (W32Time)** | clients sync from the server via explicit **NTP** (`ntp_mode`, default); **also corrects large offsets** (dead CMOS battery); `nt5ds` available where MS-SNTP signing works |

**Optional** (enabled via `site.yaml` / the setup assistant):

| Package | Enabled by | Effect |
|---|---|---|
| **KMS activation (Windows)** | `kmshost` | activate Windows against the KMS host (startup script) |
| **KMS activation (Office)** | `kms_office_host` (or `kmshost`) | activate volume-licensed Office — its own registry key, own startup script |
| **Branding per school** | wallpaper file | desktop **and** logon background per school (from NETLOGON) |
| **Veyon** | `veyon_binddn` + password | classroom management, LDAP directory, roaming, **teachers only** (`role-teacher` + `all-teachers`); bandwidth-tuned monitoring |
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

kmshost: "kms.school.de"      # empty = no KMS (Windows)
kms_port: "1688"              # Windows KMS port
kms_office_host: ""           # empty = use kmshost; set only for a separate Office KMS
kms_office_port: "1688"       # Office KMS port
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
display_off_seconds: 0        # switch the display off after N s; 0 = never (screen still LOCKS, see 04)
ntp_mode: ntp                 # time sync: ntp (explicit server, default) | nt5ds (signed, needs working ntp_signd)

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
kmshost: "kms.school.de"       # Windows
kms_office_host: ""            # Office — empty = use the same host as Windows
kms_port: "1688"               # optional
kms_office_port: "1688"        # optional
```
Sets the KMS host and activates Windows via a startup script (`slmgr /ato`).

**Office needs its own entry.** Windows and Office are separate products with separate
registry keys — the Windows setting does *not* activate Office:

| | Registry key (HKLM) |
|---|---|
| Windows | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform` |
| Office | `Software\Microsoft\OfficeSoftwareProtectionPlatform` |

Since one KMS server usually activates both, `kms_office_host` defaults to `kmshost` when
left empty; set it only if Office is served by a *different* host. The wizard asks for both
and accepts either `host` or `host:port`.

Covers volume-licensed **Office LTSC 2024 / LTSC 2021 / 2019 / 2016** (MSI *and*
Click-to-Run, incl. Project and Visio). Volume Office ships its product key (GVLK)
preinstalled, so nothing else is needed. **Microsoft 365 Apps** (subscription) is not
KMS-activated at all and is skipped automatically. There is no ADMX policy for this — the
official Office administrative templates contain no KMS setting, so the registry values are
the only Group Policy route.

Two operational notes that cause most "it doesn't activate" cases:
- **Counts differ:** Office activates once the KMS host has counted **≥ 5** clients,
  Windows needs **≥ 25**.
- **The values tattoo.** Both keys live outside the four `…\Policies\…` branches, so they
  are *not* withdrawn from a client when the GPO stops applying. Clearing `kms_office_host`
  removes the GPO on the server (see below); to clear a client run
  `ospp.vbs /remhst` (Office) or `slmgr.vbs /ckms` (Windows) there.

> Emptying a setting now actually takes effect: a package whose precondition is gone has its
> GPO **unlinked and deleted** on the next `apply`, instead of silently continuing to push
> the old value.

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

**Teacher notebooks (`teachernb`, by default the `d_nopxe` device group) are excluded from
all proxy packages.** They leave the school network, where the school proxy is unreachable —
and because the proxy lands in the real WinINET key (not under `…\Policies\…`) it *tattoos*,
so it would stay configured off-site and cut the notebook off from the internet.

> If those notebooks already carry a proxy from an earlier rollout, removing the policy does
> **not** clear it. Reset it once per affected profile, e.g.
> `reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /f`.

## Wi-Fi: multiple networks & roaming

### Teacher Wi-Fi (WPA2-Enterprise) on linuxmuster

Export the RADIUS EAP CA on the server and point the toolkit at it — everything the manual
click-through would do is then applied by the GPO:

```bash
lmnradius ca export --out /etc/linuxmuster/lmn-gpo/eap-ca.pem
```
```yaml
wlan_enterprise_networks:
  - ssid: "MSG-LEHRER"
    servernames: "radius.evsvbz.org"
    ca_cert: "/etc/linuxmuster/lmn-gpo/eap-ca-msg.pem"
  - ssid: "GSG-LEHRER"
    servernames: "radius-gsg.evsvbz.org"
    ca_cert: "/etc/linuxmuster/lmn-gpo/eap-ca-gsg.pem"
```

One entry per site, **each with its own RADIUS CA** (sites sharing a RADIUS just reference the
same file). Order is the connection preference. Because the pack is `scope: global` and
filtered to `@teachernb`, **every teacher notebook receives all of these profiles and all of
these CAs** — so a teacher roaming to another school connects there too. The older single-key
form (`wlan_enterprise_ssid` / `_servernames` / `_ca_cert`) still works and is folded into a
one-element list.
```bash
lmn-gpo apply --pack 13-wlan-enterprise --yes
```

| Manual step | What the pack does |
|---|---|
| Install CA in **Local Computer** → Trusted Root | `certutil -addstore -f Root`, run as SYSTEM = machine store |
| Tick only that one root CA | `TrustedRootCA=<SHA-1>` pins exactly this certificate |
| Enter the server name | `ServerNames` |
| "Prompt for new servers" **off** | `DisableUserPromptForServerValidation=true` |
| SSO tick | `singleSignOn` / `preLogon` |

`apply` prints the certificate it pins (`RADIUS CA pinned: subject=... SHA1 ...`) — check that
it really is the *EAP CA*. A wrong file used to be accepted silently and produced a thumbprint
over garbage; the client then refuses to connect **with no prompt at all**, because prompting
is disabled by design. That is now a hard error instead.

> **The teacher Wi-Fi cannot come up before login, and no setting changes that.** It
> authenticates the *user* (`authMode=user`), and before login there is no user. `preLogon`
> means the 802.1X handshake runs *during* the Windows logon with the credentials just typed —
> not that the link is already up at the logon screen. Consequently the very first teacher
> logon on a notebook needs cable or another network once. Only *machine* authentication would
> connect earlier, and that requires a RADIUS policy for domain computers.



> **How the two packages split.** `13-wlan-psk` deploys the PSK networks as **all-user
> (machine) profiles**, so LINBO/PXE machines associate **before anyone logs in**. Delivery
> is a **self-healing scheduled task** (`LMN-GPO-WlanProfiles`, boot + every 15 min + logon),
> not a one-shot at boot: `netsh` needs a wireless *interface*, the profile store lives per
> interface inside `WlanSvc`, and `WlanSvc` is trigger-started -- so a plain boot-time import
> silently does nothing when the adapter is not up yet. The task also starts `WlanSvc`,
> re-enables a disabled adapter and sets the connection order. Log:
> `%SystemRoot%\Temp\lmn-gpo-wlan.log`.
> The order of `wlan_psk_networks` is the roaming preference (first = priority 1). `13-wlan-enterprise` is user-authenticated (PEAP + SSO `preLogon`), so teacher
> laptops connect **at** login, not before. Both exclusions follow `teachernb` (by default the
> `d_nopxe` device group).
>
> **The student PSK is not a secret from your students.** It sits in cleartext in the profile
> XML inside the startup script in sysvol. `filter_deny_read: ['@role-student']` denies
> students read on the GPO *object*, but `samba-tool ntacl sysvolreset` writes a fixed ACL
> template in which Authenticated Users keep read on the *file* — verified on a live DC. If
> that is unacceptable, pre-stage the profile in the LINBO image or move the student network
> to WPA2-Enterprise.


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

### Veyon bandwidth

Active automatically with Veyon (pack `10b-veyon-bandwidth-schule`), tunable in `site.yaml`:

```yaml
veyon_monitoring_interval_ms: 2000   # thumbnail refresh (Veyon default 1000)
veyon_monitoring_quality: 3          # thumbnails   0=Highest(lossless) .. 4=Lowest
veyon_remote_quality: 2              # remote view  (Veyon default 0 = lossless!)
```

**Veyon has no "lower the resolution" setting, and cannot usefully have one.** The Master
receives every student's *full* framebuffer and only scales it down locally afterwards; the
thumbnail size is a per-user JSON setting, not a registry value. Smaller tiles save nothing on
the wire. The two levers that work are how *often* a frame is fetched and how *hard* it is
compressed - which is what this pack sets. Roughly 3-5x less traffic in a busy room.

Both keys are read by the Veyon **Master**, i.e. the teacher's PC, so that machine must be in
the school's `OU=Devices` - which it is when teachers use the ordinary classroom computers.
The interval is then pushed to the clients, whose Veyon Server discards early update requests
itself, so the traffic is never generated in the first place.

Needs **Veyon >= 4.8 on both sides**: against a client reporting older, the master silently
falls back to lossless. Check with `veyon-cli config get Core/ApplicationVersion`.

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

```yaml
ntp_mode: ntp     # default: explicit NTP against the server. Alternative: nt5ds
```

**Why plain NTP is the default.** `nt5ds` is Microsoft's "domain way": the client takes the
time from the domain hierarchy and *requires* the reply to be signed with its computer
account. A Samba DC can only sign through `ntpd`'s `ntpsigndsocket`, and that chain breaks
easily on a stock Ubuntu 24.04 server. When it does, the client rejects every reply and stays
on `Local CMOS Clock` **forever** while drifting past the 5-minute Kerberos limit -- with no
error anywhere, because the GPO itself is applied correctly. Observed in the field.

Two known causes, both server-side:
- `ntpd` applies only the **most specific** matching `restrict` line and *replaces* its
  flags. A bare `restrict 10.10.40.0/24` therefore strips `mssntp` for exactly that subnet,
  even though `restrict -4 default ... mssntp` is present.
- Ubuntu 24.04 ships **ntpsec 1.2.2**, whose MS-SNTP handling is reported broken (fixed
  upstream in 1.2.3).

Diagnose it on a client with `w32tm /query /source`. If it says `Local CMOS Clock` while
`w32tm /stripchart /computer:<server> /samples:3` returns values, plain NTP works and only
the signing is failing -- which is exactly what `ntp_mode: ntp` sidesteps.

Switch to `nt5ds` only once a client really shows the server as its source. **Trade-off:**
with plain NTP the time is not authenticated, so someone on the LAN could spoof NTP replies.



Fixes "not all clocks are correct" (always active). **Core fix:**
`MaxPos/NegPhaseCorrection = 0xFFFFFFFF` → W32Time also corrects **large offsets** (typical
for dead BIOS/CMOS batteries); without it a client that drifted far simply never catches up.
Clients only (linked at `OU=SCHOOLS`); the DC stays untouched.
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

## Checking the prerequisites (automatic)

`lmn-gpo doctor` resolves every security-filter group from your real `site.yaml` and fails
(exit 1) when an **exclusion** matches nothing — because that is the silent case: the GPO then
applies to exactly the devices it was meant to spare.

```
Security-filter prerequisites (from site.yaml):
  config: /etc/linuxmuster/lmn-gpo/site.yaml
  teacher-notebook group (teachernb): 'd_lehrer-nb'
  ✗ 12-proxy-base   GLOBAL   exclude   @teachernb  → applies to them anyway!
```

The same block is printed by `lmn-gpo apply` **before the first change**, so a broken
`teachernb` or a school without a noPXE group shows up before anything is written rather than
afterwards. `lmn-gpo env` additionally flags any school that has no noPXE group at all.

## Checking on the client

`scripts/lmn-gpo-check.ps1` checks **on the Windows client** (read-only) whether the policies
have arrived **and take effect** — covering all 32 packages: `gpresult` (computer **and**
user), registry actual values, firewall, local groups, KMS (Windows **and** Office),
hotspot, OneDrive, hibernation,
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
- [Features (32 Pakete)](#features-32-pakete)
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

## Features (32 Pakete)

**Immer aktiv** (kein zusätzlicher Parameter nötig):

| Paket | Wirkung |
|---|---|
| **Datenschutz / Telemetrie** | Telemetrie, Werbe-ID, Aktivitätsverlauf, Standort, Input-Sammlung, „Find my device", KI-Datenanalyse aus |
| **Microsoft-Konten blockieren** | keine MS-Konten-Anmeldung, nur lokale/Domänen-Konten |
| **OneDrive deaktivieren** | OneDrive-Autostart & Datei-Sync aus |
| **First-Run / OOBE / Consumer** | „Fertig einrichten", Spotlight, Cortana, Consumer-Features, Edge-/Erstlauf-Assistenten aus |
| **Windows-Update-Split** | **aus für LINBO-Rechner**, **an für Nicht-LINBO-Geräte** (`d_nopxe`) |
| **Energie** | kein Standby, **Display geht nie aus** (`display_off_seconds`, 0 = nie) — *lockerer für Lehrer-Notebooks* |
| **Bildschirmsperre** | Sperre nach 30 Min Inaktivität — *lockerer für Lehrer-Notebooks* |
| **Ruhezustand aus** | Hibernate deaktiviert — *außer `d_nopxe`* |
| **Wake-on-LAN + Fast Startup aus** | WoL scharf (Startskript), `HiberbootEnabled=0` |
| **Remote-Management** | RDP aktiv, Firewall-Ausnahmen (RDP/SMB/RPC/ICMP), Remote-Shutdown-Recht |
| **Globale Admins** | `global-admins` als lokale Admins + RDP **überall** |
| **Schul-Admins** | `<schule>-admins` als lokale Admins + RDP **je Schule** |
| **Mobiler Hotspot verbieten** | Windows-Hotspot / ICS auf **allen** Rechnern gesperrt (Schalter ausgegraut) — keine Ausnahme |
| **Schüler-Lockdown** | Schüler (`role-student`) können sensible Einstellungen nicht ändern — v. a. den **Proxy nicht rausnehmen** (+ Verbindungen-Tab/PAC & Registry-Editor gesperrt); **Lehrer/Admins uneingeschränkt** (Loopback + Filter) |
| **Zeitsynchronisation (W32Time)** | Clients synchen per explizitem **NTP** vom Server (`ntp_mode`, Standard); **korrigiert auch große Versätze** (leere CMOS-Batterie); `nt5ds` möglich, wo MS-SNTP-Signierung funktioniert |

**Optional** (per `site.yaml` / Setup-Assistent aktiviert):

| Paket | Aktiviert durch | Wirkung |
|---|---|---|
| **KMS-Aktivierung (Windows)** | `kmshost` | Windows gegen den KMS-Host aktivieren (Startskript) |
| **KMS-Aktivierung (Office)** | `kms_office_host` (oder `kmshost`) | Volumen-Office aktivieren — eigener Registry-Schlüssel, eigenes Startskript |
| **Branding pro Schule** | Wallpaper-Datei | Desktop- **und** Anmelde-Hintergrund je Schule (aus NETLOGON) |
| **Veyon** | `veyon_binddn` + Passwort | Klassenraum-Steuerung, LDAP-Directory, Roaming, **nur Lehrer** (`role-teacher` + `all-teachers`); bandbreitenoptimiertes Monitoring |
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

kmshost: "kms.schule.de"      # leer = kein KMS (Windows)
kms_port: "1688"              # Windows-KMS-Port
kms_office_host: ""           # leer = kmshost verwenden; nur für einen eigenen Office-KMS setzen
kms_office_port: "1688"       # Office-KMS-Port
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
display_off_seconds: 0        # Display nach N s abschalten; 0 = nie (Sperre bleibt, siehe 04)
ntp_mode: ntp                 # Zeitsync: ntp (expliziter Server, Standard) | nt5ds (signiert, braucht ntp_signd)

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
kmshost: "kms.schule.de"       # Windows
kms_office_host: ""            # Office — leer = derselbe Host wie Windows
kms_port: "1688"               # optional
kms_office_port: "1688"        # optional
```
Setzt den KMS-Host und aktiviert Windows per Startskript (`slmgr /ato`).

**Office braucht einen eigenen Eintrag.** Windows und Office sind getrennte Produkte mit
getrennten Registry-Schlüsseln — die Windows-Einstellung aktiviert Office *nicht*:

| | Registry-Schlüssel (HKLM) |
|---|---|
| Windows | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform` |
| Office | `Software\Microsoft\OfficeSoftwareProtectionPlatform` |

Da meist ein KMS-Server beides aktiviert, fällt `kms_office_host` auf `kmshost` zurück,
solange es leer bleibt; setze es nur, wenn Office über einen *anderen* Host läuft. Der
Assistent fragt beides ab und akzeptiert `host` oder `host:port`.

Abgedeckt ist volumenlizenziertes **Office LTSC 2024 / LTSC 2021 / 2019 / 2016** (MSI *und*
Click-to-Run, inkl. Project und Visio). Volumen-Office bringt seinen Produktschlüssel (GVLK)
bereits mit, es ist also nichts weiter nötig. **Microsoft 365 Apps** (Abo) wird gar nicht per
KMS aktiviert und automatisch übersprungen. Eine ADMX-Richtlinie dafür gibt es nicht — die
offiziellen Office-Vorlagen enthalten keine einzige KMS-Einstellung, die Registry-Werte sind
also der einzige Gruppenrichtlinien-Weg.

Zwei Betriebshinweise, die die meisten „aktiviert nicht"-Fälle erklären:
- **Unterschiedliche Schwellen:** Office aktiviert, sobald der KMS-Host **≥ 5** Clients
  gezählt hat, Windows braucht **≥ 25**.
- **Die Werte tätowieren.** Beide Schlüssel liegen außerhalb der vier `…\Policies\…`-Zweige
  und werden daher *nicht* zurückgenommen, wenn die GPO nicht mehr greift. Das Leeren von
  `kms_office_host` entfernt die GPO auf dem Server (siehe unten); auf einem Client räumt
  `ospp.vbs /remhst` (Office) bzw. `slmgr.vbs /ckms` (Windows) auf.

> Das Leeren einer Einstellung wirkt jetzt wirklich: Ein Paket, dessen Voraussetzung
> weggefallen ist, wird beim nächsten `apply` **entlinkt und gelöscht**, statt still den
> alten Wert weiter auszurollen.

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

**Lehrer-Notebooks (`teachernb`, standardmäßig die Gerätegruppe `d_nopxe`) sind von allen
Proxy-Paketen ausgenommen.** Sie verlassen das Schulnetz, wo der Schul-Proxy nicht erreichbar
ist — und weil der Proxy im echten WinINET-Schlüssel landet (nicht unter `…\Policies\…`),
*tätowiert* er: er bliebe auswärts gesetzt und schnitte das Notebook vom Internet ab.

> Tragen diese Notebooks aus einem früheren Rollout schon einen Proxy, räumt das Entfernen der
> Richtlinie ihn **nicht** weg. Einmalig pro betroffenem Profil zurücksetzen, z. B.
> `reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /f`.

## WLAN: mehrere Netze & Roaming

### Lehrer-WLAN (WPA2-Enterprise) unter linuxmuster

RADIUS-EAP-CA auf dem Server exportieren und dem Toolkit den Pfad geben — alles, was man sonst
am Client durchklickt, erledigt dann die GPO:

```bash
lmnradius ca export --out /etc/linuxmuster/lmn-gpo/eap-ca.pem
```
```yaml
wlan_enterprise_networks:
  - ssid: "MSG-LEHRER"
    servernames: "radius.evsvbz.org"
    ca_cert: "/etc/linuxmuster/lmn-gpo/eap-ca-msg.pem"
  - ssid: "GSG-LEHRER"
    servernames: "radius-gsg.evsvbz.org"
    ca_cert: "/etc/linuxmuster/lmn-gpo/eap-ca-gsg.pem"
```

One entry per site, **each with its own RADIUS CA** (sites sharing a RADIUS just reference the
same file). Order is the connection preference. Because the pack is `scope: global` and
filtered to `@teachernb`, **every teacher notebook receives all of these profiles and all of
these CAs** — so a teacher roaming to another school connects there too. The older single-key
form (`wlan_enterprise_ssid` / `_servernames` / `_ca_cert`) still works and is folded into a
one-element list.
```bash
lmn-gpo apply --pack 13-wlan-enterprise --yes
```

| Schritt von Hand | Was das Paket macht |
|---|---|
| CA in **Lokaler Computer** → Vertrauenswürdige Stammzertifizierungsstellen | `certutil -addstore -f Root`, läuft als SYSTEM = Maschinenspeicher |
| Nur diese eine Stamm-CA anhaken | `TrustedRootCA=<SHA-1>` pinnt genau dieses Zertifikat |
| Servername eintragen | `ServerNames` |
| „Benutzer bei neuen Servern fragen" **aus** | `DisableUserPromptForServerValidation=true` |
| SSO-Häkchen | `singleSignOn` / `preLogon` |

`apply` gibt aus, welches Zertifikat gepinnt wird (`RADIUS CA pinned: subject=... SHA1 ...`) —
prüf dort, dass es wirklich die *EAP-CA* ist. Eine falsche Datei wurde früher stillschweigend
akzeptiert und ergab einen Fingerabdruck über Datenmüll; der Client verweigert dann die
Verbindung **ganz ohne Rückfrage**, weil das Nachfragen bewusst abgeschaltet ist. Das ist jetzt
ein harter Fehler.

> **Das Lehrer-WLAN kann nicht vor dem Login stehen, daran ändert keine Einstellung etwas.** Es
> authentifiziert den *Benutzer* (`authMode=user`), und vor der Anmeldung gibt es keinen.
> `preLogon` heißt: Die 802.1X-Anmeldung läuft *während* der Windows-Anmeldung mit den gerade
> eingetippten Daten — nicht, dass die Verbindung am Anmeldebildschirm schon steht. Die erste
> Lehrer-Anmeldung auf einem Notebook braucht deshalb einmal Kabel oder ein anderes Netz. Nur
> eine *Computerkonto*-Authentifizierung würde früher verbinden, dafür braucht der RADIUS eine
> Richtlinie für Domänencomputer.



> **Aufteilung der zwei Pakete.** `13-wlan-psk` verteilt die PSK-Netze als **All-User-Profile
> (Maschinenprofile)**, LINBO/PXE-Rechner verbinden sich also **vor dem Login**. Ausgeliefert
> wird per **selbstheilender geplanter Aufgabe** (`LMN-GPO-WlanProfiles`, Boot + alle 15 Min +
> Anmeldung), nicht als Einmalschuss beim Start: `netsh` braucht ein WLAN-*Interface*, der
> Profilspeicher liegt pro Interface in `WlanSvc`, und `WlanSvc` ist trigger-gestartet — ein
> reiner Boot-Import tut also stillschweigend nichts, wenn der Adapter noch nicht da ist. Die
> Aufgabe startet zusätzlich `WlanSvc`, aktiviert einen deaktivierten Adapter und setzt die
> Verbindungsreihenfolge (erstes Netz aus `wlan_psk_networks` = Priorität 1). Log:
> `%SystemRoot%\Temp\lmn-gpo-wlan.log`.
> `13-wlan-enterprise` authentifiziert den Benutzer (PEAP + SSO `preLogon`), Lehrer-
> Notebooks verbinden sich daher **beim** Login, nicht davor. Beide Ausschlüsse folgen
> `teachernb` (standardmäßig die Gerätegruppe `d_nopxe`).
>
> **Das Schüler-PSK ist vor deinen Schülern kein Geheimnis.** Es steht im Klartext im Profil-
> XML innerhalb des Startskripts in sysvol. `filter_deny_read: ['@role-student']` entzieht
> Schülern den Lesezugriff auf das GPO-*Objekt*, aber `samba-tool ntacl sysvolreset` schreibt
> eine feste ACL-Vorlage, in der Authenticated Users Lesezugriff auf die *Datei* behalten —
> auf einem echten DC nachgemessen. Wenn das nicht akzeptabel ist: Profil ins LINBO-Image
> vorbereiten oder das Schülernetz auf WPA2-Enterprise umstellen.


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

### Veyon-Bandbreite

Automatisch mit Veyon aktiv (Paket `10b-veyon-bandwidth-schule`), in `site.yaml` anpassbar:

```yaml
veyon_monitoring_interval_ms: 2000   # Kachel-Aktualisierung (Veyon-Default 1000)
veyon_monitoring_quality: 3          # Kacheln       0=Highest(verlustfrei) .. 4=Lowest
veyon_remote_quality: 2              # Fernzugriff   (Veyon-Default 0 = verlustfrei!)
```

**Veyon kennt keine „Auflösung heruntersetzen"-Einstellung und kann sinnvollerweise keine
haben.** Der Master empfängt von jedem Schüler-PC das *vollständige* Bild und verkleinert es
erst danach lokal; die Kachelgröße ist eine Benutzer-JSON-Einstellung, kein Registry-Wert.
Kleinere Kacheln sparen also nichts auf der Leitung. Die beiden wirksamen Hebel sind, *wie oft*
ein Bild geholt und *wie stark* es komprimiert wird — genau das setzt dieses Paket. Grob 3-5×
weniger Last in einem belebten Raum.

Beide Schlüssel liest der Veyon-**Master**, also der Lehrer-PC — dieser Rechner muss in der
`OU=Devices` der Schule stehen, was zutrifft, wenn Lehrer die normalen Klassenraum-Rechner
nutzen. Das Intervall wird anschließend an die Clients weitergereicht, deren Veyon-Server zu
frühe Anfragen selbst verwirft; die Daten entstehen also gar nicht erst.

Braucht **Veyon >= 4.8 auf beiden Seiten**: Meldet sich ein Client als älter, fällt der Master
stillschweigend auf verlustfrei zurück. Prüfen mit `veyon-cli config get Core/ApplicationVersion`.

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

```yaml
ntp_mode: ntp     # Standard: expliziter NTP gegen den Server. Alternative: nt5ds
```

**Warum normales NTP der Standard ist.** `nt5ds` ist Microsofts „Domänen-Weg": Der Client holt
die Zeit aus der Domänenhierarchie und *verlangt*, dass die Antwort mit seinem Computerkonto
signiert ist. Ein Samba-DC kann das nur über den `ntpsigndsocket` von `ntpd`, und diese Kette
bricht auf einem Ubuntu-24.04-Server leicht. Passiert das, verwirft der Client jede Antwort und
bleibt **dauerhaft** auf `Local CMOS Clock`, während die Uhr über die 5-Minuten-Kerberos-Grenze
wegläuft — ohne Fehlermeldung, denn die GPO selbst ist korrekt angekommen. Im Feld beobachtet.

Zwei bekannte Ursachen, beide serverseitig:
- `ntpd` wendet nur die **spezifischste** passende `restrict`-Zeile an und *ersetzt* deren
  Flags. Ein nacktes `restrict 10.10.40.0/24` nimmt damit genau diesem Subnetz das `mssntp`,
  obwohl `restrict -4 default ... mssntp` in der Datei steht.
- Ubuntu 24.04 liefert **ntpsec 1.2.2** aus, dessen MS-SNTP-Behandlung als defekt gemeldet ist
  (upstream erst ab 1.2.3 behoben).

Diagnose am Client mit `w32tm /query /source`. Steht dort `Local CMOS Clock`, während
`w32tm /stripchart /computer:<server> /samples:3` Werte liefert, funktioniert normales NTP und
nur die Signierung scheitert — genau das umgeht `ntp_mode: ntp`.

Auf `nt5ds` erst umstellen, wenn ein Client den Server wirklich als Quelle anzeigt.
**Abwägung:** Bei normalem NTP ist die Zeit nicht authentifiziert, jemand im LAN könnte also
NTP-Antworten fälschen.



Behebt „nicht alle Uhrzeiten stimmen" (immer aktiv). **Kern-Fix:**
`MaxPos/NegPhaseCorrection = 0xFFFFFFFF` → W32Time korrigiert **auch große Versätze** (typisch
bei leeren BIOS/CMOS-Batterien); ohne das holt ein weit abgedrifteter Client nie wieder auf.
Nur für Clients (an `OU=SCHOOLS`); der DC bleibt unberührt.
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

## Voraussetzungen prüfen (automatisch)

`lmn-gpo doctor` löst jede Security-Filter-Gruppe aus deiner echten `site.yaml` auf und
scheitert (Exit 1), wenn ein **Ausschluss** ins Leere greift — das ist der stille Fall: die
GPO gilt dann genau für die Geräte, die sie aussparen sollte.

```
Security-filter prerequisites (from site.yaml):
  config: /etc/linuxmuster/lmn-gpo/site.yaml
  teacher-notebook group (teachernb): 'd_lehrer-nb'
  ✗ 12-proxy-base   GLOBAL   exclude   @teachernb  → applies to them anyway!
```

Denselben Block gibt `lmn-gpo apply` **vor der ersten Änderung** aus — ein kaputtes
`teachernb` oder eine Schule ohne noPXE-Gruppe fällt also auf, bevor etwas geschrieben wird.
`lmn-gpo env` markiert zusätzlich jede Schule, die gar keine noPXE-Gruppe hat.

## Prüfen am Client

`scripts/lmn-gpo-check.ps1` prüft **auf dem Windows-Client** (rein lesend), ob die Richtlinien
angekommen sind **und wirken** — deckt alle 32 Pakete ab: `gpresult` (Computer **und** User),
Registry-Ist-Werte, Firewall, lokale Gruppen, KMS (Windows **und** Office), Hotspot,
OneDrive, Ruhezustand, Loopback,
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
