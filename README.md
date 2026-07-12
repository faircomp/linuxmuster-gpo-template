# linuxmuster-gpo-template

Ein wiederverwendbares **Group-Policy-Template-Toolkit** für **linuxmuster.net 7.x**
(Ubuntu 24.04 + Samba 4.19 Active-Directory-DC). Es erstellt, verlinkt und berechtigt
Windows-11-Gruppenrichtlinien **direkt vom Linux-Server aus** – ohne Windows-GPMC –
und ist **Multischule-fähig** (mehrere Schulen pro Server sowie identisches Ausrollen
über viele Kunden-Server hinweg).

> **Status: fertig & verifiziert.** 29 Policy-Pakete, idempotent, mit `--dry-run`.
> End-to-End gegen eine echte linuxmuster-7.3-Instanz getestet: anlegen → idempotenter
> Re-Run (0 Änderungen) → `sysvolcheck`/`aclcheck`/`dbcheck` sauber → restlos entfernen.

## Inhalt

- [Was das Toolkit macht](#warum-das-funktioniert) · [Konzept](#konzept)
- [Features (29 Pakete)](#features-29-pakete)
- **Anleitung:** [Installation](#installation) → [Schnellstart](#schnellstart) → [Bedienung](#bedienung) → [Konfiguration](#konfiguration-siteyaml)
- **Features einrichten:** [KMS](#kms) · [Branding](#branding-wallpaper--anmeldebild) · [Firefox](#firefox) · [Proxy](#rollen-proxy) · [WLAN](#wlan-mehrere-netze--roaming) · [Veyon](#veyon-klassenraum-steuerung) · [Schüler-Lockdown](#schüler-lockdown) · [Bootreihenfolge](#uefi-bootreihenfolge-pxe-zuerst) · [Zeitsync](#zeitsynchronisation)
- [Ausrollen auf die Clients](#ausrollen-auf-die-clients) · [Prüfen am Client](#prüfen-am-client) · [Update des Toolkits](#update-des-toolkits) · [Troubleshooting](#troubleshooting)
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
- **`lmgpo`-CLI** mit interaktivem **Setup-Assistenten**, **idempotent** (beliebig oft
  ausführbar), überall `--dry-run`, persistente Parameter in `site.yaml`.
- **Dynamische Erkennung**: Realm, Base-DN, Server-IP/Subnetz, Schulen, deren Präfixe,
  Admin-Gruppen, die `d_nopxe`-Gerätegruppe, Rollen-Gruppen und Räume werden live aus dem
  AD gelesen – nichts ist auf `default-school` hartkodiert.
- **Schonend**: rührt `sophomorix:*`- und Default-GPOs nie an, prüft nach jeder Änderung
  ACLs (`aclcheck`/`sysvolcheck`) und gleicht sysvol-Rechte per `sysvolreset` ab.

## Features (29 Pakete)

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

---

# Anleitung

## Installation

Auf dem **linuxmuster-Server (Samba-AD-DC)** als **root**:

```bash
cd /opt
git clone https://github.com/faircomp/linuxmuster-gpo-template.git
cd linuxmuster-gpo-template
./lmgpo-cli doctor          # Umgebungs-Selbstcheck – muss grün sein
```

Es sind keine zusätzlichen Pakete nötig (siehe [Anforderungen](#anforderungen) – Python,
`samba`-Bindings und `samba-tool` bringt linuxmuster mit). `./lmgpo-cli` ist der einzige
Einstiegspunkt.

> **Wichtig – wo liegt die `site.yaml`?**
> Der Assistent speichert deine Einstellungen standardmäßig unter
> **`/etc/linuxmuster/lmgpo/site.yaml`** — bewusst **außerhalb** des Repos. Nur so
> überlebt sie jedes `git pull`/`git clean`. **Lege sie dort ab und wende immer von dort
> an**, dann können Updates deine Konfiguration (inkl. WLAN-Passwörter) nie verlieren.

## Schnellstart

```bash
./lmgpo-cli doctor                     # 1. Umgebung prüfen
./lmgpo-cli setup                      # 2. interaktiv einrichten (fragt nur die Entscheidungen)
                                       #    -> speichert /etc/linuxmuster/lmgpo/site.yaml, zeigt Dry-Run
./lmgpo-cli apply --yes                # 3. anwenden (nutzt automatisch die gespeicherte site.yaml)
```

Danach auf einem Client `gpupdate /force` + Neustart, dann mit
[`lmgpo-check.ps1`](#prüfen-am-client) kontrollieren.

## Bedienung

Alle Kommandos: `./lmgpo-cli <befehl>`. Überall gilt: **read-only-Befehle ändern nichts**,
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
./lmgpo-cli setup
```

Der Assistent erkennt die Umgebung selbst und fragt nur die **Entscheidungen** ab
(Schulen, Pakete, Firewall-Quelle, Lehrer-Notebook-Gruppe, KMS, Wallpaper, Veyon, Firefox,
Proxy, WLAN, Bootreihenfolge). Bei jeder Frage steht der Default in `[…]` — **Enter =
übernehmen**. Beim erneuten Lauf sind **alle bisherigen Antworten vorbefüllt** (inkl.
WLAN-SSIDs + Passwörter). Am Ende: Dry-Run-Vorschau, Speichern, optional anwenden.

### Unattended anwenden

```bash
# Vorschau ohne Änderung (immer zuerst empfohlen):
./lmgpo-cli apply --config /etc/linuxmuster/lmgpo/site.yaml --dry-run

# Wirklich anwenden:
./lmgpo-cli apply --config /etc/linuxmuster/lmgpo/site.yaml --yes

# Nur einzelne Schulen bzw. Pakete:
./lmgpo-cli apply --school msg --pack 02-updates --pack 17-ntp-zeit --yes
```

Ohne `--config` nutzt `apply`/`setup` automatisch `/etc/linuxmuster/lmgpo/site.yaml`.

**Idempotent:** `apply` beliebig oft ausführen – ein zweiter Lauf erzeugt keine neuen GPOs,
schreibt keine Registry-Werte neu und bumpt keine Versionen; nur echte Abweichungen werden
korrigiert.

### Wieder entfernen

```bash
./lmgpo-cli remove --dry-run    # zeigt, was entfernt würde
./lmgpo-cli remove --yes        # entfernt ALLE LMN-*-GPOs restlos (Default-/sophomorix-GPOs bleiben)
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
veyon_bindpw_hex: "…"         # via ./lmgpo-cli veyon-encrypt-password

wlan_psk_networks:                       # beliebig viele — je Standort ein Eintrag
  - { ssid: "MSG-LINBO", psk: "…" }
  - { ssid: "GSG-LINBO", psk: "…" }
wlan_enterprise_ssid: "Lehrer-WLAN"      # leer = kein Enterprise-WLAN
wlan_enterprise_servernames: "radius.schule.de"
wlan_enterprise_ca_cert: "/pfad/zur/radius-ca.pem"

bootorder_pxe_first: false    # true = UEFI-Bootreihenfolge auf Netzwerk/PXE zuerst (opt-in!)
ntp_mode: nt5ds               # Zeitsync: nt5ds (Domäne/Samba-Weg) | ntp (expliziter Server = @serverfqdn)
```

> Die `site.yaml` enthält **Geheimnisse** (WLAN-PSKs, verschlüsseltes Bind-Passwort) und ist
> in `.gitignore` — **nicht** einchecken. Am besten unter `/etc/linuxmuster/lmgpo/` (außerhalb
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
  - { ssid: "MSG-LINBO", psk: "PSK-für-MSG" }
  - { ssid: "GSG-LINBO", psk: "PSK-für-GSG" }
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
./lmgpo-cli veyon-encrypt-password        # Bind-Passwort verschlüsseln -> Hex kopieren
```
```yaml
veyon_binddn: "CN=global-veyon,OU=Management,OU=GLOBAL,DC=..."
veyon_bindpw_hex: "<Hex>"
```

- **Zugriff nur für Lehrer:** autorisiert `all-teachers` **und** `role-teacher` als
  **BaseDN-relative DNs** (`CN=role-teacher,OU=Groups,OU=GLOBAL`, ohne `,DC=…`), weil Veyon
  intern so vergleicht; `QueryNestedUserGroups=true` löst auch verschachtelte Mitgliedschaft auf.
  Ein Schüler ist in keiner Gruppe → kann nie steuern.
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
> `schtasks /query /tn LMGPO-BootOrderPXE` (Task da?) und
> `type %SystemRoot%\Temp\lmgpo-bootorder.log` (hat der Worker die Netzwerk-Einträge gefunden
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

---

## Ausrollen auf die Clients

GPOs wirken erst, wenn der Client sie holt und der jeweilige Dienst sie liest:

1. **Grundsätzlich:** `gpupdate /force`, dann **neu starten** (Computer-Policies + Loopback +
   Start-/Shutdown-Skripte greifen beim Boot).
2. **Veyon:** zusätzlich den **Veyon-Dienst neu starten** (Reboot).
3. **WLAN (PSK/Enterprise):** **Neustart** (Maschinen-Profile werden beim Boot importiert).
4. **Bootreihenfolge:** 2× neu starten, dann `…\Temp\lmgpo-bootorder.log` prüfen.
5. **Zeit:** `gpupdate /force` → `w32tm /config /update` → `w32tm /resync` (oder Neustart).

## Prüfen am Client

`scripts/lmgpo-check.ps1` prüft **auf dem Windows-Client** (rein lesend), ob die Richtlinien
angekommen sind **und wirken** — deckt alle 29 Pakete ab: `gpresult` (Computer **und** User),
Registry-Ist-Werte, Firewall, lokale Gruppen, KMS, Hotspot, OneDrive, Ruhezustand, Loopback,
Firefox, Rollen-Proxy, **Schüler-Lockdown (HKCU)**, Veyon, WLAN (+ RADIUS-CA), **Zeitsync
(w32tm)** und das **Bootorder-Log**. Erzeugt zusätzlich einen HTML-Report.

Am besten **zweimal** ausführen:
```powershell
# 1) als ADMINISTRATOR → Computer-GPOs, Firewall, Gruppen, KMS, Veyon, Zeit, Bootorder
powershell -ExecutionPolicy Bypass -File lmgpo-check.ps1 -Refresh -WlanCaSubject "RADIUS CA"

# 2) als angemeldeter SCHÜLER (nicht elevated) → die User-Sperren (Lockdown/Proxy)
powershell -ExecutionPolicy Bypass -File lmgpo-check.ps1
```
`-Refresh` macht vorher `gpupdate /force` (einzige nicht-lesende Aktion). Ausgabe: `[OK]`/`[!!]`
je Prüfung + Summe.

## Update des Toolkits

```bash
cd /opt/linuxmuster-gpo-template
git pull
./lmgpo-cli apply --config /etc/linuxmuster/lmgpo/site.yaml --dry-run   # was ändert sich?
./lmgpo-cli apply --config /etc/linuxmuster/lmgpo/site.yaml --yes
```

- Ein `git pull` fasst deine `site.yaml` **nicht** an (sie ist gitignored und liegt idealerweise
  unter `/etc/linuxmuster/lmgpo/`). **Vermeide** `git clean -fdx` / `git reset --hard` im
  Repo-Ordner — die löschen ignorierte Dateien und damit eine dort liegende `site.yaml`.
- Nach dem Re-Apply auf den Clients wie oben `gpupdate` + Neustart.

## Troubleshooting

| Symptom | Ursache / Lösung |
|---|---|
| `apply` sagt **„0 GPO(s) angewandt"** | Ein **Opt-in-Pack** ist nicht aktiviert (z. B. `bootorder_pxe_first: true` fehlt), oder `--pack` gefiltert. `grep bootorder site.yaml`. |
| **Einstellungen nach Update weg** | `site.yaml` lag **im** Repo-Ordner und wurde von `git clean`/`reset` gelöscht. → nach `/etc/linuxmuster/lmgpo/` verschieben. |
| **Zwei `site.yaml`** (Assistent vs. `--config`) | `setup` speichert nach `/etc/linuxmuster/lmgpo/`. Immer **dieselbe** Datei anwenden. |
| **Lehrer können Veyon-Master nicht öffnen** | am Client `gpupdate /force` + **Veyon-Dienst neu starten**. Das Toolkit setzt bereits die korrekten **BaseDN-relativen** Gruppen-DNs. |
| **Bootorder-Log: „fehlt ein erforderliches Recht"** | alte Skript-Version. Aktuelles Pack nutzt einen **Scheduled Task** — neu ausrollen; Log auf `Worker (Scheduled Task…)`-Zeilen prüfen. |
| **Uhren falsch** | Pack `17-ntp-zeit` anwenden; am Client `w32tm /resync`. Der `MaxPhaseCorrection`-Fix korrigiert auch Batterie-Rechner. |
| GPO angeblich nicht angewandt | am Client als Admin `gpresult /r`; mit [`lmgpo-check.ps1`](#prüfen-am-client) gegenprüfen; auf `-Refresh` + Neustart achten. |

---

## Anforderungen

linuxmuster.net 7.x Samba-AD-DC, Python ≥ 3.10, `python3-yaml`, `samba` Python-Bindings,
`samba-tool` (Samba ≥ 4.16 für `gpo load`), `openssl` (für Veyon-/WLAN-Zertifikate).
Läuft als root auf dem DC.

## Verzeichnisstruktur

```
lmgpo/        Python-Engine + CLI (gpo, apply, env, catalog, veyon, wlan, scripts_ext, setup, cli)
catalog/      29 YAML-Policy-Pakete
scripts/      Windows-Start-/Shutdown-Skripte + lmgpo-check.ps1 (Client-Diagnose)
lib/          veyon-default-pub.pem (öffentlicher Veyon-Schlüssel)
docs/         RESEARCH.md, VEYON-PLAN.md
wallpapers/   Branding-Bilder je Schule (Bilder nicht eingecheckt)
```
