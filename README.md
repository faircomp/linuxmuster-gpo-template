# linuxmuster-gpo-template

Ein wiederverwendbares **Group-Policy-Template-Toolkit** für **linuxmuster.net 7.x**
(Ubuntu 24.04 + Samba 4.19 Active-Directory-DC). Es erstellt, verlinkt und berechtigt
Windows-11-Gruppenrichtlinien **direkt vom Linux-Server aus** – ohne Windows-GPMC –
und ist **Multischule-fähig** (mehrere Schulen pro Server sowie identisches Ausrollen
über viele Kunden-Server hinweg).

> **Status: fertig & verifiziert.** 29 Policy-Pakete, idempotent, mit `--dry-run`.
> End-to-End gegen eine echte linuxmuster-7.3-Instanz getestet: anlegen → idempotenter
> Re-Run (0 Änderungen) → `sysvolcheck`/`aclcheck`/`dbcheck` sauber → restlos entfernen.

## Warum das funktioniert

Damit ein Windows-Client eine vom Samba-DC gesetzte GPO anwendet, müssen drei Dinge
konsistent sein: die `Registry.pol` (PReg-Format), die Version in `GPT.INI` **und** im
AD-Attribut `versionNumber`, sowie die passende **Client-Side-Extension-GUID** in
`gPCMachineExtensionNames`. `samba-tool gpo load` erledigt genau das atomar für
Registry-basierte Policies; für Sicherheitseinstellungen (Benutzerrechte, Restricted
Groups), lokale Admins (GPP) und Startskripte schreibt das Toolkit die Dateien selbst und
registriert die jeweilige CSE-GUID. Details: [`docs/`](docs/).

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

Immer aktiv (kein zusätzlicher Parameter nötig):

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
| **Zeitsynchronisation (W32Time)** | Clients synchen vom Domänen-Server (NT5DS, „Samba-Weg"); **korrigiert auch große Versätze** (leere CMOS-Batterie); Umschaltbar auf expliziten NTP via `ntp_mode` |

Optional (per `site.yaml` / Setup-Assistent aktiviert):

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
| **UEFI-Bootreihenfolge PXE zuerst** | `bootorder_pxe_first: true` | Startskript (SYSTEM, jeder Boot) zwingt Netzwerk/PXE an die erste Stelle (→ LINBO), falls Windows sich vordrängt; robuste Muster-Erkennung, idempotent. **Hardwareabhängig — erst auf 1 Gerät testen** |

## Nutzung

Auf dem Schulserver als **root** ausführen.

```bash
# 1) Umgebung prüfen und ansehen
./lmgpo-cli doctor            # Umgebungs-Selbstcheck (read-only)
./lmgpo-cli env               # erkannte Umgebung (Realm, Schulen, Gruppen, SIDs)
./lmgpo-cli list              # vorhandene GPOs + Verlinkungen

# 2) Interaktiv einrichten (fragt nur die Entscheidungen, zeigt Dry-Run,
#    speichert die Antworten nach /etc/linuxmuster/lmgpo/site.yaml)
./lmgpo-cli setup

# 3) Oder unattended aus einer site.yaml anwenden
./lmgpo-cli apply --config site.yaml --dry-run   # Vorschau, nichts ändern
./lmgpo-cli apply --config site.yaml --yes       # wirklich anwenden

# gezielt einzelne Schulen / Pakete
./lmgpo-cli apply --config site.yaml --school schule-a --pack 02-updates --yes

# 4) Wieder entfernen (nur die LMN-*-GPOs des Toolkits)
./lmgpo-cli remove --dry-run
./lmgpo-cli remove --yes
```

**Idempotent:** `apply` beliebig oft ausführen – ein zweiter Lauf erzeugt keine neuen
GPOs, schreibt keine Registry-Werte neu und bumpt keine Versionen; nur echte Abweichungen
werden korrigiert.

Weitere Kommandos:

```bash
./lmgpo-cli selftest --yes                        # nicht-destruktiver E2E-Test der Engine
./lmgpo-cli veyon-encrypt-password                # Bind-Passwort für site.yaml verschlüsseln
```

## Konfiguration (`site.yaml`)

Der Setup-Assistent erzeugt die Datei; sie lässt sich auch von Hand pflegen und pro Kunde
wiederverwenden. Wichtigste Schlüssel:

```yaml
schools: null                 # null = alle erkannten Schulen, sonst [schule-a, schule-b]
packs: null                   # null = ganzer Katalog, sonst Liste von Pack-IDs
fwsource: serverip            # Firewall-Quelle: serverip | subnet | <IP/CIDR>
teachernb: nopxe              # Lehrer-Notebook-Gruppe (lockerere Energie/Sperre)

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

veyon_binddn: "CN=global-veyon,OU=Management,OU=GLOBAL,DC=..."
veyon_bindpw_hex: "…"         # via ./lmgpo-cli veyon-encrypt-password

wlan_psk_networks:                       # beliebig viele — je Standort ein Eintrag
  - { ssid: "MSG-LINBO", psk: "…" }
  - { ssid: "GSG-LINBO", psk: "…" }
wlan_enterprise_ssid: "Lehrer-WLAN"
wlan_enterprise_servernames: "radius.schule.de"
wlan_enterprise_ca_cert: "/pfad/zur/radius-ca.pem"

bootorder_pxe_first: false    # true = UEFI-Bootreihenfolge per Startskript auf Netzwerk/PXE zuerst
ntp_mode: nt5ds               # Zeitsync: nt5ds (Domäne/Samba-Weg) | ntp (expliziter Server = @serverfqdn)
```

> `site.yaml` enthält Geheimnisse (PSKs, verschlüsseltes Bind-Passwort) und ist in
> `.gitignore` — **nicht** einchecken.

## WLAN: mehrere Netze & Roaming

Mehrere Schüler-WLANs (z. B. je Standort ein eigenes) sind einfach **mehrere Einträge**
in `wlan_psk_networks` — der Setup-Assistent fragt nur eines ab, weitere trägst du in der
`site.yaml` nach:

```yaml
wlan_psk_networks:
  - { ssid: "MSG-LINBO", psk: "PSK-für-MSG" }
  - { ssid: "GSG-LINBO", psk: "PSK-für-GSG" }
```

Das Pack `13-wlan-psk` ist bewusst **global**: **alle** PSK-Profile landen als Maschinen-
Profile (`connectionMode auto`, verbinden vor dem Login) auf **jedem** Schüler-Gerät —
außer Lehrer-Notebooks (`d_nopxe`). Dadurch **roamt** ein Notebook automatisch: es verbindet
sich an jedem Standort mit der SSID, die dort in Reichweite ist (am MSG-Standort mit
`MSG-LINBO`, mitgenommen nach GSG mit `GSG-LINBO`) — ohne Zutun.

> Der Preis des Roamings: jedes Gerät trägt **alle** PSKs im lokalen Profilspeicher. Eine
> strikte Pro-Schule-Isolierung (Gerät kennt nur seinen Heim-PSK) würde das Roaming
> ausschließen — beides zugleich geht technisch nicht.

## Veyon (Klassenraum-Steuerung)

Vollständig per Registry-GPO (kein `config.json`, dateiloses LDAP-Directory), Multischule-fähig
mit Roaming: `BaseDN` = Domänenwurzel, `ComputerTree` pro Schule (Raumliste schulscharf),
Gruppen/Nutzer global — ein Lehrer darf so an **jeder** Schule den Master öffnen.

- **Zugriff nur für Lehrer:** autorisiert `all-teachers` **und** `role-teacher`. Wichtig — die
  Gruppen stehen als **BaseDN-relative DNs** (`CN=role-teacher,OU=Groups,OU=GLOBAL`, ohne `,DC=…`),
  weil Veyon intern so vergleicht; `QueryNestedUserGroups=true` löst auch verschachtelte
  Mitgliedschaft (`<schule>-teachers` → `all-teachers`) auf. Ein Schüler ist in keiner der
  Gruppen → kann nie steuern.
- **Bind-User** `global-veyon` (dediziert, read-only); Passwort mit `./lmgpo-cli
  veyon-encrypt-password` verschlüsseln und als `veyon_bindpw_hex` in die `site.yaml`. Hinweis:
  Veyons Bind-Passwort ist mit einem statischen, öffentlichen Schlüssel verschlüsselt — also
  umkehrbar; den Bind-User eng berechtigt halten (Details: [`docs/VEYON-PLAN.md`](docs/VEYON-PLAN.md)).
- **Windows-Firewall** bleibt für Veyon (Port 11100) offen; die Standort-Trennung macht die
  OPNsense, nicht Windows.
- **Nach dem Ausrollen:** auf den Clients `gpupdate /force` und den **Veyon-Dienst neu starten**
  (Reboot) — Veyon liest die Config nur beim Dienststart.

## Schüler-Lockdown

Zwei Pakete sorgen dafür, dass **nur Schüler** (`role-student`) bestimmte Windows-Einstellungen
nicht ändern können, **Lehrer und Admins aber uneingeschränkt** bleiben:

- `15-lockdown-base` (Computer): aktiviert **Loopback-Merge** (`UserPolicyMode=2`), damit
  benutzerbasierte, rollengefilterte Richtlinien auf gemeinsam genutzten Klassenrechnern greifen.
- `15-lockdown-student` (User, exklusiv auf `role-student`): reine HKCU-Policies —
  **Proxy nicht änderbar** (Einstellungen-App *und* Internetoptionen), Verbindungen-Tab & PAC/
  Autoconfig gesperrt, **Registry-Editor** gesperrt (damit die Sperren nicht ausgehebelt werden).

Weil exklusiv auf `role-student` gefiltert wird, sind Lehrer/Admins nicht Mitglied → für sie
gilt nichts davon. Bewusst **moderat** gehalten (die Systemsteuerung wird *nicht* komplett
gesperrt). Strenger geht per zusätzlicher HKCU-Einträge in `catalog/15-lockdown-student.yaml`,
z. B.:

| Wirkung | Registry (`class: user`) |
|---|---|
| Systemsteuerung + Einstellungen ganz ausblenden | `…\Policies\Explorer\NoControlPanel = 1` |
| Eingabeaufforderung sperren | `…\Policies\Microsoft\Windows\System\DisableCMD = 1` |
| Task-Manager sperren | `…\Policies\System\DisableTaskMgr = 1` |
| Hintergrundbild-Wechsel sperren | `…\Policies\ActiveDesktop\NoChangingWallPaper = 1` |

## Client-seitige Prüfung

`scripts/lmgpo-check.ps1` prüft **auf dem Windows-Client** (read-only), ob die Richtlinien
angekommen sind: `gpresult`-Auswertung, Registry-Stichproben, Energie/Sperre, Proxy,
Firefox, Veyon und ein **WLAN-Abschnitt** (Profile, Auth-Typ, aktuelle Verbindung,
optional RADIUS-CA im Trusted-Root-Store). Erzeugt zusätzlich einen HTML-Report.

```powershell
.\lmgpo-check.ps1 -WlanCaSubject "meine-schul-ca"
```

## Anforderungen

linuxmuster.net 7.x Samba-AD-DC, Python ≥ 3.10, `python3-yaml`, `samba` Python-Bindings,
`samba-tool` (Samba ≥ 4.16 für `gpo load`), `openssl` (für Veyon-/WLAN-Zertifikate).
Läuft als root auf dem DC.

## Verzeichnisstruktur

```
lmgpo/        Python-Engine + CLI (gpo, apply, env, catalog, veyon, wlan, setup, cli)
catalog/      29 YAML-Policy-Pakete
scripts/      Windows-Startskripte + lmgpo-check.ps1 (Client-Diagnose)
lib/          veyon-default-pub.pem (öffentlicher Veyon-Schlüssel)
docs/         RESEARCH.md, VEYON-PLAN.md
wallpapers/   Branding-Bilder je Schule (Bilder nicht eingecheckt)
```
