# linuxmuster-gpo-template

Ein wiederverwendbares **Group-Policy-Template-Toolkit** für **linuxmuster.net 7.x**
(Ubuntu 24.04 + Samba 4.19 Active-Directory-DC). Es erstellt, verlinkt und berechtigt
Windows-11-Gruppenrichtlinien **direkt vom Linux-Server aus** – ohne Windows-GPMC –
und ist **Multischule-fähig** (mehrere Schulen pro Server sowie identisches Ausrollen
über viele Kunden-Server hinweg).

> **Status: fertig & verifiziert.** 24 Policy-Pakete, idempotent, mit `--dry-run`.
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

## Features (24 Pakete)

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

Optional (per `site.yaml` / Setup-Assistent aktiviert):

| Paket | Aktiviert durch | Wirkung |
|---|---|---|
| **KMS-Aktivierung** | `kmshost` | Windows gegen den KMS-Host aktivieren (Startskript) |
| **Branding pro Schule** | Wallpaper-Datei | Desktop- **und** Anmelde-Hintergrund je Schule (aus NETLOGON) |
| **Veyon** | `veyon_binddn` + Passwort | Klassenraum-Steuerung, LDAP-Directory, Roaming, **nur Lehrer** (`role-teacher`) |
| **Firefox-Grundhärtung** | `firefox_enabled` | First-Run aus, saubere New-Tab (Suche + Verknüpfungen, kein Werbekram) |
| **Firefox-Startseite** | `firefox_homepage` | global-Default **oder pro Schule**, optional fest gesperrt |
| **Rollen-Proxy** | `proxy_enabled` + Host | **Adresse folgt dem Gerät** (Schule), **Port folgt dem Nutzer** (Lehrer/Schüler/Staff), roaming-fest; alle Browser auf System-Proxy; Proxy-Host als Intranet-Zone (SSO) |
| **WLAN PSK (Schüler)** | `wlan_psk_networks` | mehrere PSK-Netze als Maschinen-Profil → verbinden **vor dem Login**; *nicht* auf Lehrer-Notebooks |
| **WLAN Enterprise (Lehrer)** | `wlan_enterprise_ssid` + CA-Cert | WPA2-Enterprise/PEAP mit RADIUS, CA-Zertifikat wird installiert; **nur Lehrer** (RADIUS erzwingt Gruppe), exklusiv auf `d_nopxe` |

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

wlan_psk_networks:
  - { ssid: "Schueler-WLAN", psk: "…" }
wlan_enterprise_ssid: "Lehrer-WLAN"
wlan_enterprise_servernames: "radius.schule.de"
wlan_enterprise_ca_cert: "/pfad/zur/radius-ca.pem"
```

> `site.yaml` enthält Geheimnisse (PSKs, verschlüsseltes Bind-Passwort) und ist in
> `.gitignore` — **nicht** einchecken.

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
catalog/      24 YAML-Policy-Pakete
scripts/      Windows-Startskripte + lmgpo-check.ps1 (Client-Diagnose)
lib/          veyon-default-pub.pem (öffentlicher Veyon-Schlüssel)
docs/         RESEARCH.md, VEYON-PLAN.md
wallpapers/   Branding-Bilder je Schule (Bilder nicht eingecheckt)
```
