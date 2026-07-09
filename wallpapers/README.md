# Hintergrundbilder (Desktop + Anmeldebildschirm)

Lege hier pro Schule ein Bild ab. Das Toolkit kopiert es beim `apply` nach
**NETLOGON** (`\\<domain>\NETLOGON\lmgpo-wallpapers\<schule>.<ext>`, für alle
Clients lesbar) und setzt es als **Desktop-Hintergrund** (User) und
**Sperr-/Anmeldebildschirm-Bild** (Computer) für die jeweilige Schule.

## Namensschema

- `wallpapers/<schulname>.jpg` — z. B. `default-school.jpg`, `gym.jpg`
- `wallpapers/default.jpg` — Fallback für Schulen ohne eigenes Bild

Unterstützte Endungen: `.jpg`, `.jpeg`, `.png`, `.bmp`.

Ist für eine Schule kein Bild (und kein `default.*`) vorhanden, wird das
Branding-Paket für diese Schule übersprungen (`requires: wallpaper`).

Ein alternatives Quellverzeichnis lässt sich im Assistenten (bzw. in der
`site.yaml` als `wallpaper_dir`) angeben.

> Empfehlung: 1920×1080 (oder die native Auflösung eurer Geräte), JPG/PNG.
