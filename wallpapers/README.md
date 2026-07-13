# Wallpapers (desktop + logon screen)

Place one image per school here. During `apply` the toolkit copies it to
**NETLOGON** (`\\<domain>\NETLOGON\lmn-gpo-wallpapers\<schule>.<ext>`, readable by all
clients) and sets it as the **desktop wallpaper** (user) and
**lock/logon screen image** (computer) for the respective school.

## Naming scheme

- `wallpapers/<schulname>.jpg` — e.g. `default-school.jpg`, `gym.jpg`
- `wallpapers/default.jpg` — fallback for schools without their own image

Supported extensions: `.jpg`, `.jpeg`, `.png`, `.bmp`.

If no image (and no `default.*`) exists for a school, the branding pack for that
school is skipped (`requires: wallpaper`).

An alternative source directory can be specified in the wizard (or in
`site.yaml` as `wallpaper_dir`).

> Recommendation: 1920×1080 (or the native resolution of your devices), JPG/PNG.
