# libfprint-00a2 — Linux Driver for Synaptics `06cb:00a2` (ThinkPad E480 / E490 / E580 / E590)

Open-source `libfprint` fork with native support for the **Synaptics Metallica MOH (Match-on-Host) Touch Fingerprint Reader** (`USB ID 06cb:00a2`), including support for both sensor revisions **`0190:0061`** and **`0190:006a`** (ROM `6.7`, product `0x30`).

> **Legal & Compliance Notice:** This repository contains **100% open-source code** (LGPL-2.1+). **No proprietary Synaptics or Lenovo binaries/firmware blobs are included.** At install time, `scripts/validity-extract-vendor-data.py` downloads Lenovo's official Windows driver (`r0yfp10w.exe`) directly from Lenovo's servers, verifies every file against pinned SHA-256 digests, and extracts the required firmware blobs locally on your machine.

---

## Supported Hardware

| Attribute | Value |
| :--- | :--- |
| **USB ID (`lsusb`)** | `06cb:00a2` (`Synaptics, Inc. Metallica MOH Touch Fingerprint Reader`) |
| **Sensor Module** | `57K0 FM-3380-003` (type `0x199`) |
| **Supported Revisions** | `0190:0061` and `0190:006a` (ROM `6.7`, product `0x30`) |
| **ThinkPad Models** | ThinkPad E480, E580, R480, E490, E590, R490, R590 |

Verify your hardware before installing:

```bash
lsusb | grep -i 06cb:00a2
```

---

## Architecture

Unlike Match-on-Chip (MOC) readers supported by `python-validity`, the `06cb:00a2` is a **Match-on-Host (MOH)** sensor:

1. **Open-source `libfprint` driver (`validity`):** Handles USB reset, TLS 1.2 secure channel pairing (using DMI-derived host keys), sensor calibration, and `112×112` image capture, followed by host-side matching via `libfprint`'s NBIS (`bozorth3`) engine.
2. **Local firmware extraction:** Uses `scripts/validity-extract-vendor-data.py` + `innoextract` to extract and SHA-256 verify 5 vendor files from Lenovo's `r0yfp10w.exe` into `/usr/share/libfprint-2/validity/06cb-00a2/`:
   * `init.bin`, `reset.bin`, `db-write-enable.bin`, `partition-signature.bin`, `6_07f_lenovo_sm_qm.xpfwext`.
3. **Native `fprintd` integration:** Works directly with your distribution's standard `fprintd` and PAM stack (GNOME, KDE Plasma, `sudo`, Polkit) — no `open-fprintd` replacement needed.

---

## Quick Install (Fedora, Ubuntu/Debian, Arch, openSUSE)

```bash
git clone https://github.com/JonathasHenrique/libfprint-00a2-thinkpad.git
cd libfprint-00a2-thinkpad
chmod +x install.sh
./install.sh
```

If you already downloaded Lenovo's `r0yfp10w.exe` locally, pass it directly:

```bash
./install.sh --installer /path/to/r0yfp10w.exe
```

What `install.sh` does:
1. Detects your distribution via `/etc/os-release` and installs build dependencies.
2. Compiles and installs `libfprint` with the `validity` (`06cb:00a2`) driver.
3. Downloads/verifies `r0yfp10w.exe` (SHA-256) and installs firmware blobs into `/usr/share/libfprint-2/validity/06cb-00a2/`.
4. Reloads `udev` rules, restarts `fprintd`, enables PAM fingerprint support, and locks the `libfprint` package against accidental overwrites.

---

## Post-Installation & Testing

1. **Confirm sensor detection:**
   ```bash
   fprintd-list "$USER"
   ```
   Expected output: `Synaptics Metallica match-on-host sensor (VSI)`.

2. **Enroll your fingerprint:**
   ```bash
   fprintd-enroll
   ```
   * **First open:** Takes ~15 seconds while the driver provisions the sensor and uploads `6_07f_lenovo_sm_qm.xpfwext`.
   * **15 touches:** Lift and slightly shift your finger on each stage until `enroll-completed`. (You can also enroll via GNOME Settings or KDE System Settings → *Users*.)

3. **Verify recognition & `sudo`:**
   ```bash
   fprintd-verify
   sudo -k && sudo true
   ```

---

## Troubleshooting

### Dual Boot with Windows
Each OS pairs the sensor with its own host keys (Windows uses SGX-sealed keys; Linux uses DMI-derived keys). If you boot into Windows and then back into Linux:
* On the next Linux open, the driver automatically detects the foreign pairing, factory-wipes and re-pairs the sensor (~15 s).
* Your **Linux fingerprints remain valid** (they are stored on the Linux host in `/var/lib/fprint/`), while Windows will require re-enrolling fingerprints next time you use it.

### KDE Plasma Initial Login (`plasmalogin`)
KDE's lock screen (`Meta + L`), `sudo`, and Polkit work out of the box. For initial login on Fedora KDE (`plasmalogin`), you can optionally create a local PAM override:

```bash
sudo cp /usr/lib/pam.d/plasmalogin /etc/pam.d/plasmalogin
sudo sed -i '2i auth        sufficient    pam_fprintd.so' /etc/pam.d/plasmalogin
```
*(Press **Enter** with an empty password at login to trigger the fingerprint prompt. To revert: `sudo rm /etc/pam.d/plasmalogin`.)*

### Debug Logs
If enrollment or verification fails, run `fprintd` in debug mode:

```bash
sudo systemctl stop fprintd
sudo G_MESSAGES_DEBUG=all /usr/libexec/fprintd -t
```

---

## Upstream Patch

The standalone patch adding `0190:006a` revision support and threshold tuning is available in [`patches/0001-validity-add-0190-006a-sensor-profile.patch`](patches/0001-validity-add-0190-006a-sensor-profile.patch) for easy submission to upstream [`aurel1510/libfprint-00a2`](https://codeberg.org/aurel1510/libfprint-00a2).

---

## Credits & License

* **Upstream `06cb:00a2` driver:** [Aurel Farkasovsky (`aurel1510/libfprint-00a2`)](https://codeberg.org/aurel1510/libfprint-00a2)
* **VSI protocol reverse engineering:** [`uunicorn/python-validity`](https://github.com/uunicorn/python-validity)
* **Base library:** [freedesktop.org `libfprint`](https://gitlab.freedesktop.org/libfprint/libfprint)
* **License:** LGPL-2.1-or-later (see [`COPYING`](COPYING))
