# validity: Synaptics "Metallica" match-on-host sensors

Driver for the Synaptics 06cb:00a2 "Metallica MOH Touch Fingerprint Reader"
(sensor 57K0 FM-3380-003, type 0x199). According to Lenovo it is found in the
ThinkPad E480, E580, R480, E490, E590, R490 and R590. The driver was developed
and tested on an E480 (ROM 6.7 build 0xa4, patch level 0xd103).

These sensors use the Validity "VSI" protocol, which the
[python-validity](https://github.com/uunicorn/python-validity) project
reverse engineered for the match-on-chip 138a:0090/0097 and 06cb:009a/009d
sensors. The 06cb:00a2 sensor differs from those in three ways:

* It needs its own vendor-signed command blobs and flash layout signature.
* Its firmware does not match fingerprints on the chip. It returns a
  reconstructed 112x112 8-bit image instead. (The Windows driver matches on
  the host, in an Intel SGX enclave.)
* A USB port reset restarts the sensor MCU without re-enumeration, so the
  whole provisioning fits into a single device open.

## Vendor data

The signed blobs and the firmware extension are not redistributable. They are
extracted from Lenovo's driver package (r0yfp10w.exe, driver 5.2.326.26) with

    scripts/validity-extract-vendor-data.py [--installer r0yfp10w.exe]

into `$datadir/libfprint-2/validity/06cb-00a2/`. Both the script and the
driver check every file against a pinned SHA-256 digest.

| File                         | Purpose                                       |
|------------------------------|-----------------------------------------------|
| `init.bin`                   | sent on every open                            |
| `reset.bin`                  | unlocks factory reset and partitioning        |
| `db-write-enable.bin`        | unlocks flash writes                          |
| `partition-signature.bin`    | signature of the flash partition table        |
| `6_07f_lenovo_sm_qm.xpfwext` | firmware extension (uploaded when missing)    |

The blobs depend on the ROM version, and the files above are the ones for
ROM 6.x. The vendor driver also has a second partition table signature,
selected by bit 0x20 of byte 0x17 of the ROM info reply. This driver only
has the one used by the tested sensor.

## Protocol summary

Endpoints: 0x01/0x81 for commands and replies, 0x82 for raw frames
(calibration only) and 0x83 for event packets.

Opening the sensor:

1. USB reset.
2. ROM info (`01`), reset info (`19`), firmware info (`43 02`) and the init
   blob (`06 ...`), all unencrypted.
3. Flash info (`3e`) and the pairing data (flash partition 1).
4. TLS-like handshake.
5. Firmware info, sensor identification (`75`) and the factory calibration
   values (`6f`).
6. Calibration.

The secure channel is a modified TLS 1.2 (ECDH-ECDSA, AES-256-CBC and
HMAC-SHA256 without sequence numbers). Its long-term keys are stored on the
sensor, in partition 1. The host private key there is encrypted with a key
derived from the DMI product name and serial number, so the host keeps no
state. Opening therefore requires root privileges, to read
`/sys/class/dmi/id/product_serial`.

Capturing an image:

1. Start a capture program (`02`). It is built from per-sensor tables, the
   calibration data and the factory calibration values.
2. Wait for the events `00` (started), `02` (finger down) and `03` with bit 2
   of byte 2 set (scan complete).
3. Read the image (`51 <u32 max>`).
4. Stop the program (`04`).

The vendor also has an "enroll" variant of the capture program, with
different image reconstruction settings. Its images match poorly against
"identify" images, so the driver uses the identify program for every capture.

Finger detection is level triggered. A freshly armed program reports "finger
down" within a few ms if a finger rests on the sensor. Lift detection re-arms
the program and waits 300 ms. A detected scan must be completed and its image
read. Aborting it latches the detector, and from then on every new program
reports a finger.

## Provisioning

The driver provisions the sensor during open if the flash has no partitions,
or if the pairing data was written by another host (e.g. Windows, whose
SGX-sealed keys cannot be read):

1. Factory wipe (`reset.bin` and `10`), then a USB reset. This step only runs
   if the sensor was paired with another host.
2. Unlock, then partition the flash with a new client certificate (`4f`).
3. Read the sensor key (`50`) and verify it against the firmware public key.
4. Key exchange, then erase the partitions and write the pairing data.
5. Upload the firmware extension, then a USB reset.

This takes about 15 seconds. It only starts after the vendor data files and
the flash chip have been checked. Provisioning destroys the pairing with any
other operating system, whose driver will in turn re-pair the sensor for
itself.

If a capture fails (e.g. because the sensor lost its session after a power
glitch or a suspend), the next activation resets the sensor and redoes the
handshake before scanning again. Pairing and calibration are kept.

The vendor driver applies a persistent firmware patch to sensors whose ROM
patch level is not 0xd103. This driver does not implement that patch, and
logs a warning for such sensors.

## Calibration

The sensor is calibrated on every open, which takes about 0.6 s. The results
are reproducible to within a few LSB. Each calibration round uses only the
second of its three frames, so the driver accepts the truncated frame stream
the sensor occasionally sends right after a firmware restart.

The resulting "clean slate" reference frame is written to flash partition 6
only if the partition does not already hold a valid one in this driver's
format. This avoids needless flash wear.

## Matching

Images are matched on the host with libfprint's NBIS (bozorth3). The
parameters come from measurements with this sensor:

| Preparation                                  | minutiae | FRR (t=10) | max impostor |
|----------------------------------------------|---------:|-----------:|-------------:|
| native 112x112                               |      6.4 |       100% |            0 |
| 2x upscale                                   |     12.8 |       6.4% |            3 |
| 2x upscale + 16 px edge padding              |     18.1 |       4.9% |            4 |
| **2x + 16 px edge padding + perimeter removal (used)** | **16.5** | **4.9%** | **4** |
| 2x upscale + 32 px edge padding              |     27.0 |         0% |           11 |
| 2x upscale + 32 px flat padding              |     33.4 |         0% |           14 |

The evaluation ran offline with libfprint's minutiae detection and bozorth3:
15 enroll images per template, 300 random templates, 20 genuine and 20
impostor images. Padding with a flat color, or too much padding, creates
artificial minutiae at the same positions in every image, and these match
across different fingers.

The driver uses 2x bilinear upscaling, 16 px edge replication, perimeter
minutiae removal, a bozorth3 threshold of 10 and 15 enroll stages. Live tests
gave 14/14 genuine matches and 0/7 impostor matches, with impostor scores of
0 to 4.

## Security

* Images travel over the secure channel only. The host authenticates the
  sensor through ECDH with the sensor's static key, which the Synaptics
  firmware key signs. A spoofed USB device therefore cannot complete the
  handshake or inject images.
* The record MACs carry no sequence numbers (a property of the sensor
  protocol), so an attacker on the USB bus could replay earlier sensor
  replies within a session.
* The host's pairing key is stored on the sensor, readable without
  authentication. It is encrypted with a key derived from the DMI product
  name and serial number and a constant published by python-validity.
  Someone who knows these values and has access to the sensor can
  impersonate this host to the sensor and read images from it. This matches
  the security level of the vendor's non-SGX driver and of python-validity.
* Provisioning wipes the sensor only after the vendor data and the flash
  chip have been checked, so missing or wrong input cannot leave a sensor
  half provisioned.
* Decrypted records and image buffers are wiped before they are freed.

## Known limitations

* Only the E480 configuration (ROM 6.7, patch level 0xd103, W25Q80B flash)
  has been tested.
* On the last enroll stage, libfprint core may log "Deactivating image device
  while it is not idle". This happens because minutiae detection finishes
  before the finger is lifted, and it is harmless.
* Dual boot with Windows: each OS re-pairs the sensor when it finds it
  paired with the other. Fingerprints then have to be re-enrolled in Windows
  after Linux re-paired the sensor, and vice versa. Linux prints stay valid,
  as they are stored on the host.

## Upstreaming notes

`meson compile sync-udev-hwdb` refreshes the unsupported device list from the
libfprint wiki, which still lists 06cb:00a2. The wiki entry has to be removed
when this driver is merged, otherwise the generated list adds the device back.

## Testing

`tests/test-validity.c` checks the capture program builder and the
calibration math byte for byte against the output of python-validity. It also
covers the pairing data handling and the error paths of the secure channel.

The umockdev test (`tests/validity`) runs with `FP_DEVICE_EMULATION=1`. In
this mode the driver uses a fixed host identity, deterministic randomness and
RFC 6979 signatures (OpenSSL 3.2 or later), so the secure channel traffic
replays byte for byte.

The recording does not contain the vendor init blob. A placeholder of the
same length takes its place, and `tests/validity-replay.py` inserts the blob
from the vendor data directory before the replay. The data directory is the
installed one, or `FP_VALIDITY_DATA_DIR` if set. Without vendor data, the
test is skipped.

To re-record the test on real hardware:

1. Open the sensor once with `FP_DEVICE_EMULATION=1` set. This re-pairs it to
   the test identity, so the recording contains a normal open.
2. As root, run `tests/create-driver-test.py --test custom validity` from the
   build directory. This needs the `usbmon` kernel module. Touch the sensor
   with a knuckle rather than a fingertip.
3. Replace the init blob in the new recording with the placeholder:
   `tests/validity-replay.py --strip tests/validity/custom.pcapng <vendor data dir>`.
4. Open the sensor normally once, to re-pair it with the real host identity.
   Enrolled fingerprints stay valid.
