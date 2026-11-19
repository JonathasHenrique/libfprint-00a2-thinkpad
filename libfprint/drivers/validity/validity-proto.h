/*
 * Synaptics/Validity "VSI" sensors: command encoding, sensor programs and
 * calibration
 *
 * Copyright (C) 2026 Aurel Farkasovsky
 *
 * The protocol knowledge implemented here was originally reverse engineered
 * by the python-validity project (Copyright (c) 2020 uunicorn, MIT License,
 * see LICENSE.python-validity in this directory).
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#pragma once

#include <glib.h>

/* --- Command opcodes ---------------------------------------------------- */

#define VALIDITY_CMD_ROM_INFO 0x01
#define VALIDITY_CMD_CAPTURE 0x02
#define VALIDITY_CMD_CAPTURE_STOP 0x04
#define VALIDITY_CMD_REBOOT 0x05
#define VALIDITY_CMD_EXEC_BLOB 0x06          /* signed vendor blob */
#define VALIDITY_CMD_FACTORY_WIPE 0x10
#define VALIDITY_CMD_RESET_INFO 0x19
#define VALIDITY_CMD_CLEANUP 0x1a            /* commit pending flash ops */
#define VALIDITY_CMD_FLASH_INFO 0x3e
#define VALIDITY_CMD_FLASH_ERASE 0x3f
#define VALIDITY_CMD_FLASH_READ 0x40
#define VALIDITY_CMD_FLASH_WRITE 0x41
#define VALIDITY_CMD_FW_SIGNATURE 0x42
#define VALIDITY_CMD_FW_INFO 0x43
#define VALIDITY_CMD_PARTITION_FLASH 0x4f
#define VALIDITY_CMD_GET_ECDH 0x50
#define VALIDITY_CMD_GET_DATA 0x51           /* program status / image */
#define VALIDITY_CMD_FACTORY_BITS 0x6f
#define VALIDITY_CMD_IDENTIFY_SENSOR 0x75

/* --- Status codes (first two bytes of every plain response, LE) --------- */

#define VALIDITY_STATUS_OK 0x0000
#define VALIDITY_STATUS_NO_FW 0x04b0
#define VALIDITY_STATUS_NOTHING_TO_COMMIT 0x0491
#define VALIDITY_STATUS_FLASH_DENIED 0x0406
#define VALIDITY_STATUS_BLOB_REJECTED 0x04be

/* --- Flash partitions --------------------------------------------------- */

#define VALIDITY_PARTITION_TLS 1
#define VALIDITY_PARTITION_FWEXT 2
#define VALIDITY_PARTITION_TEMPLATES 4
#define VALIDITY_PARTITION_UNKNOWN5 5
#define VALIDITY_PARTITION_CALIBRATION 6
#define VALIDITY_FLASH_CHUNK 0x1000

/* --- Interrupt packets (EP 0x83) ---------------------------------------- */

#define VALIDITY_INT_SCAN_STARTED 0x00
#define VALIDITY_INT_FINGER_DOWN 0x02
#define VALIDITY_INT_SCAN_PROGRESS 0x03
#define VALIDITY_INT_SCAN_COMPLETE_MASK 0x04   /* bit in byte 2 of 0x03 */

typedef struct
{
  guint32 timestamp;
  guint32 build;
  guint8  major;
  guint8  minor;
  guint8  product;
  guint8  flags;        /* byte 0x17 of the reply, selects signing key set */
  guint8  state;        /* low nibble: 7 = operational, 2 = unprovisioned */
  guint16 patch_level;
} ValidityRomInfo;

typedef struct
{
  guint8  id;
  guint8  type;
  guint16 access_lvl;
  guint32 offset;
  guint32 size;
} ValidityPartition;

typedef struct
{
  guint16           jedec_id0;
  guint16           jedec_id1;
  guint16           blocks;
  guint16           blocksize;
  guint             n_partitions;
  ValidityPartition partitions[16];
} ValidityFlashInfo;

typedef struct
{
  const gchar *name;
  guint32      size;
  guint8       jedec_id0;
  guint8       jedec_id1;
  guint32      sector_size;
  guint8       sector_erase_cmd;
} ValidityFlashIc;

typedef struct
{
  gboolean present;
  guint16  major;
  guint16  minor;
  guint16  n_modules;
  guint32  buildtime;
} ValidityFwInfo;

typedef enum {
  VALIDITY_CAPTURE_CALIBRATE,
  VALIDITY_CAPTURE_IDENTIFY,
  VALIDITY_CAPTURE_ENROLL,
} ValidityCaptureMode;

/* Static description of a supported sensor */
typedef struct
{
  guint16       dev_major;            /* from VALIDITY_CMD_IDENTIFY_SENSOR */
  guint16       dev_version;
  guint16       sensor_type;
  const gchar  *name;

  guint8        rom_major;            /* capture program applicability */
  guint8        rom_minor;

  guint16       bytes_per_line;
  guint16       repeat_multiplier;
  guint16       lines_per_calibration_data;
  guint16       line_width;
  guint         key_calibration_line;
  guint         calibration_frames;
  guint         calibration_iterations;

  const guint8 *calibration_blob;
  gsize         calibration_blob_len;
  const guint8 *capture_prog;
  gsize         capture_prog_len;
  const guint8 *finger_detect;        /* chunk 0x4e (identify) / 0x26 (enroll) */
  const guint8 *finger_detect_enroll;
  gsize         finger_detect_len;
  const guint8 *image_recon;          /* chunk 0x2e */
  const guint8 *image_recon_enroll;
  gsize         image_recon_len;
} ValiditySensorProfile;

/* Mutable per-device sensor state used to build capture programs */
typedef struct
{
  const ValiditySensorProfile *profile;
  guint                        lines_per_frame;
  GBytes                      *factory_calibration_values;
  GBytes                      *calib_data;  /* NULL until calibrated */
} ValiditySensor;

typedef struct
{
  guint16 width;
  guint16 height;
  guint16 bpp;
  guint8 *pixels;      /* width * height bytes, owned */
} ValidityImage;

/* --- Generic response helpers ------------------------------------------ */

guint16 validity_rsp_status (const guint8 *rsp,
                             gsize         len);

gboolean validity_check_status (const guint8 *rsp,
                                gsize         len,
                                const gchar  *what,
                                GError      **error);

/* --- Parsers ------------------------------------------------------------ */

gboolean validity_parse_rom_info (const guint8    *rsp,
                                  gsize            len,
                                  ValidityRomInfo *info,
                                  GError         **error);

gboolean validity_parse_flash_info (const guint8      *rsp,
                                    gsize              len,
                                    ValidityFlashInfo *info,
                                    GError           **error);

gboolean validity_parse_fw_info (const guint8   *rsp,
                                 gsize           len,
                                 ValidityFwInfo *info,
                                 GError        **error);

gboolean validity_parse_sensor_id (const guint8 *rsp,
                                   gsize         len,
                                   guint16      *major,
                                   guint16      *version,
                                   GError      **error);

GBytes *validity_parse_factory_bits (const guint8 *rsp,
                                     gsize         len,
                                     guint16       subtag,
                                     GError      **error);

GBytes *validity_parse_flash_read (const guint8 *rsp,
                                   gsize         len,
                                   GError      **error);

GBytes *validity_parse_pairing_cert (const guint8 *rsp,
                                     gsize         len,
                                     GError      **error);

GBytes *validity_parse_ecdh_reply (const guint8 *rsp,
                                   gsize         len,
                                   GError      **error);

gboolean validity_parse_image (const guint8  *rsp,
                               gsize          len,
                               ValidityImage *image,
                               GError       **error);

/* --- Command builders --------------------------------------------------- */

GBytes *validity_cmd_flash_read (guint8  partition,
                                 guint32 addr,
                                 guint32 size);

GBytes *validity_cmd_flash_write (guint8        partition,
                                  guint32       addr,
                                  const guint8 *data,
                                  gsize         len);

GBytes *validity_cmd_fw_signature (guint8        partition,
                                   const guint8 *sig,
                                   gsize         len);

GBytes *validity_cmd_factory_bits (guint16 tag);

GBytes *validity_cmd_get_data (guint32 max_len);

GBytes *validity_cmd_partition_flash (const ValidityFlashIc   *ic,
                                      const ValidityPartition *layout,
                                      guint                    n_partitions,
                                      const guint8            *layout_signature,
                                      gsize                    signature_len,
                                      GBytes                  *client_cert,
                                      const guint8            *ca_blob,
                                      gsize                    ca_blob_len);

/* --- Sensor database ---------------------------------------------------- */

const ValidityFlashIc *validity_flash_ic_lookup (guint16 jedec_id0,
                                                 guint16 jedec_id1,
                                                 guint32 size);

const ValiditySensorProfile *validity_sensor_profile_lookup (guint16                dev_major,
                                                             guint16                dev_version,
                                                             const ValidityRomInfo *rom);

/* --- Capture programs and calibration ----------------------------------- */

void validity_sensor_clear (ValiditySensor *sensor);

gboolean validity_sensor_init (ValiditySensor              *sensor,
                               const ValiditySensorProfile *profile,
                               GBytes                      *factory_calibration_values,
                               GError                     **error);

GBytes *validity_build_capture_cmd (ValiditySensor     *sensor,
                                    ValidityCaptureMode mode,
                                    GError            **error);

gsize validity_calibration_frame_bytes (ValiditySensor *sensor);

gboolean validity_calibration_process (ValiditySensor *sensor,
                                       const guint8   *raw,
                                       gsize           len,
                                       GError        **error);

GBytes *validity_calibration_build_clean_slate (ValiditySensor *sensor,
                                                const guint8   *raw,
                                                gsize           len,
                                                GError        **error);

gsize validity_clean_slate_payload_size (ValiditySensor *sensor);

gboolean validity_clean_slate_header_valid (const guint8 *hdr,
                                            gsize         len,
                                            guint16      *payload_len);

gboolean validity_clean_slate_payload_valid (const guint8 *hdr,
                                             const guint8 *payload,
                                             gsize         payload_len);

#define VALIDITY_CLEAN_SLATE_HDR_SIZE 0x44

/* Prepares a sensor image for minutiae extraction: bilinear upscaling by
 * @scale and a @pad pixel border replicating the edge pixels.  Returns a
 * newly allocated (width * scale + 2 * pad) x (height * scale + 2 * pad)
 * image. */
guint8 *validity_image_prepare (const guint8 *pixels,
                                guint         width,
                                guint         height,
                                guint         scale,
                                guint         pad,
                                guint        *out_width,
                                guint        *out_height);

/* Exposed for unit tests */
GBytes *validity_calibration_average (ValiditySensor *sensor,
                                      const guint8   *raw,
                                      gsize           len,
                                      GError        **error);
