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

#define FP_COMPONENT "validity"

#include "fpi-log.h"
#include "fpi-device.h"
#include "fpi-byte-reader.h"
#include "fpi-byte-writer.h"
#include "validity-proto.h"

#include <math.h>
#include <string.h>
#include <openssl/evp.h>

#define proto_error(error, ...) \
  g_set_error ((error), FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO, __VA_ARGS__)

/* ---------------------------------------------------------------------- */
/* Sensor database                                                        */
/* ---------------------------------------------------------------------- */

static const ValidityFlashIc flash_ics[] = {
  { "M25P05-A",    0x010000, 0x20, 0x20, 0x8000,  0xd8 },
  { "M25P10-A",    0x020000, 0x20, 0x20, 0x8000,  0xd8 },
  { "M25P20",      0x040000, 0x20, 0x20, 0x10000, 0xd8 },
  { "M25P40",      0x080000, 0x20, 0x20, 0x10000, 0xd8 },
  { "M25P80",      0x100000, 0x20, 0x20, 0x10000, 0xd8 },
  { "M25P16",      0x200000, 0x20, 0x20, 0x10000, 0xd8 },
  { "M25P32",      0x400000, 0x20, 0x20, 0x10000, 0xd8 },
  { "M25P64",      0x800000, 0x20, 0x20, 0x10000, 0xd8 },
  { "SST25VF040B", 0x080000, 0xbf, 0x25, 0x10000, 0xd8 },
  { "W25X10A",     0x020000, 0xef, 0x30, 0x1000,  0x20 },
  { "W25X20A",     0x040000, 0xef, 0x30, 0x1000,  0x20 },
  { "W25X40A",     0x080000, 0xef, 0x30, 0x1000,  0x20 },
  { "W25X80A",     0x100000, 0xef, 0x30, 0x1000,  0x20 },
  { "W25Q40B",     0x080000, 0xef, 0x40, 0x1000,  0x20 },
  { "W25Q80B",     0x100000, 0xef, 0x40, 0x1000,  0x20 },
  { "MX25L4006E",  0x080000, 0xc2, 0x20, 0x1000,  0x20 },
  { "EN25Q40",     0x080000, 0x1c, 0x30, 0x1000,  0x20 },
  { "MX25V8035F",  0x100000, 0xc2, 0x23, 0x1000,  0x20 },
  { "AT25SF081",   0x100000, 0x1f, 0x85, 0x1000,  0x20 },
  { "GD25Q80C",    0x100000, 0xc8, 0x40, 0x1000,  0x20 },
};

/* Sensor type 0x199 (57K0 FM-3380-003, as found in 06cb:00a2) */
static const guint8 calibration_blob_0199[] = {
  0x9b, 0x9a, 0x99, 0x97, 0x96, 0x95, 0x93, 0x92, 0x91, 0x8f, 0x8e, 0x8d, 0x8b, 0x8a, 0x89, 0x87,
  0x86, 0x85, 0x83, 0x82, 0x81, 0x7f, 0x7e, 0x7d, 0x7b, 0x7a, 0x79, 0x77, 0x76, 0x75, 0x73, 0x72,
  0x71, 0x6f, 0x6e, 0x6d, 0x6b, 0x6a, 0x69, 0x67, 0x66, 0x65, 0x63, 0x62, 0x61, 0x5f, 0x5e, 0x5d,
  0x5b, 0x5a, 0x59, 0x57, 0x56, 0x55, 0x52, 0x51, 0x50, 0x4e, 0x4d, 0x4c, 0x4a, 0x49, 0x48, 0x46,
  0x45, 0x44, 0x42, 0x41, 0x40, 0x3e, 0x3d, 0x3c, 0x3a, 0x39, 0x38, 0x36, 0x35, 0x34, 0x32, 0x31,
  0x30, 0x2e, 0x2d, 0x2c, 0x2a, 0x29, 0x28, 0x26, 0x25, 0x24, 0x22, 0x21, 0x20, 0x1e, 0x1d, 0x1c,
  0x1a, 0x19, 0x18, 0x16, 0x15, 0x14, 0x12, 0x11, 0x10, 0x0e, 0x0d, 0x0c, 0x0a, 0x09, 0x08, 0x06,
};

/* Base capture program for ROM 6.7 + sensor type 0x199: a list of
 * (type, length, payload) chunks. */
static const guint8 capture_prog_6_7_0199[] = {
  0x23, 0x00, 0x00, 0x00, 0x20, 0x00, 0x08, 0x00, 0x00, 0x20, 0x00, 0x80, 0x00, 0x00, 0x01, 0x00,
  0x32, 0x00, 0x74, 0x00, 0x00, 0x00, 0x00, 0x80, 0x20, 0x20, 0x04, 0x00, 0x24, 0x20, 0x00, 0x00,
  0x50, 0x20, 0x77, 0x36, 0x28, 0x20, 0x01, 0x00, 0x30, 0x20, 0x01, 0x00, 0x3c, 0x20, 0x80, 0x00,
  0x08, 0x21, 0x38, 0x00, 0x0c, 0x21, 0x00, 0x00, 0x48, 0x21, 0x07, 0x00, 0x4c, 0x21, 0x00, 0x00,
  0x58, 0x20, 0x00, 0x00, 0x5c, 0x20, 0x00, 0x00, 0x60, 0x20, 0x00, 0x00, 0x68, 0x20, 0x05, 0x00,
  0x6c, 0x20, 0x01, 0x49, 0x70, 0x20, 0x01, 0x41, 0x74, 0x20, 0x01, 0x88, 0x78, 0x20, 0x01, 0x80,
  0x84, 0x20, 0x20, 0x00, 0x94, 0x20, 0x01, 0x80, 0x9c, 0x20, 0x09, 0x02, 0xa0, 0x20, 0x0b, 0x19,
  0xb4, 0x20, 0x03, 0x00, 0xb8, 0x20, 0x3b, 0x04, 0xbc, 0x20, 0x14, 0x00, 0xc0, 0x20, 0x02, 0x00,
  0xc4, 0x20, 0x01, 0x00, 0xc8, 0x20, 0x02, 0x00, 0x33, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x80,
  0xcc, 0x20, 0x00, 0x00, 0xf5, 0x03, 0xd0, 0x20, 0x00, 0x00, 0xa1, 0x01, 0x32, 0x00, 0x44, 0x00,
  0x00, 0x00, 0x00, 0x80, 0xdc, 0x20, 0xe8, 0x03, 0xe0, 0x20, 0x64, 0x01, 0xe4, 0x20, 0xd0, 0x02,
  0xe8, 0x20, 0x00, 0x01, 0xf0, 0x20, 0x05, 0x00, 0xf8, 0x20, 0x05, 0x00, 0xfc, 0x20, 0x00, 0x00,
  0xb8, 0x20, 0x3a, 0x00, 0x00, 0x08, 0x04, 0x00, 0x14, 0x08, 0x00, 0x00, 0x08, 0x08, 0x00, 0x00,
  0x08, 0x08, 0x00, 0x00, 0x14, 0x08, 0x30, 0x00, 0x08, 0x08, 0x00, 0x00, 0x14, 0x08, 0x31, 0x00,
  0x1c, 0x08, 0x1a, 0x00, 0x32, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x80, 0x50, 0x11, 0x01, 0x00,
  0x4c, 0x11, 0x1e, 0x00, 0x34, 0x00, 0x78, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x22, 0x17, 0x10, 0x22, 0x17, 0x10, 0x22,
  0x16, 0x10, 0x22, 0x16, 0x10, 0x22, 0x16, 0x01, 0x06, 0x50, 0x10, 0x25, 0x01, 0x01, 0x00, 0x00,
  0x07, 0xc8, 0x07, 0x8c, 0x06, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4f, 0x80, 0x00, 0x6d,
  0x03, 0x00, 0x28, 0x03, 0x07, 0x03, 0x09, 0x90, 0x09, 0x8d, 0xb0, 0x0b, 0x90, 0x88, 0x09, 0x91,
  0x85, 0x8e, 0x08, 0xc1, 0x81, 0x0b, 0x91, 0x90, 0x91, 0x0a, 0xc1, 0xb8, 0x92, 0x8a, 0x09, 0x93,
  0x87, 0x8a, 0x89, 0x0b, 0x93, 0x88, 0x89, 0x89, 0x08, 0xc8, 0x81, 0x91, 0x89, 0x0a, 0xc8, 0x88,
  0x92, 0x89, 0x09, 0x9a, 0x81, 0x8a, 0x89, 0x0b, 0x9a, 0x88, 0x89, 0x89, 0x08, 0xd0, 0x81, 0x91,
  0x89, 0x0a, 0xd0, 0x88, 0x92, 0x89, 0x08, 0x02, 0x81, 0x8a, 0x09, 0x5a, 0x81, 0x0a, 0x02, 0x88,
  0x89, 0x0b, 0x5a, 0x88, 0x08, 0xd9, 0x81, 0x89, 0x89, 0x0a, 0xd9, 0x90, 0x89, 0x89, 0x09, 0x5e,
  0x82, 0x89, 0x89, 0x0b, 0x5e, 0x88, 0x89, 0x89, 0x08, 0xe1, 0x81, 0x89, 0x89, 0x0a, 0xe1, 0x90,
  0x89, 0x89, 0x09, 0x64, 0x82, 0x89, 0x89, 0x0b, 0x64, 0x88, 0x89, 0x09, 0x6e, 0x81, 0x08, 0xe9,
  0x81, 0x89, 0x0b, 0x6e, 0x88, 0x0a, 0xe9, 0x90, 0x91, 0xb9, 0x09, 0x6f, 0x82, 0x8a, 0x8f, 0x0b,
  0x6f, 0x88, 0x91, 0x89, 0x08, 0xf0, 0x81, 0x8a, 0x89, 0x0a, 0xf0, 0x90, 0x89, 0x89, 0x09, 0x76,
  0x82, 0x89, 0x91, 0x0b, 0x76, 0xb8, 0x91, 0x8a, 0x08, 0xf8, 0x87, 0x92, 0x91, 0x0a, 0xf8, 0x88,
  0x8a, 0x92, 0x09, 0x7c, 0x81, 0x89, 0x8a, 0x0b, 0x7c, 0x09, 0x01, 0x80, 0x89, 0x89, 0x0b, 0x01,
  0x88, 0x89, 0x91, 0x09, 0x7f, 0x81, 0x89, 0x92, 0x0b, 0x7f, 0x09, 0x08, 0x80, 0x89, 0x92, 0x0b,
  0x08, 0x88, 0x89, 0x92, 0x0c, 0x07, 0x03, 0x03, 0x07, 0x20, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00,
  0x2f, 0x00, 0x04, 0x00, 0x70, 0x00, 0x00, 0x00, 0x29, 0x00, 0x04, 0x00, 0x70, 0x00, 0x00, 0x00,
  0x35, 0x00, 0x04, 0x00, 0x80, 0x00, 0x00, 0x00,
};

/* Finger detection parameters (chunk 0x4e for identify, 0x26 for enroll):
 * outcome masks, WOVAR/ASP thresholds, poll times and debounce counts. */
static const guint8 finger_detect_0199[] = {
  0xfb, 0xb2, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x30, 0x00, 0x00, 0x00, 0x87, 0x00, 0x02, 0x00,
  0x67, 0x00, 0x0a, 0x00, 0x01, 0x80, 0x00, 0x00, 0x0a, 0x02, 0x00, 0x00, 0x0b, 0x19, 0x00, 0x00,
  0x88, 0x13, 0xb8, 0x0b, 0x01, 0x09, 0x10, 0x00,
};

static const guint8 finger_detect_enroll_0199[] = {
  0xfb, 0xb2, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x30, 0x00, 0x00, 0x00, 0x87, 0x00, 0x02, 0x00,
  0x67, 0x00, 0x0a, 0x00, 0x01, 0x80, 0x00, 0x00, 0x0a, 0x02, 0x00, 0x00, 0x0b, 0x19, 0x00, 0x00,
  0x50, 0xc3, 0x60, 0xea, 0x01, 0x09, 0x10, 0x00,
};

/* Image reconstruction parameters (chunk 0x2e); 112x112 output */
static const guint8 image_recon_0199[] = {
  0x02, 0x00, 0x18, 0x00, 0x02, 0x00, 0x00, 0x00, 0x70, 0x00, 0x70, 0x00, 0x4d, 0x01, 0x00, 0x00,
  0xa0, 0x00, 0x8c, 0x00, 0x3c, 0x32, 0x32, 0x1e, 0x3c, 0x0a, 0x02, 0x02,
};

static const guint8 image_recon_enroll_0199[] = {
  0x02, 0x00, 0x18, 0x00, 0x23, 0x00, 0x00, 0x00, 0x70, 0x00, 0x70, 0x00, 0x4d, 0x01, 0x00, 0x00,
  0xa0, 0x00, 0x8c, 0x00, 0x3c, 0x32, 0x32, 0x1e, 0x3c, 0x0a, 0x02, 0x02,
};

G_STATIC_ASSERT (sizeof (finger_detect_0199) == sizeof (finger_detect_enroll_0199));
G_STATIC_ASSERT (sizeof (image_recon_0199) == sizeof (image_recon_enroll_0199));

static const ValiditySensorProfile sensor_profiles[] = {
  {
    .dev_major = 0x0190,
    .dev_version = 0x61,
    .sensor_type = 0x199,
    .name = "57K0 FM-3380-003",
    .rom_major = 6,
    .rom_minor = 7,
    .bytes_per_line = 0x78,
    .repeat_multiplier = 2,
    .lines_per_calibration_data = 112,
    .line_width = 112,
    .key_calibration_line = 0x38,
    .calibration_frames = 3,
    .calibration_iterations = 3,
    .calibration_blob = calibration_blob_0199,
    .calibration_blob_len = sizeof (calibration_blob_0199),
    .capture_prog = capture_prog_6_7_0199,
    .capture_prog_len = sizeof (capture_prog_6_7_0199),
    .finger_detect = finger_detect_0199,
    .finger_detect_enroll = finger_detect_enroll_0199,
    .finger_detect_len = sizeof (finger_detect_0199),
    .image_recon = image_recon_0199,
    .image_recon_enroll = image_recon_enroll_0199,
    .image_recon_len = sizeof (image_recon_0199),
  },
  {
    .dev_major = 0x0190,
    .dev_version = 0x6a,
    .sensor_type = 0x199,
    .name = "57K0 FM-3380-003 (rev 006a)",
    .rom_major = 6,
    .rom_minor = 7,
    .bytes_per_line = 0x78,
    .repeat_multiplier = 2,
    .lines_per_calibration_data = 112,
    .line_width = 112,
    .key_calibration_line = 0x38,
    .calibration_frames = 3,
    .calibration_iterations = 3,
    .calibration_blob = calibration_blob_0199,
    .calibration_blob_len = sizeof (calibration_blob_0199),
    .capture_prog = capture_prog_6_7_0199,
    .capture_prog_len = sizeof (capture_prog_6_7_0199),
    .finger_detect = finger_detect_0199,
    .finger_detect_enroll = finger_detect_enroll_0199,
    .finger_detect_len = sizeof (finger_detect_0199),
    .image_recon = image_recon_0199,
    .image_recon_enroll = image_recon_enroll_0199,
    .image_recon_len = sizeof (image_recon_0199),
  },
};

const ValidityFlashIc *
validity_flash_ic_lookup (guint16 jedec_id0, guint16 jedec_id1, guint32 size)
{
  for (guint i = 0; i < G_N_ELEMENTS (flash_ics); i++)
    if (flash_ics[i].jedec_id0 == jedec_id0 &&
        flash_ics[i].jedec_id1 == jedec_id1 &&
        flash_ics[i].size == size)
      return &flash_ics[i];

  return NULL;
}

const ValiditySensorProfile *
validity_sensor_profile_lookup (guint16 dev_major, guint16 dev_version, const ValidityRomInfo *rom)
{
  for (guint i = 0; i < G_N_ELEMENTS (sensor_profiles); i++)
    {
      const ValiditySensorProfile *p = &sensor_profiles[i];

      if (p->dev_major == dev_major && p->dev_version == (dev_version & 0xff) &&
          p->rom_major == rom->major && p->rom_minor == rom->minor)
        return p;
    }

  return NULL;
}

/* ---------------------------------------------------------------------- */
/* Responses                                                              */
/* ---------------------------------------------------------------------- */

guint16
validity_rsp_status (const guint8 *rsp, gsize len)
{
  if (len < 2)
    return 0xffff;

  return rsp[0] | (rsp[1] << 8);
}

gboolean
validity_check_status (const guint8 *rsp, gsize len, const gchar *what, GError **error)
{
  guint16 status = validity_rsp_status (rsp, len);

  if (status != VALIDITY_STATUS_OK)
    {
      proto_error (error, "%s failed with status 0x%04x", what, status);
      return FALSE;
    }

  return TRUE;
}

gboolean
validity_parse_rom_info (const guint8 *rsp, gsize len, ValidityRomInfo *info, GError **error)
{
  const guint8 *p = rsp + 2;

  if (!validity_check_status (rsp, len, "ROM info", error))
    return FALSE;

  if (len < 2 + 0x24)
    {
      proto_error (error, "ROM info reply too short (%" G_GSIZE_FORMAT " bytes)", len);
      return FALSE;
    }

  info->timestamp = FP_READ_UINT32_LE (p);
  info->build = FP_READ_UINT32_LE (p + 4);
  info->major = p[8];
  info->minor = p[9];
  info->product = p[0x0b];
  info->flags = p[0x17];
  info->patch_level = FP_READ_UINT16_LE (p + 0x20);
  info->state = p[0x23] & 0x0f;
  return TRUE;
}

gboolean
validity_parse_flash_info (const guint8 *rsp, gsize len, ValidityFlashInfo *info, GError **error)
{
  FpiByteReader reader;
  guint16 unknown0, unknown1, n;

  if (!validity_check_status (rsp, len, "Flash info", error))
    return FALSE;

  fpi_byte_reader_init (&reader, rsp + 2, len - 2);
  if (!fpi_byte_reader_get_uint16_le (&reader, &info->jedec_id0) ||
      !fpi_byte_reader_get_uint16_le (&reader, &info->jedec_id1) ||
      !fpi_byte_reader_get_uint16_le (&reader, &info->blocks) ||
      !fpi_byte_reader_get_uint16_le (&reader, &unknown0) ||
      !fpi_byte_reader_get_uint16_le (&reader, &info->blocksize) ||
      !fpi_byte_reader_get_uint16_le (&reader, &unknown1) ||
      !fpi_byte_reader_get_uint16_le (&reader, &n))
    goto bad;

  if (n > G_N_ELEMENTS (info->partitions))
    goto bad;

  info->n_partitions = n;
  for (guint i = 0; i < n; i++)
    {
      ValidityPartition *part = &info->partitions[i];

      if (!fpi_byte_reader_get_uint8 (&reader, &part->id) ||
          !fpi_byte_reader_get_uint8 (&reader, &part->type) ||
          !fpi_byte_reader_get_uint16_le (&reader, &part->access_lvl) ||
          !fpi_byte_reader_get_uint32_le (&reader, &part->offset) ||
          !fpi_byte_reader_get_uint32_le (&reader, &part->size))
        goto bad;
    }

  return TRUE;

bad:
  proto_error (error, "Malformed flash info reply");
  return FALSE;
}

gboolean
validity_parse_fw_info (const guint8 *rsp, gsize len, ValidityFwInfo *info, GError **error)
{
  FpiByteReader reader;

  memset (info, 0, sizeof (*info));

  if (validity_rsp_status (rsp, len) == VALIDITY_STATUS_NO_FW)
    return TRUE;

  if (!validity_check_status (rsp, len, "Firmware info", error))
    return FALSE;

  fpi_byte_reader_init (&reader, rsp + 2, len - 2);
  if (!fpi_byte_reader_get_uint16_le (&reader, &info->major) ||
      !fpi_byte_reader_get_uint16_le (&reader, &info->minor) ||
      !fpi_byte_reader_get_uint16_le (&reader, &info->n_modules) ||
      !fpi_byte_reader_get_uint32_le (&reader, &info->buildtime) ||
      fpi_byte_reader_get_remaining (&reader) != info->n_modules * 12u)
    {
      proto_error (error, "Malformed firmware info reply");
      return FALSE;
    }

  info->present = TRUE;
  return TRUE;
}

gboolean
validity_parse_sensor_id (const guint8 *rsp, gsize len,
                          guint16 *major, guint16 *version, GError **error)
{
  if (!validity_check_status (rsp, len, "Sensor identification", error))
    return FALSE;

  if (len != 2 + 8 || FP_READ_UINT32_LE (rsp + 2) != 0)
    {
      proto_error (error, "Malformed sensor identification reply");
      return FALSE;
    }

  *version = FP_READ_UINT16_LE (rsp + 6);
  *major = FP_READ_UINT16_LE (rsp + 8);
  return TRUE;
}

GBytes *
validity_parse_factory_bits (const guint8 *rsp, gsize len, guint16 subtag, GError **error)
{
  FpiByteReader reader;
  guint32 unknown, entries;
  GBytes *result = NULL;

  if (!validity_check_status (rsp, len, "Factory calibration read", error))
    return NULL;

  fpi_byte_reader_init (&reader, rsp + 2, len - 2);
  if (!fpi_byte_reader_get_uint32_le (&reader, &unknown) ||
      !fpi_byte_reader_get_uint32_le (&reader, &entries))
    goto bad;

  for (guint32 i = 0; i < entries; i++)
    {
      guint32 ptr;
      guint16 vlen, tag, stag, flags;
      const guint8 *value;

      if (!fpi_byte_reader_get_uint32_le (&reader, &ptr) ||
          !fpi_byte_reader_get_uint16_le (&reader, &vlen) ||
          !fpi_byte_reader_get_uint16_le (&reader, &tag) ||
          !fpi_byte_reader_get_uint16_le (&reader, &stag) ||
          !fpi_byte_reader_get_uint16_le (&reader, &flags) ||
          !fpi_byte_reader_get_data (&reader, vlen, &value))
        goto bad;

      if (stag == subtag && !result)
        result = g_bytes_new (value, vlen);
    }

  if (fpi_byte_reader_get_remaining (&reader) != 0)
    {
      g_clear_pointer (&result, g_bytes_unref);
      goto bad;
    }

  if (!result)
    proto_error (error, "Factory calibration entry 0x%x not found", subtag);

  return result;

bad:
  proto_error (error, "Malformed factory calibration reply");
  return NULL;
}

GBytes *
validity_parse_flash_read (const guint8 *rsp, gsize len, GError **error)
{
  guint32 size;

  if (!validity_check_status (rsp, len, "Flash read", error))
    return NULL;

  if (len < 8)
    goto bad;

  size = FP_READ_UINT32_LE (rsp + 2);
  if (len - 8 < size)
    goto bad;

  return g_bytes_new (rsp + 8, size);

bad:
  proto_error (error, "Malformed flash read reply");
  return NULL;
}

GBytes *
validity_parse_pairing_cert (const guint8 *rsp, gsize len, GError **error)
{
  guint32 cert_len;

  if (!validity_check_status (rsp, len, "Flash partitioning", error))
    return NULL;

  if (len < 6)
    goto bad;

  cert_len = FP_READ_UINT32_LE (rsp + 2);
  if (cert_len == 0 || len - 6 < cert_len)
    goto bad;

  return g_bytes_new (rsp + 6, cert_len);

bad:
  proto_error (error, "Malformed partitioning reply");
  return NULL;
}

GBytes *
validity_parse_ecdh_reply (const guint8 *rsp, gsize len, GError **error)
{
  const gsize blob = 400;
  guint32 total;

  if (!validity_check_status (rsp, len, "Sensor key read", error))
    return NULL;

  /* status || LE32 total length (counting itself) || zeroes || 400 byte blob */
  if (len < 2 + 4 + blob)
    goto bad;

  total = FP_READ_UINT32_LE (rsp + 2);
  if (total != len - 2)
    goto bad;

  for (gsize i = 2 + 4; i < len - blob; i++)
    if (rsp[i] != 0)
      goto bad;

  return g_bytes_new (rsp + len - blob, blob);

bad:
  proto_error (error, "Malformed sensor key reply");
  return NULL;
}

gboolean
validity_parse_image (const guint8 *rsp, gsize len, ValidityImage *image, GError **error)
{
  const guint8 *p = rsp + 6;
  guint32 payload;
  gsize pixels;

  memset (image, 0, sizeof (*image));

  if (!validity_check_status (rsp, len, "Image read", error))
    return FALSE;

  /* status || LE32 len || w(2) h(2) ?(2) bpp(2) ?(4) || pixels */
  if (len < 6 + 12)
    goto bad;

  payload = FP_READ_UINT32_LE (rsp + 2);
  if (payload != len - 6)
    goto bad;

  image->width = FP_READ_UINT16_LE (p);
  image->height = FP_READ_UINT16_LE (p + 2);
  image->bpp = FP_READ_UINT16_LE (p + 6);
  pixels = (gsize) image->width * image->height;

  if (image->bpp != 8 || pixels == 0 || payload != 12 + pixels)
    {
      proto_error (error, "Unexpected image format %ux%u, %u bpp, %u bytes",
                   image->width, image->height, image->bpp, payload);
      return FALSE;
    }

  image->pixels = g_memdup2 (p + 12, pixels);
  return TRUE;

bad:
  proto_error (error, "Malformed image reply");
  return FALSE;
}

/* ---------------------------------------------------------------------- */
/* Commands                                                               */
/* ---------------------------------------------------------------------- */

static GBytes *
writer_to_bytes (FpiByteWriter *writer)
{
  gsize size = fpi_byte_writer_get_pos (writer);

  return g_bytes_new_take (fpi_byte_writer_reset_and_get_data (writer), size);
}

static GBytes *
flash_rw_cmd (guint8 opcode, guint8 partition, guint32 addr, guint32 size,
              const guint8 *data)
{
  FpiByteWriter writer;
  gboolean ok = TRUE;

  fpi_byte_writer_init_with_size (&writer, 13 + (data ? size : 0), FALSE);
  ok &= fpi_byte_writer_put_uint8 (&writer, opcode);
  ok &= fpi_byte_writer_put_uint8 (&writer, partition);
  ok &= fpi_byte_writer_put_uint8 (&writer, 1);
  ok &= fpi_byte_writer_put_uint16_le (&writer, 0);
  ok &= fpi_byte_writer_put_uint32_le (&writer, addr);
  ok &= fpi_byte_writer_put_uint32_le (&writer, size);
  if (data)
    ok &= fpi_byte_writer_put_data (&writer, data, size);
  g_assert (ok);

  return writer_to_bytes (&writer);
}

GBytes *
validity_cmd_flash_read (guint8 partition, guint32 addr, guint32 size)
{
  return flash_rw_cmd (VALIDITY_CMD_FLASH_READ, partition, addr, size, NULL);
}

GBytes *
validity_cmd_flash_write (guint8 partition, guint32 addr, const guint8 *data, gsize len)
{
  return flash_rw_cmd (VALIDITY_CMD_FLASH_WRITE, partition, addr, len, data);
}

GBytes *
validity_cmd_fw_signature (guint8 partition, const guint8 *sig, gsize len)
{
  FpiByteWriter writer;
  gboolean ok = TRUE;

  fpi_byte_writer_init_with_size (&writer, 5 + len, FALSE);
  ok &= fpi_byte_writer_put_uint8 (&writer, VALIDITY_CMD_FW_SIGNATURE);
  ok &= fpi_byte_writer_put_uint8 (&writer, partition);
  ok &= fpi_byte_writer_put_uint8 (&writer, 0);
  ok &= fpi_byte_writer_put_uint16_le (&writer, len);
  ok &= fpi_byte_writer_put_data (&writer, sig, len);
  g_assert (ok);

  return writer_to_bytes (&writer);
}

GBytes *
validity_cmd_factory_bits (guint16 tag)
{
  FpiByteWriter writer;
  gboolean ok = TRUE;

  fpi_byte_writer_init_with_size (&writer, 9, FALSE);
  ok &= fpi_byte_writer_put_uint8 (&writer, VALIDITY_CMD_FACTORY_BITS);
  ok &= fpi_byte_writer_put_uint16_le (&writer, tag);
  ok &= fpi_byte_writer_put_uint16_le (&writer, 0);
  ok &= fpi_byte_writer_put_uint32_le (&writer, 0);
  g_assert (ok);

  return writer_to_bytes (&writer);
}

GBytes *
validity_cmd_get_data (guint32 max_len)
{
  guint8 cmd[5] = { VALIDITY_CMD_GET_DATA };

  FP_WRITE_UINT32_LE (cmd + 1, max_len);
  return g_bytes_new (cmd, sizeof (cmd));
}

static void
put_tlv (FpiByteWriter *writer, guint16 id, const guint8 *data, gsize len)
{
  gboolean ok = TRUE;

  ok &= fpi_byte_writer_put_uint16_le (writer, id);
  ok &= fpi_byte_writer_put_uint16_le (writer, len);
  ok &= fpi_byte_writer_put_data (writer, data, len);
  g_assert (ok);
}

GBytes *
validity_cmd_partition_flash (const ValidityFlashIc *ic,
                              const ValidityPartition *layout, guint n_partitions,
                              const guint8 *layout_signature, gsize signature_len,
                              GBytes *client_cert,
                              const guint8 *ca_blob, gsize ca_blob_len)
{
  FpiByteWriter writer, params, table;
  static const guint8 hdr[] = { VALIDITY_CMD_PARTITION_FLASH, 0, 0, 0, 0 };
  gboolean ok = TRUE;

  g_autoptr(GBytes) params_bytes = NULL;
  g_autoptr(GBytes) table_bytes = NULL;

  /* Flash geometry: size, sector size, 2 pad bytes, erase opcode, pad */
  fpi_byte_writer_init_with_size (&params, 12, FALSE);
  ok &= fpi_byte_writer_put_uint32_le (&params, ic->size);
  ok &= fpi_byte_writer_put_uint32_le (&params, ic->sector_size);
  ok &= fpi_byte_writer_put_uint16_le (&params, 0);
  ok &= fpi_byte_writer_put_uint8 (&params, ic->sector_erase_cmd);
  ok &= fpi_byte_writer_put_uint8 (&params, 0);
  params_bytes = writer_to_bytes (&params);

  /* Partition records: 12 byte entry, 4 zero bytes, SHA-256 of the entry */
  fpi_byte_writer_init_with_size (&table, n_partitions * 0x30 + signature_len, FALSE);
  for (guint i = 0; i < n_partitions; i++)
    {
      guint8 entry[12];
      guint8 digest[32];
      unsigned int digest_len = sizeof (digest);

      entry[0] = layout[i].id;
      entry[1] = layout[i].type;
      FP_WRITE_UINT16_LE (entry + 2, layout[i].access_lvl);
      FP_WRITE_UINT32_LE (entry + 4, layout[i].offset);
      FP_WRITE_UINT32_LE (entry + 8, layout[i].size);
      if (EVP_Digest (entry, sizeof (entry), digest, &digest_len, EVP_sha256 (), NULL) != 1)
        g_error ("validity: SHA-256 failed");

      ok &= fpi_byte_writer_put_data (&table, entry, sizeof (entry));
      ok &= fpi_byte_writer_put_uint32_le (&table, 0);
      ok &= fpi_byte_writer_put_data (&table, digest, sizeof (digest));
    }
  ok &= fpi_byte_writer_put_data (&table, layout_signature, signature_len);
  table_bytes = writer_to_bytes (&table);

  fpi_byte_writer_init (&writer);
  ok &= fpi_byte_writer_put_data (&writer, hdr, sizeof (hdr));
  g_assert (ok);
  put_tlv (&writer, 0, g_bytes_get_data (params_bytes, NULL), g_bytes_get_size (params_bytes));
  put_tlv (&writer, 1, g_bytes_get_data (table_bytes, NULL), g_bytes_get_size (table_bytes));
  put_tlv (&writer, 5, g_bytes_get_data (client_cert, NULL), g_bytes_get_size (client_cert));
  put_tlv (&writer, 3, ca_blob, ca_blob_len);

  return writer_to_bytes (&writer);
}

/* ---------------------------------------------------------------------- */
/* Timeslot programs                                                      */
/* ---------------------------------------------------------------------- */

enum {
  INSN_NOOP,
  INSN_END_OF_TABLE,
  INSN_RETURN,
  INSN_CLEAR_SO,
  INSN_END_OF_DATA,
  INSN_MACRO,
  INSN_ENABLE_RX,
  INSN_IDLE_RX,
  INSN_ENABLE_SO,
  INSN_DISABLE_SO,
  INSN_INTERRUPT,
  INSN_CALL,
  INSN_FEATURES,
  INSN_REGISTER_WRITE,
  INSN_SAMPLE,
  INSN_SAMPLE_REPEAT,
};

#define REG_CALIBRATION 0x8000203c

typedef struct
{
  guint   opcode;
  guint   size;
  guint32 operand[3];
} Insn;

/* Decodes one timeslot instruction; returns FALSE on unknown or truncated
 * instructions. */
static gboolean
decode_insn (const guint8 *b, gsize len, Insn *insn)
{
  guint8 op;

  if (len == 0)
    return FALSE;

  op = b[0];
  memset (insn, 0, sizeof (*insn));
  insn->size = 1;

  if (op <= 4)
    {
      insn->opcode = op;
    }
  else if (op == 5 || op == 6)
    {
      insn->opcode = op == 5 ? INSN_MACRO : INSN_ENABLE_RX;
      insn->size = 2;
    }
  else if (op == 7)
    {
      insn->opcode = INSN_IDLE_RX;
      insn->size = 2;
    }
  else if ((op & 0xfe) == 0x08)
    {
      insn->opcode = INSN_ENABLE_SO;
      insn->size = 2;
    }
  else if ((op & 0xfe) == 0x0a)
    {
      insn->opcode = INSN_DISABLE_SO;
      insn->size = 2;
    }
  else if ((op & 0xfc) == 0x0c)
    {
      insn->opcode = INSN_INTERRUPT;
    }
  else if ((op & 0xf8) == 0x10)
    {
      insn->opcode = INSN_CALL;
      insn->size = 3;
    }
  else if ((op & 0xe0) == 0x20)
    {
      insn->opcode = INSN_FEATURES;
    }
  else if ((op & 0xc0) == 0x40)
    {
      insn->opcode = INSN_REGISTER_WRITE;
      insn->size = 3;
    }
  else if ((op & 0xc0) == 0x80)
    {
      insn->opcode = INSN_SAMPLE;
    }
  else if ((op & 0xc0) == 0xc0)
    {
      insn->opcode = INSN_SAMPLE_REPEAT;
      insn->size = 2;
    }
  else
    {
      return FALSE;
    }

  if (insn->size > len)
    return FALSE;

  switch (insn->opcode)
    {
    case INSN_CALL:
      insn->operand[0] = op & 7;
      insn->operand[1] = b[1] << 2;   /* destination address */
      insn->operand[2] = b[2] ? b[2] : 0x100;
      break;

    case INSN_REGISTER_WRITE:
      insn->operand[0] = (op & 0x3f) * 4 + 0x80002000;
      insn->operand[1] = b[1] | (b[2] << 8);
      break;

    default:
      break;
    }

  return TRUE;
}

/* Returns the offset of the n-th (1-based) instruction matching @opcode
 * (and @reg for register writes), or -1. */
static gssize
find_nth_insn (const guint8 *b, gsize len, guint opcode, guint32 reg, guint n)
{
  gsize pc = 0;

  while (pc < len)
    {
      Insn insn;

      if (!decode_insn (b + pc, len - pc, &insn))
        return -1;

      if (insn.opcode == opcode && (opcode != INSN_REGISTER_WRITE || insn.operand[0] == reg))
        if (--n == 0)
          return pc;

      pc += insn.size;
    }

  return -1;
}

/* Scales repeat counts of call instructions (vendor driver logic). */
static gboolean
patch_timeslot_table (guint8 *b, gsize len, gboolean inc_address, guint mult)
{
  gsize i = 0;

  while (i + 3 < len)
    {
      if ((b[i] & 0xf8) == 0x10)
        {
          if (b[i + 2] > 1)
            {
              if (b[i + 2] * mult > 0xff || (inc_address && b[i + 1] == 0xff))
                return FALSE;
              b[i + 2] *= mult;
              if (inc_address)
                b[i + 1] += 1;
            }
          i += 3;
        }
      else if (b[i] == 0)
        {
          i += 1;
        }
      else if (b[i] == 7)
        {
          i += 2;
        }
      else
        {
          break;
        }
    }

  return TRUE;
}

/* Replaces the value of the last calibration register write in the last
 * called subroutine with the factory calibration value of the key line. */
static gboolean
patch_timeslot_again (ValiditySensor *sensor, guint8 *b, gsize len)
{
  const ValiditySensorProfile *prof = sensor->profile;
  gsize fcv_len;
  const guint8 *fcv = g_bytes_get_data (sensor->factory_calibration_values, &fcv_len);
  gssize target = -1, match = -1;
  gsize pc = 0;

  while (pc < len)
    {
      Insn insn;

      if (!decode_insn (b + pc, len - pc, &insn))
        return FALSE;
      if (insn.opcode == INSN_END_OF_TABLE || insn.opcode == INSN_RETURN ||
          insn.opcode == INSN_END_OF_DATA)
        break;
      if (insn.opcode == INSN_CALL)
        target = insn.operand[1];
      pc += insn.size;
    }

  if (target < 0)
    return TRUE;

  pc = target;
  while (pc < len)
    {
      Insn insn;

      if (!decode_insn (b + pc, len - pc, &insn))
        return FALSE;
      if (insn.opcode == INSN_END_OF_TABLE || insn.opcode == INSN_RETURN ||
          insn.opcode == INSN_END_OF_DATA)
        break;
      if (insn.opcode == INSN_REGISTER_WRITE && insn.operand[0] == REG_CALIBRATION)
        match = pc;
      pc += insn.size;
    }

  if (match < 0)
    return TRUE;

  if (prof->key_calibration_line >= fcv_len)
    return FALSE;

  b[match + 1] = fcv[prof->key_calibration_line];
  return TRUE;
}

/* Packs @len values relative to their minimum with the minimal bit width,
 * LSB first.  Returns the bit width (0 on failure). */
static guint
bitpack (const guint8 *values, gsize len, guint8 *min_out, GByteArray *out)
{
  guint8 min = 0xff, max = 0;
  guint bits = 0;
  gsize nbytes;

  for (gsize i = 0; i < len; i++)
    {
      min = MIN (min, values[i]);
      max = MAX (max, values[i]);
    }

  for (guint delta = max - min; delta; delta >>= 1)
    bits++;

  if (len == 0 || bits == 0)
    return 0;

  nbytes = (bits * len + 7) / 8;
  g_byte_array_set_size (out, nbytes);
  memset (out->data, 0, nbytes);

  for (gsize i = 0; i < len; i++)
    {
      guint v = values[i] - min;

      for (guint bit = 0; bit < bits; bit++)
        if (v & (1u << bit))
          {
            gsize pos = i * bits + bit;
            out->data[pos / 8] |= 1u << (pos % 8);
          }
    }

  *min_out = min;
  return bits;
}

typedef struct
{
  guint32     mask;
  guint32     flags;
  guint8      v0, v1;
  guint16     v2;
  GByteArray *data;
} LineUpdate;

static void
line_update_clear (gpointer p)
{
  LineUpdate *l = p;

  g_byte_array_unref (l->data);
}

#define LINE_UPDATE_COUNT(l) (((l)->flags >> 20) & 0x0f)

typedef struct
{
  guint16 type;
  GBytes *data;
} Chunk;

static void
chunk_clear (gpointer p)
{
  Chunk *c = p;

  g_bytes_unref (c->data);
}

static void
chunks_add (GArray *chunks, guint16 type, const guint8 *data, gsize len)
{
  Chunk c = { type, g_bytes_new (data, len) };

  g_array_append_val (chunks, c);
}

static GArray *
split_chunks (const guint8 *prog, gsize len, GError **error)
{
  g_autoptr(GArray) chunks = g_array_new (FALSE, FALSE, sizeof (Chunk));
  gsize pos = 0;

  g_array_set_clear_func (chunks, chunk_clear);

  while (pos < len)
    {
      guint16 type, size;

      if (len - pos < 4)
        goto bad;
      type = FP_READ_UINT16_LE (prog + pos);
      size = FP_READ_UINT16_LE (prog + pos + 2);
      if (size > len - pos - 4)
        goto bad;

      chunks_add (chunks, type, prog + pos + 4, size);
      pos += 4 + size;
    }

  return g_steal_pointer (&chunks);

bad:
  proto_error (error, "Malformed capture program");
  return NULL;
}

void
validity_sensor_clear (ValiditySensor *sensor)
{
  g_clear_pointer (&sensor->factory_calibration_values, g_bytes_unref);
  g_clear_pointer (&sensor->calib_data, g_bytes_unref);
  sensor->profile = NULL;
  sensor->lines_per_frame = 0;
}

gboolean
validity_sensor_init (ValiditySensor *sensor, const ValiditySensorProfile *profile,
                      GBytes *factory_calibration_values, GError **error)
{
  g_autoptr(GArray) chunks = NULL;
  guint32 lines_2d = 0;

  validity_sensor_clear (sensor);

  chunks = split_chunks (profile->capture_prog, profile->capture_prog_len, error);
  if (!chunks)
    return FALSE;

  for (guint i = 0; i < chunks->len; i++)
    {
      Chunk *c = &g_array_index (chunks, Chunk, i);

      /* "2D" chunk: lines per frame before repetition */
      if (c->type == 0x2f && g_bytes_get_size (c->data) == 4)
        {
          lines_2d = FP_READ_UINT32_LE (g_bytes_get_data (c->data, NULL));
          break;
        }
    }

  if (lines_2d == 0 ||
      g_bytes_get_size (factory_calibration_values) != profile->line_width ||
      profile->lines_per_calibration_data == 0 ||
      lines_2d * profile->repeat_multiplier < profile->lines_per_calibration_data)
    {
      proto_error (error, "Inconsistent sensor description");
      return FALSE;
    }

  sensor->profile = profile;
  sensor->lines_per_frame = lines_2d * profile->repeat_multiplier;
  sensor->factory_calibration_values = g_bytes_ref (factory_calibration_values);
  return TRUE;
}

static GByteArray *
get_key_line (ValiditySensor *sensor)
{
  const ValiditySensorProfile *prof = sensor->profile;
  GByteArray *line = g_byte_array_sized_new (prof->line_width);

  g_byte_array_set_size (line, prof->line_width);

  if (sensor->calib_data)
    {
      gsize calib_len;
      const guint8 *calib = g_bytes_get_data (sensor->calib_data, &calib_len);
      gsize bytes_per_calib_line = calib_len / prof->lines_per_calibration_data;
      gsize offset = 8 + bytes_per_calib_line * prof->key_calibration_line;

      g_assert (offset + prof->line_width <= calib_len);
      for (guint i = 0; i < prof->line_width; i++)
        line->data[i] = calib[offset + i] == 5 ? 4 : calib[offset + i];
    }
  else
    {
      memset (line->data, 0, prof->line_width);
    }

  return line;
}

static void
line_update_pad (LineUpdate *l)
{
  while (l->data->len % 4)
    g_byte_array_append (l->data, (const guint8 *) "", 1);
}

/* Builds the "line update" chunks for sensors with type 1 line updates
 * (this includes sensor type 0x199). */
static gboolean
line_update_type_1 (ValiditySensor *sensor, ValidityCaptureMode mode, GArray *chunks,
                    GError **error)
{
  const ValiditySensorProfile *prof = sensor->profile;

  g_autoptr(GArray) lines = g_array_new (FALSE, TRUE, sizeof (LineUpdate));
  g_autoptr(GByteArray) tst = NULL;
  g_autoptr(GByteArray) update = g_byte_array_new ();
  g_autoptr(GByteArray) transform = g_byte_array_new ();
  gsize fcv_len;
  const guint8 *fcv = g_bytes_get_data (sensor->factory_calibration_values, &fcv_len);
  guint32 count = 2;
  guint8 tmp[8];
  gssize pc;

  g_array_set_clear_func (lines, line_update_clear);

  for (guint i = 0; i < chunks->len; i++)
    {
      Chunk *c = &g_array_index (chunks, Chunk, i);
      g_autoptr(GByteArray) key_line = NULL;
      gsize size;
      const guint8 *data;

      if (c->type != 0x34)
        continue;

      /* Timeslot table 2D */
      data = g_bytes_get_data (c->data, &size);
      g_clear_pointer (&tst, g_byte_array_unref);
      tst = g_byte_array_sized_new (size);
      g_byte_array_append (tst, data, size);

      if (size < prof->line_width ||
          !patch_timeslot_table (tst->data, tst->len, TRUE, prof->repeat_multiplier) ||
          (mode != VALIDITY_CAPTURE_CALIBRATE && !patch_timeslot_again (sensor, tst->data, tst->len)))
        {
          proto_error (error, "Unable to patch the timeslot table");
          return FALSE;
        }

      key_line = get_key_line (sensor);
      g_byte_array_append (key_line, tst->data + prof->line_width, tst->len - prof->line_width);
      g_bytes_unref (c->data);
      c->data = g_bytes_new (key_line->data, key_line->len);
    }

  if (!tst)
    {
      proto_error (error, "Capture program lacks a timeslot table");
      return FALSE;
    }

  /* Reply configuration */
  chunks_add (chunks, 0x17, NULL, 0);

  if (mode == VALIDITY_CAPTURE_IDENTIFY)
    {
      chunks_add (chunks, 0x4e, prof->finger_detect, prof->finger_detect_len);
      chunks_add (chunks, 0x2e, prof->image_recon, prof->image_recon_len);
    }
  else if (mode == VALIDITY_CAPTURE_ENROLL)
    {
      chunks_add (chunks, 0x26, prof->finger_detect_enroll, prof->finger_detect_len);
      chunks_add (chunks, 0x2e, prof->image_recon_enroll, prof->image_recon_len);
    }

  /* Line update interleave */
  FP_WRITE_UINT32_LE (tmp, 1);
  chunks_add (chunks, 0x44, tmp, 4);

  /* Calibration blob, patched at the 2nd "Enable Rx" instruction */
  pc = find_nth_insn (tst->data, tst->len, INSN_ENABLE_RX, 0, 2);
  if (pc < 0)
    goto no_insn;
  {
    LineUpdate l = { 0xff, (pc + 1) | (count << 20) | 0x7000000, 0x0f, 0, 0,
                     g_byte_array_new () };
    g_byte_array_append (l.data, prof->calibration_blob, prof->calibration_blob_len);
    g_array_append_val (lines, l);
    count++;
  }

  /* Factory calibration values, patched at the 1st calibration register write */
  pc = find_nth_insn (tst->data, tst->len, INSN_REGISTER_WRITE, REG_CALIBRATION, 1);
  if (pc < 0)
    goto no_insn;
  {
    LineUpdate l = { 0xff, (pc + 1) | (count << 20) | 0x7000000, 0, 0, 0,
                     g_byte_array_new () };
    guint bits = bitpack (fcv, fcv_len, &l.v1, l.data);

    if (bits == 0)
      {
        g_byte_array_unref (l.data);
        proto_error (error, "Degenerate factory calibration values");
        return FALSE;
      }
    l.v0 = (bits - 1) | 8;
    g_array_append_val (lines, l);
    count++;
  }

  /* Per column calibration offsets */
  if (sensor->calib_data)
    {
      gsize calib_len;
      const guint8 *calib = g_bytes_get_data (sensor->calib_data, &calib_len);
      gsize bpcl = calib_len / prof->lines_per_calibration_data;

      for (guint i = 0; i < prof->line_width; i += 4)
        {
          LineUpdate l = { 0xffffffff, i | (0x85u << 24), 0, 0, 0, g_byte_array_new () };

          for (guint j = 0; j < prof->lines_per_calibration_data; j++)
            {
              gsize off = 8 + j * bpcl + i;

              g_assert (off + 4 <= calib_len);
              g_byte_array_append (l.data, calib + off, 4);
            }
          g_array_append_val (lines, l);
        }
    }

  for (guint i = 0; i < lines->len; i++)
    line_update_pad (&g_array_index (lines, LineUpdate, i));

  /* Line update: count, (mask, flags) pairs, then the inline data */
  FP_WRITE_UINT32_LE (tmp, lines->len);
  g_byte_array_append (update, tmp, 4);
  for (guint i = 0; i < lines->len; i++)
    {
      LineUpdate *l = &g_array_index (lines, LineUpdate, i);

      FP_WRITE_UINT32_LE (tmp, l->mask);
      FP_WRITE_UINT32_LE (tmp + 4, l->flags);
      g_byte_array_append (update, tmp, 8);
    }
  for (guint i = 0; i < lines->len; i++)
    {
      LineUpdate *l = &g_array_index (lines, LineUpdate, i);

      if (LINE_UPDATE_COUNT (l) <= 1)
        g_byte_array_append (update, l->data->data, l->data->len);
    }
  chunks_add (chunks, 0x30, update->data, update->len);

  /* Line update transform: the out-of-line (packed) entries */
  for (guint i = 0; i < lines->len; i++)
    {
      LineUpdate *l = &g_array_index (lines, LineUpdate, i);

      if (LINE_UPDATE_COUNT (l) <= 1)
        continue;

      tmp[0] = l->v0;
      tmp[1] = l->v1;
      FP_WRITE_UINT16_LE (tmp + 2, l->v2);
      g_byte_array_append (transform, tmp, 4);
      g_byte_array_append (transform, l->data->data, l->data->len);
    }
  chunks_add (chunks, 0x43, transform->data, transform->len);

  return TRUE;

no_insn:
  proto_error (error, "Timeslot table lacks an expected instruction");
  return FALSE;
}

GBytes *
validity_build_capture_cmd (ValiditySensor *sensor, ValidityCaptureMode mode, GError **error)
{
  const ValiditySensorProfile *prof = sensor->profile;

  g_autoptr(GArray) chunks = NULL;
  g_autoptr(GByteArray) out = g_byte_array_new ();
  guint8 hdr[5];
  guint req_lines = 0;

  g_return_val_if_fail (prof != NULL, NULL);

  chunks = split_chunks (prof->capture_prog, prof->capture_prog_len, error);
  if (!chunks || !line_update_type_1 (sensor, mode, chunks, error))
    return NULL;

  if (mode == VALIDITY_CAPTURE_CALIBRATE)
    req_lines = prof->calibration_frames * sensor->lines_per_frame + 1;

  hdr[0] = VALIDITY_CMD_CAPTURE;
  FP_WRITE_UINT16_LE (hdr + 1, prof->bytes_per_line);
  FP_WRITE_UINT16_LE (hdr + 3, req_lines);
  g_byte_array_append (out, hdr, sizeof (hdr));

  for (guint i = 0; i < chunks->len; i++)
    {
      Chunk *c = &g_array_index (chunks, Chunk, i);
      gsize size;
      const guint8 *data = g_bytes_get_data (c->data, &size);
      guint8 chdr[4];

      if (size > G_MAXUINT16)
        {
          proto_error (error, "Capture program chunk too large");
          return NULL;
        }

      FP_WRITE_UINT16_LE (chdr, c->type);
      FP_WRITE_UINT16_LE (chdr + 2, size);
      g_byte_array_append (out, chdr, sizeof (chdr));
      if (size)
        g_byte_array_append (out, data, size);
    }

  return g_byte_array_free_to_bytes (g_steal_pointer (&out));
}

/* ---------------------------------------------------------------------- */
/* Calibration                                                            */
/* ---------------------------------------------------------------------- */

gsize
validity_calibration_frame_bytes (ValiditySensor *sensor)
{
  const ValiditySensorProfile *prof = sensor->profile;

  return (gsize) (prof->calibration_frames * sensor->lines_per_frame + 1) * prof->bytes_per_line;
}

GBytes *
validity_calibration_average (ValiditySensor *sensor, const guint8 *raw, gsize len, GError **error)
{
  const ValiditySensorProfile *prof = sensor->profile;
  gsize bpl = prof->bytes_per_line;
  gsize frame_size = (gsize) sensor->lines_per_frame * bpl;
  guint interleave = sensor->lines_per_frame / prof->lines_per_calibration_data;

  g_autoptr(GByteArray) out = NULL;
  const guint8 *frame;

  /* Only the interleaved layout is implemented; the first frame is
   * discarded as it is not settled yet. */
  if (interleave < 2 || prof->calibration_frames < 2)
    {
      proto_error (error, "Unsupported calibration frame layout");
      return NULL;
    }

  if (len < 2 * frame_size)
    {
      proto_error (error, "Short calibration data (%" G_GSIZE_FORMAT " bytes)", len);
      return NULL;
    }

  frame = raw + frame_size;
  out = g_byte_array_sized_new (frame_size / interleave);

  for (gsize group = 0; group < frame_size / (interleave * bpl); group++)
    {
      const guint8 *lines = frame + group * interleave * bpl;

      for (gsize col = 0; col < bpl; col++)
        {
          guint sum = 0;
          guint8 avg;

          for (guint l = 0; l < interleave; l++)
            sum += lines[l * bpl + col];
          avg = sum / interleave;
          g_byte_array_append (out, &avg, 1);
        }
    }

  return g_byte_array_free_to_bytes (g_steal_pointer (&out));
}

static gint
clip8 (gint x)
{
  return CLAMP (x, -128, 127);
}

static guint8
scale_calibration (guint8 x)
{
  /* Truncating division, like the vendor implementation */
  return (guint8) clip8 (((gint) x - 0x80) * 10 / 0x22);
}

gboolean
validity_calibration_process (ValiditySensor *sensor, const guint8 *raw, gsize len, GError **error)
{
  const ValiditySensorProfile *prof = sensor->profile;

  g_autoptr(GBytes) cooked = validity_calibration_average (sensor, raw, len, error);
  gsize bpl = prof->bytes_per_line;
  gsize cooked_len;
  g_autofree guint8 *frame = NULL;

  if (!cooked)
    return FALSE;

  frame = g_bytes_unref_to_data (g_steal_pointer (&cooked), &cooked_len);

  for (gsize line = 0; line < cooked_len / bpl; line++)
    for (gsize col = 8; col < bpl; col++)
      frame[line * bpl + col] = scale_calibration (frame[line * bpl + col]);

  if (sensor->calib_data)
    {
      gsize old_len;
      const guint8 *old = g_bytes_get_data (sensor->calib_data, &old_len);

      g_assert (old_len == cooked_len);

      /* Keep the old line headers, accumulate the signed offsets */
      for (gsize line = 0; line < cooked_len / bpl; line++)
        {
          memcpy (frame + line * bpl, old + line * bpl, 8);
          for (gsize col = 8; col < bpl; col++)
            {
              gsize i = line * bpl + col;
              frame[i] = (guint8) clip8 ((gint8) old[i] + (gint8) frame[i]);
            }
        }
    }

  g_clear_pointer (&sensor->calib_data, g_bytes_unref);
  sensor->calib_data = g_bytes_new_take (g_steal_pointer (&frame), cooked_len);
  return TRUE;
}

#define CLEAN_SLATE_MAGIC 0x5002

GBytes *
validity_calibration_build_clean_slate (ValiditySensor *sensor, const guint8 *raw, gsize len,
                                        GError **error)
{
  g_autoptr(GBytes) frame = validity_calibration_average (sensor, raw, len, error);
  g_autoptr(GByteArray) payload = NULL;
  g_autoptr(GByteArray) out = NULL;
  guint8 tmp[4];
  guint8 digest[32];
  unsigned int digest_len = sizeof (digest);
  gsize frame_len;

  if (!frame)
    return NULL;

  frame_len = g_bytes_get_size (frame);
  if (frame_len + 4 > G_MAXUINT16)
    {
      proto_error (error, "Calibration frame too large");
      return NULL;
    }

  /* LE16 len || frame || LE16 0 */
  payload = g_byte_array_sized_new (frame_len + 4);
  FP_WRITE_UINT16_LE (tmp, frame_len);
  g_byte_array_append (payload, tmp, 2);
  g_byte_array_append (payload, g_bytes_get_data (frame, NULL), frame_len);
  FP_WRITE_UINT16_LE (tmp, 0);
  g_byte_array_append (payload, tmp, 2);

  if (EVP_Digest (payload->data, payload->len, digest, &digest_len, EVP_sha256 (), NULL) != 1)
    g_error ("validity: SHA-256 failed");

  /* LE16 magic || LE16 len || SHA-256 || 32 zeroes || payload */
  out = g_byte_array_sized_new (VALIDITY_CLEAN_SLATE_HDR_SIZE + payload->len);
  FP_WRITE_UINT16_LE (tmp, CLEAN_SLATE_MAGIC);
  FP_WRITE_UINT16_LE (tmp + 2, payload->len);
  g_byte_array_append (out, tmp, 4);
  g_byte_array_append (out, digest, sizeof (digest));
  memset (digest, 0, sizeof (digest));
  g_byte_array_append (out, digest, sizeof (digest));
  g_byte_array_append (out, payload->data, payload->len);

  return g_byte_array_free_to_bytes (g_steal_pointer (&out));
}

gsize
validity_clean_slate_payload_size (ValiditySensor *sensor)
{
  const ValiditySensorProfile *prof = sensor->profile;

  /* LE16 len || averaged frame || LE16 0 */
  return 2 + (gsize) prof->lines_per_calibration_data * prof->bytes_per_line + 2;
}

gboolean
validity_clean_slate_header_valid (const guint8 *hdr, gsize len, guint16 *payload_len)
{
  if (len < VALIDITY_CLEAN_SLATE_HDR_SIZE || FP_READ_UINT16_LE (hdr) != CLEAN_SLATE_MAGIC)
    return FALSE;

  for (gsize i = 36; i < VALIDITY_CLEAN_SLATE_HDR_SIZE; i++)
    if (hdr[i] != 0)
      return FALSE;

  *payload_len = FP_READ_UINT16_LE (hdr + 2);
  return *payload_len > 0;
}

gboolean
validity_clean_slate_payload_valid (const guint8 *hdr, const guint8 *payload, gsize payload_len)
{
  guint8 digest[32];
  unsigned int digest_len = sizeof (digest);

  if (EVP_Digest (payload, payload_len, digest, &digest_len, EVP_sha256 (), NULL) != 1)
    return FALSE;

  return memcmp (digest, hdr + 4, sizeof (digest)) == 0;
}

/* ---------------------------------------------------------------------- */
/* Image preparation                                                      */
/* ---------------------------------------------------------------------- */

guint8 *
validity_image_prepare (const guint8 *pixels, guint width, guint height,
                        guint scale, guint pad, guint *out_width, guint *out_height)
{
  guint sw, sh, w, h;
  g_autofree guint8 *scaled = NULL;
  guint8 *out;

  g_return_val_if_fail (pixels != NULL && width > 0 && height > 0 && scale > 0, NULL);

  sw = width * scale;
  sh = height * scale;
  w = sw + 2 * pad;
  h = sh + 2 * pad;
  scaled = g_malloc (sw * sh);
  out = g_malloc (w * h);

  /* Bilinear interpolation with pixel centers aligned (x + 0.5) */
  for (guint y = 0; y < sh; y++)
    {
      double fy = (y + 0.5) / scale - 0.5;
      gint y0 = CLAMP ((gint) floor (fy), 0, (gint) height - 1);
      gint y1 = MIN (y0 + 1, (gint) height - 1);
      double ay = CLAMP (fy - y0, 0.0, 1.0);

      for (guint x = 0; x < sw; x++)
        {
          double fx = (x + 0.5) / scale - 0.5;
          gint x0 = CLAMP ((gint) floor (fx), 0, (gint) width - 1);
          gint x1 = MIN (x0 + 1, (gint) width - 1);
          double ax = CLAMP (fx - x0, 0.0, 1.0);
          double v = (1 - ay) * ((1 - ax) * pixels[y0 * width + x0] + ax * pixels[y0 * width + x1]) +
                     ay * ((1 - ax) * pixels[y1 * width + x0] + ax * pixels[y1 * width + x1]);

          scaled[y * sw + x] = (guint8) CLAMP (v + 0.5, 0, 255);
        }
    }

  /* Replicated edges let the minutiae detector use the blocks near the
   * sensor edge.  A flat fill would create artificial ridge endings at the
   * same positions in every image. */
  for (guint y = 0; y < h; y++)
    for (guint x = 0; x < w; x++)
      {
        guint sy = CLAMP ((gint) y - (gint) pad, 0, (gint) sh - 1);
        guint sx = CLAMP ((gint) x - (gint) pad, 0, (gint) sw - 1);

        out[y * w + x] = scaled[sy * sw + sx];
      }

  explicit_bzero (scaled, sw * sh);
  *out_width = w;
  *out_height = h;
  return out;
}
