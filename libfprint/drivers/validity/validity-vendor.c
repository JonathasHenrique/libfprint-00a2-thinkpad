/*
 * Synaptics/Validity "VSI" sensors: vendor data files
 *
 * Copyright (C) 2026 Aurel Farkasovsky
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

#include "config.h"
#include "fpi-log.h"
#include "fpi-device.h"
#include "validity-vendor.h"

#include <openssl/evp.h>
#include <string.h>

typedef struct
{
  const gchar *name;
  const gchar *sha256;
} VendorFileInfo;

typedef struct
{
  guint16        vid;
  guint16        pid;
  const gchar   *subdir;
  VendorFileInfo files[VALIDITY_VENDOR_N_FILES];
} VendorDeviceInfo;

/* Extracted from the Lenovo package r0yfp10w.exe (driver 5.2.326.26). */
static const VendorDeviceInfo vendor_devices[] = {
  {
    .vid = 0x06cb,
    .pid = 0x00a2,
    .subdir = "06cb-00a2",
    .files = {
      [VALIDITY_VENDOR_INIT] = {
        "init.bin",
        "0f3128a1c93b49f0a5162bbad26b22ae02f539ab0668678ea090449922e39674"
      },
      [VALIDITY_VENDOR_RESET] = {
        "reset.bin",
        "1a43ff9949f64f71e9b62003015b6101a3d36a8442e52fd0d58cb12964b0e706"
      },
      [VALIDITY_VENDOR_DB_WRITE_ENABLE] = {
        "db-write-enable.bin",
        "cd3fe4e0b3be7af277dceb040bddf53bf001e0dcfffa912c9cd67b2b9c34e371"
      },
      [VALIDITY_VENDOR_PARTITION_SIG] = {
        "partition-signature.bin",
        "8389426fc0cfa3d75cf79ee3d93ba21e43e2a8b606202f084d55446bc846bbdb"
      },
      [VALIDITY_VENDOR_FWEXT] = {
        "6_07f_lenovo_sm_qm.xpfwext",
        "ad14dddb5914cad8fa9f6a2a29120c152476bdac10c735beadbc15e9c2e05ba6"
      },
    },
  },
};

struct _ValidityVendorData
{
  const VendorDeviceInfo *info;
  gchar                  *dir;
  GBytes                 *files[VALIDITY_VENDOR_N_FILES];
};

static gchar *
sha256_hex (GBytes *bytes)
{
  guint8 digest[32];
  unsigned int len = sizeof (digest);
  gsize size;
  const guint8 *data = g_bytes_get_data (bytes, &size);
  GString *hex = g_string_sized_new (64);

  if (EVP_Digest (data, size, digest, &len, EVP_sha256 (), NULL) != 1)
    g_error ("validity: SHA-256 failed");

  for (guint i = 0; i < len; i++)
    g_string_append_printf (hex, "%02x", digest[i]);

  return g_string_free (hex, FALSE);
}

ValidityVendorData *
validity_vendor_data_new (guint16 vid, guint16 pid, const gchar *dir_override, GError **error)
{
  g_autoptr(ValidityVendorData) data = g_new0 (ValidityVendorData, 1);

  for (guint i = 0; i < G_N_ELEMENTS (vendor_devices); i++)
    if (vendor_devices[i].vid == vid && vendor_devices[i].pid == pid)
      data->info = &vendor_devices[i];

  if (!data->info)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED,
                   "No vendor data known for %04x:%04x", vid, pid);
      return NULL;
    }

  data->dir = g_build_filename (dir_override ? dir_override : VALIDITY_DATA_DIR,
                                data->info->subdir, NULL);
  return g_steal_pointer (&data);
}

void
validity_vendor_data_free (ValidityVendorData *data)
{
  if (!data)
    return;

  for (guint i = 0; i < VALIDITY_VENDOR_N_FILES; i++)
    g_clear_pointer (&data->files[i], g_bytes_unref);
  g_free (data->dir);
  g_free (data);
}

static GBytes *
load_file (ValidityVendorData *data, ValidityVendorFile file, GError **error)
{
  const VendorFileInfo *info = &data->info->files[file];
  g_autofree gchar *path = g_build_filename (data->dir, info->name, NULL);
  g_autofree gchar *contents = NULL;
  g_autofree gchar *digest = NULL;

  g_autoptr(GError) local_error = NULL;
  g_autoptr(GBytes) bytes = NULL;
  gsize len;

  if (!g_file_get_contents (path, &contents, &len, &local_error))
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                   "Missing sensor vendor data (%s). Extract it from the vendor driver "
                   "package with scripts/validity-extract-vendor-data.py from the libfprint "
                   "sources (see drivers/validity/README.md).",
                   local_error->message);
      return NULL;
    }

  bytes = g_bytes_new_take (g_steal_pointer (&contents), len);
  digest = sha256_hex (bytes);
  if (g_strcmp0 (digest, info->sha256) != 0)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                   "Sensor vendor data file %s does not have the expected contents "
                   "(SHA-256 %s)", path, digest);
      return NULL;
    }

  fp_dbg ("Loaded vendor data file %s (%" G_GSIZE_FORMAT " bytes)", path, len);
  return g_steal_pointer (&bytes);
}

GBytes *
validity_vendor_data_get (ValidityVendorData *data, ValidityVendorFile file, GError **error)
{
  g_return_val_if_fail (file < VALIDITY_VENDOR_N_FILES, NULL);

  if (!data->files[file])
    data->files[file] = load_file (data, file, error);

  return data->files[file] ? g_bytes_ref (data->files[file]) : NULL;
}

gboolean
validity_vendor_data_check_provisioning (ValidityVendorData *data, GError **error)
{
  for (guint i = 0; i < VALIDITY_VENDOR_N_FILES; i++)
    {
      g_autoptr(GBytes) bytes = validity_vendor_data_get (data, i, error);

      if (!bytes)
        return FALSE;
    }

  return TRUE;
}
