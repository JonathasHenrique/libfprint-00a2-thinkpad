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

#pragma once

#include <glib.h>

/*
 * The sensor only accepts certain operations when they are accompanied by
 * vendor-signed blobs, and it runs a vendor-signed firmware extension.
 * These are not redistributable, so they are extracted from the vendor's
 * Windows driver package at install time (see
 * scripts/validity-extract-vendor-data.py) and loaded from disk at runtime.
 * Every file is verified against a pinned SHA-256 digest before use.
 */

typedef enum {
  VALIDITY_VENDOR_INIT,              /* sent on every open */
  VALIDITY_VENDOR_RESET,             /* unlocks factory reset/partitioning */
  VALIDITY_VENDOR_DB_WRITE_ENABLE,   /* unlocks flash writes */
  VALIDITY_VENDOR_PARTITION_SIG,     /* signature of the flash layout */
  VALIDITY_VENDOR_FWEXT,             /* firmware extension image */
  VALIDITY_VENDOR_N_FILES,
} ValidityVendorFile;

typedef struct _ValidityVendorData ValidityVendorData;

/* @dir_override may be NULL; otherwise used instead of the compiled-in
 * data directory (used by the test suite). */
ValidityVendorData *validity_vendor_data_new (guint16      vid,
                                              guint16      pid,
                                              const gchar *dir_override,
                                              GError     **error);

void validity_vendor_data_free (ValidityVendorData *data);

/* Loads (once) and returns a verified file. */
GBytes *validity_vendor_data_get (ValidityVendorData *data,
                                  ValidityVendorFile  file,
                                  GError            **error);

/* Loads and verifies every file needed to (re-)provision the sensor, so
 * that a destructive provisioning run is only started when it can finish. */
gboolean validity_vendor_data_check_provisioning (ValidityVendorData *data,
                                                  GError            **error);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (ValidityVendorData, validity_vendor_data_free)
