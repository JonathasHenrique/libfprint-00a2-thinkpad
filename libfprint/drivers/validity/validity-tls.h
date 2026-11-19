/*
 * Synaptics/Validity "VSI" sensors: TLS-like secure channel
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

/*
 * The sensor uses a modified TLS 1.2, close to
 * TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA but without sequence numbers in the
 * MAC and with non-standard message encodings.  This module builds and
 * parses the messages but does no I/O, so it can be unit tested without a
 * device.
 *
 * The long-term pairing keys are stored on the sensor's flash ("TLS flash",
 * partition 1).  The host private key there is encrypted with a key derived
 * from the host's DMI product name and serial number, so the host keeps no
 * state of its own.
 */

#define VALIDITY_TLS_FLASH_SIZE 0x1000
#define VALIDITY_TLS_ECDH_BLOB_SIZE 400
#define VALIDITY_TLS_PAIRING_CERT_LEN 444
/* Largest sensor certificate that still fits into the pairing data */
#define VALIDITY_TLS_MAX_CERT_LEN 0x800

typedef enum {
  /* Paired with another host or host identity. Needs re-pairing. */
  VALIDITY_TLS_ERROR_FOREIGN_PAIRING,
  /* Malformed or unexpected data. */
  VALIDITY_TLS_ERROR_PROTO,
  /* A cryptographic primitive failed or a signature/MAC did not verify. */
  VALIDITY_TLS_ERROR_CRYPTO,
} ValidityTlsError;

#define VALIDITY_TLS_ERROR (validity_tls_error_quark ())
GQuark validity_tls_error_quark (void);

/**
 * ValidityRandomFunc:
 * @buf: buffer to fill
 * @len: number of bytes to generate
 * @user_data: user data
 *
 * Source of randomness. The default uses the OpenSSL CSPRNG; tests and
 * emulation replace it with a deterministic stream.
 */
typedef void (*ValidityRandomFunc) (guint8  *buf,
                                    gsize    len,
                                    gpointer user_data);

typedef struct _ValidityTls ValidityTls;

ValidityTls *validity_tls_new (void);
void validity_tls_free (ValidityTls *self);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (ValidityTls, validity_tls_free)

void validity_tls_set_random_func (ValidityTls       *self,
                                   ValidityRandomFunc func,
                                   gpointer           user_data);

/* Derives the host-bound keys that protect the pairing private key. */
void validity_tls_set_host_identity (ValidityTls *self,
                                     const gchar *product_name,
                                     const gchar *product_serial);

/* --- Long-term pairing data ("TLS flash") ------------------------------ */

gboolean validity_tls_load_flash (ValidityTls  *self,
                                  const guint8 *data,
                                  gsize         len,
                                  GError      **error);

GBytes *validity_tls_build_flash (ValidityTls *self,
                                  GError     **error);

gboolean validity_tls_has_pairing (ValidityTls *self);

/* --- Creating a new pairing -------------------------------------------- */

gboolean validity_tls_pairing_begin (ValidityTls *self,
                                     GError     **error);

GBytes *validity_tls_pairing_get_client_cert (ValidityTls *self,
                                              GError     **error);

gboolean validity_tls_pairing_set_server_cert (ValidityTls  *self,
                                               const guint8 *cert,
                                               gsize         len,
                                               GError      **error);

gboolean validity_tls_pairing_set_server_ecdh (ValidityTls  *self,
                                               const guint8 *blob,
                                               gsize         len,
                                               GError      **error);

gboolean validity_tls_pairing_finish (ValidityTls *self,
                                      GError     **error);

/* Fixed data block sent to the sensor when partitioning its flash. */
const guint8 *validity_tls_get_ca_blob (gsize *len);

/* --- Session establishment --------------------------------------------- */

void validity_tls_reset_session (ValidityTls *self);

gboolean validity_tls_is_established (ValidityTls *self);

GBytes *validity_tls_build_client_hello (ValidityTls *self,
                                         GError     **error);

gboolean validity_tls_handle_server_hello (ValidityTls  *self,
                                           const guint8 *rsp,
                                           gsize         len,
                                           GError      **error);

GBytes *validity_tls_build_client_finish (ValidityTls *self,
                                          GError     **error);

gboolean validity_tls_handle_server_finish (ValidityTls  *self,
                                            const guint8 *rsp,
                                            gsize         len,
                                            GError      **error);

/* --- Application data -------------------------------------------------- */

GBytes *validity_tls_wrap (ValidityTls  *self,
                           const guint8 *data,
                           gsize         len,
                           GError      **error);

GBytes *validity_tls_unwrap (ValidityTls  *self,
                             const guint8 *rsp,
                             gsize         len,
                             GError      **error);

/* --- Exposed for unit tests -------------------------------------------- */

void validity_tls_prf (const guint8 *secret,
                       gsize         secret_len,
                       const guint8 *seed,
                       gsize         seed_len,
                       guint8       *out,
                       gsize         out_len);
