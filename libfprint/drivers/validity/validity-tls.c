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

#define FP_COMPONENT "validity"

#include "fpi-log.h"
#include "validity-tls.h"

#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>

G_DEFINE_AUTOPTR_CLEANUP_FUNC (EVP_PKEY, EVP_PKEY_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (OSSL_PARAM_BLD, OSSL_PARAM_BLD_free)

#define KEY_SIZE 32           /* AES-256 and HMAC-SHA256 keys */
#define MAC_SIZE 32           /* HMAC-SHA256 output, never truncated */
#define AES_BLOCK 16
#define RANDOM_SIZE 32
#define MASTER_SIZE 48
#define KEY_BLOCK_SIZE 0x120
#define VERIFY_DATA_SIZE 12
#define EC_COORD_SIZE 32

#define TLS_CONTENT_CCS 0x14
#define TLS_CONTENT_ALERT 0x15
#define TLS_CONTENT_HANDSHAKE 0x16
#define TLS_CONTENT_APP_DATA 0x17

#define HS_SERVER_HELLO 0x02
#define HS_CERTIFICATE 0x0b
#define HS_CERTIFICATE_REQUEST 0x0d
#define HS_SERVER_HELLO_DONE 0x0e
#define HS_CERTIFICATE_VERIFY 0x0f
#define HS_CLIENT_KEY_EXCHANGE 0x10
#define HS_FINISHED 0x14
#define HS_CLIENT_HELLO 0x01

#define CIPHER_SUITE_ECDH_ECDSA_AES256_CBC_SHA 0xc005

/* Pairing (TLS flash) block identifiers */
#define FLASH_BLOCK_EMPTY0 0
#define FLASH_BLOCK_EMPTY1 1
#define FLASH_BLOCK_EMPTY2 2
#define FLASH_BLOCK_CERT 3
#define FLASH_BLOCK_PRIVKEY 4
#define FLASH_BLOCK_CA 5
#define FLASH_BLOCK_ECDH 6
#define FLASH_BLOCK_END 0xffff
#define FLASH_BLOCK_HDR (2 + 2 + 32)

#define PRIVKEY_BLOB_PREFIX 0x02

/* Prefix of the sensor command that carries handshake records. */
static const guint8 handshake_cmd_prefix[] = { 0x44, 0x00, 0x00, 0x00 };

/* Fixed secret shared by all hosts; used to derive the key that signs the
 * client certificate (the sensor knows the matching public key) and the
 * host-bound keys protecting the pairing private key. */
static const guint8 password_hardcoded[32] = {
  0x71, 0x7c, 0xd7, 0x2d, 0x09, 0x62, 0xbc, 0x4a, 0x28, 0x46, 0x13, 0x8d, 0xbb, 0x2c, 0x24, 0x19,
  0x25, 0x12, 0xa7, 0x64, 0x07, 0x06, 0x5f, 0x38, 0x38, 0x46, 0x13, 0x9d, 0x4b, 0xec, 0x20, 0x33,
};

static const guint8 gwk_sign_hardcoded[32] = {
  0x3a, 0x4c, 0x76, 0xb7, 0x6a, 0x97, 0x98, 0x1d, 0x12, 0x74, 0x24, 0x7e, 0x16, 0x66, 0x10, 0xe7,
  0x7f, 0x4d, 0x9c, 0x9d, 0x07, 0xd3, 0xc7, 0x28, 0xe5, 0x32, 0x91, 0x6b, 0xdd, 0x28, 0xb4, 0x54,
};

/* Firmware public key (big endian X, Y on P-256); the sensor signs its ECDH
 * key with the matching private key. */
static const guint8 fw_pubkey_x[32] = {
  0xf7, 0x27, 0x65, 0x3b, 0x4e, 0x16, 0xce, 0x06, 0x65, 0xa6, 0x89, 0x4d, 0x7f, 0x3a, 0x30, 0xd7,
  0xd0, 0xa0, 0xbe, 0x31, 0x0d, 0x12, 0x92, 0xa7, 0x43, 0x67, 0x1f, 0xdf, 0x69, 0xf6, 0xa8, 0xd3,
};

static const guint8 fw_pubkey_y[32] = {
  0xa8, 0x55, 0x38, 0xf8, 0xb6, 0xbe, 0xc5, 0x0d, 0x6e, 0xef, 0x8b, 0xd5, 0xf4, 0xd0, 0x7a, 0x88,
  0x62, 0x43, 0xc5, 0x8b, 0x23, 0x93, 0x94, 0x8d, 0xf7, 0x61, 0xa8, 0x47, 0x21, 0xa6, 0xca, 0x94,
};

/* NIST P-256 domain parameters in the sensor's native little-endian
 * structure ("crt_hardcoded" in python-validity). */
static const guint8 ca_blob[420] = {
  0x17, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xfc, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x4b, 0x60, 0xd2, 0x27, 0x3e, 0x3c, 0xce, 0x3b, 0xf6, 0xb0, 0x53, 0xcc, 0xb0, 0x06, 0x1d, 0x65,
  0xbc, 0x86, 0x98, 0x76, 0x55, 0xbd, 0xeb, 0xb3, 0xe7, 0x93, 0x3a, 0xaa, 0xd8, 0x35, 0xc6, 0x5a,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x96, 0xc2, 0x98, 0xd8, 0x45, 0x39, 0xa1, 0xf4, 0xa0, 0x33, 0xeb, 0x2d,
  0x81, 0x7d, 0x03, 0x77, 0xf2, 0x40, 0xa4, 0x63, 0xe5, 0xe6, 0xbc, 0xf8, 0x47, 0x42, 0x2c, 0xe1,
  0xf2, 0xd1, 0x17, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf5, 0x51, 0xbf, 0x37, 0x68, 0x40, 0xb6, 0xcb,
  0xce, 0x5e, 0x31, 0x6b, 0x57, 0x33, 0xce, 0x2b, 0x16, 0x9e, 0x0f, 0x7c, 0x4a, 0xeb, 0xe7, 0x8e,
  0x9b, 0x7f, 0x1a, 0xfe, 0xe2, 0x42, 0xe3, 0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x51, 0x25, 0x63, 0xfc,
  0xc2, 0xca, 0xb9, 0xf3, 0x84, 0x9e, 0x17, 0xa7, 0xad, 0xfa, 0xe6, 0xbc, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
};

struct _ValidityTls
{
  ValidityRandomFunc random_func;
  gpointer           random_data;

  /* Host-bound keys protecting the pairing private key */
  guint8 psk_encryption_key[KEY_SIZE];
  guint8 psk_validation_key[KEY_SIZE];

  /* Long-term pairing material */
  EVP_PKEY *client_key;                 /* host private key */
  guint8    client_x[EC_COORD_SIZE];           /* big endian */
  guint8    client_y[EC_COORD_SIZE];
  guint8    client_d[EC_COORD_SIZE];
  GBytes   *server_cert;                /* sensor certificate */
  GBytes   *ecdh_blob;                  /* signed sensor ECDH key */
  EVP_PKEY *server_ecdh_key;
  GBytes   *priv_blob;                  /* encrypted host private key */

  /* Session state */
  EVP_MD_CTX *handshake_hash;
  guint8      client_random[RANDOM_SIZE];
  guint8      server_random[RANDOM_SIZE];
  guint8      session_x[EC_COORD_SIZE];         /* ephemeral public key */
  guint8      session_y[EC_COORD_SIZE];
  guint8      master_secret[MASTER_SIZE];
  guint8      sign_key[KEY_SIZE];
  guint8      validation_key[KEY_SIZE];
  guint8      encryption_key[KEY_SIZE];
  guint8      decryption_key[KEY_SIZE];
  gboolean    keys_ready;
  gboolean    secure_rx;
  gboolean    secure_tx;
};

G_DEFINE_QUARK (validity - tls - error - quark, validity_tls_error)

/* ---------------------------------------------------------------------- */
/* Helpers                                                                */
/* ---------------------------------------------------------------------- */

static void
reverse_copy (guint8 *dst, const guint8 *src, gsize len)
{
  for (gsize i = 0; i < len; i++)
    dst[i] = src[len - 1 - i];
}

static void
default_random (guint8 *buf, gsize len, gpointer user_data)
{
  /* RAND_bytes() only fails if the CSPRNG cannot be seeded at all, in which
   * case continuing would be insecure. */
  if (RAND_bytes (buf, len) != 1)
    g_error ("validity: OpenSSL failed to generate random bytes");
}

static void
get_random (ValidityTls *self, guint8 *buf, gsize len)
{
  self->random_func (buf, len, self->random_data);
}

static gboolean
set_crypto_error (GError **error, const gchar *what)
{
  g_set_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_CRYPTO,
               "Cryptographic operation failed: %s", what);
  return FALSE;
}

static void
hmac_sha256 (const guint8 *key, gsize key_len,
             const guint8 *data1, gsize data1_len,
             const guint8 *data2, gsize data2_len,
             guint8 out[MAC_SIZE])
{
  g_autofree guint8 *buf = g_malloc (data1_len + data2_len);
  unsigned int out_len = MAC_SIZE;

  if (data1_len)
    memcpy (buf, data1, data1_len);
  if (data2_len)
    memcpy (buf + data1_len, data2, data2_len);

  if (!HMAC (EVP_sha256 (), key, key_len, buf, data1_len + data2_len, out, &out_len))
    g_error ("validity: HMAC-SHA256 failed");

  OPENSSL_cleanse (buf, data1_len + data2_len);
}

void
validity_tls_prf (const guint8 *secret, gsize secret_len,
                  const guint8 *seed, gsize seed_len,
                  guint8 *out, gsize out_len)
{
  guint8 a[MAC_SIZE];
  guint8 block[MAC_SIZE];
  gsize done = 0;

  /* TLS 1.2 P_SHA256: A(1) = HMAC(secret, seed) */
  hmac_sha256 (secret, secret_len, seed, seed_len, NULL, 0, a);

  while (done < out_len)
    {
      gsize n;

      hmac_sha256 (secret, secret_len, a, sizeof (a), seed, seed_len, block);
      n = MIN (sizeof (block), out_len - done);
      memcpy (out + done, block, n);
      done += n;

      hmac_sha256 (secret, secret_len, a, sizeof (a), NULL, 0, a);
    }

  OPENSSL_cleanse (a, sizeof (a));
  OPENSSL_cleanse (block, sizeof (block));
}

/* PRF with a "label" + seed, as used throughout the protocol. */
static void
prf_label (const guint8 *secret, gsize secret_len,
           const gchar *label,
           const guint8 *seed, gsize seed_len,
           guint8 *out, gsize out_len)
{
  gsize label_len = strlen (label);
  g_autofree guint8 *buf = g_malloc (label_len + seed_len);

  memcpy (buf, label, label_len);
  if (seed_len)
    memcpy (buf + label_len, seed, seed_len);

  validity_tls_prf (secret, secret_len, buf, label_len + seed_len, out, out_len);
  OPENSSL_cleanse (buf, label_len + seed_len);
}

static gboolean
aes256_cbc (gboolean encrypt,
            const guint8 key[KEY_SIZE], const guint8 iv[AES_BLOCK],
            const guint8 *in, gsize len, guint8 *out)
{
  EVP_CIPHER_CTX *ctx;
  int out_len = 0, final_len = 0;
  gboolean ok;

  g_return_val_if_fail (len % AES_BLOCK == 0, FALSE);

  ctx = EVP_CIPHER_CTX_new ();
  if (!ctx)
    return FALSE;

  ok = EVP_CipherInit_ex (ctx, EVP_aes_256_cbc (), NULL, key, iv, encrypt ? 1 : 0) == 1 &&
       EVP_CIPHER_CTX_set_padding (ctx, 0) == 1 &&
       EVP_CipherUpdate (ctx, out, &out_len, in, len) == 1 &&
       EVP_CipherFinal_ex (ctx, out + out_len, &final_len) == 1 &&
       (gsize) (out_len + final_len) == len;

  EVP_CIPHER_CTX_free (ctx);
  return ok;
}

/* --- Elliptic curve helpers (NIST P-256) ------------------------------- */

static EVP_PKEY *
ec_key_from_params (const guint8 *priv_be, const guint8 *x_be, const guint8 *y_be)
{
  g_autoptr(OSSL_PARAM_BLD) bld = OSSL_PARAM_BLD_new ();
  OSSL_PARAM *params = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *pkey = NULL;
  BIGNUM *priv = NULL;
  guint8 point[1 + 2 * EC_COORD_SIZE];
  int selection = EVP_PKEY_PUBLIC_KEY;

  if (!bld)
    return NULL;

  point[0] = POINT_CONVERSION_UNCOMPRESSED;
  memcpy (point + 1, x_be, EC_COORD_SIZE);
  memcpy (point + 1 + EC_COORD_SIZE, y_be, EC_COORD_SIZE);

  if (!OSSL_PARAM_BLD_push_utf8_string (bld, OSSL_PKEY_PARAM_GROUP_NAME, SN_X9_62_prime256v1, 0) ||
      !OSSL_PARAM_BLD_push_octet_string (bld, OSSL_PKEY_PARAM_PUB_KEY, point, sizeof (point)))
    goto out;

  if (priv_be)
    {
      priv = BN_secure_new ();
      if (!priv || !BN_bin2bn (priv_be, EC_COORD_SIZE, priv) ||
          !OSSL_PARAM_BLD_push_BN (bld, OSSL_PKEY_PARAM_PRIV_KEY, priv))
        goto out;
      selection = EVP_PKEY_KEYPAIR;
    }

  params = OSSL_PARAM_BLD_to_param (bld);
  ctx = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);
  if (!params || !ctx || EVP_PKEY_fromdata_init (ctx) != 1 ||
      EVP_PKEY_fromdata (ctx, &pkey, selection, params) != 1)
    pkey = NULL;

out:
  OSSL_PARAM_free (params);
  EVP_PKEY_CTX_free (ctx);
  BN_clear_free (priv);
  OPENSSL_cleanse (point, sizeof (point));
  return pkey;
}

/* Computes the public point for @priv_be.  Returns FALSE if the scalar is
 * not a valid private key (zero or >= group order). */
static gboolean
ec_public_from_private (const guint8 *priv_be, guint8 *x_be, guint8 *y_be)
{
  EC_GROUP *group = EC_GROUP_new_by_curve_name (NID_X9_62_prime256v1);
  EC_POINT *point = NULL;
  BIGNUM *priv = BN_secure_new ();
  BN_CTX *bn_ctx = BN_CTX_new ();
  guint8 buf[1 + 2 * EC_COORD_SIZE];
  gboolean ok = FALSE;

  if (!group || !priv || !bn_ctx || !BN_bin2bn (priv_be, EC_COORD_SIZE, priv))
    goto out;

  if (BN_is_zero (priv) || BN_cmp (priv, EC_GROUP_get0_order (group)) >= 0)
    goto out;

  point = EC_POINT_new (group);
  if (!point || !EC_POINT_mul (group, point, priv, NULL, NULL, bn_ctx) ||
      EC_POINT_point2oct (group, point, POINT_CONVERSION_UNCOMPRESSED,
                          buf, sizeof (buf), bn_ctx) != sizeof (buf))
    goto out;

  memcpy (x_be, buf + 1, EC_COORD_SIZE);
  memcpy (y_be, buf + 1 + EC_COORD_SIZE, EC_COORD_SIZE);
  ok = TRUE;

out:
  EC_POINT_free (point);
  EC_GROUP_free (group);
  BN_clear_free (priv);
  BN_CTX_free (bn_ctx);
  return ok;
}

/* Generates a key pair using the configured random source, so that
 * emulation runs are deterministic. */
static EVP_PKEY *
ec_generate (ValidityTls *self, guint8 *priv_be, guint8 *x_be, guint8 *y_be)
{
  for (guint attempt = 0; attempt < 64; attempt++)
    {
      get_random (self, priv_be, EC_COORD_SIZE);
      if (ec_public_from_private (priv_be, x_be, y_be))
        return ec_key_from_params (priv_be, x_be, y_be);
    }

  return NULL;
}

/* ECDSA over a precomputed SHA-256 digest; DER encoded signature.
 * With OpenSSL 3.2 or later the nonces are deterministic (RFC 6979): the
 * signatures then do not depend on RNG quality, and emulation runs are
 * reproducible. */
static GBytes *
ecdsa_sign_digest (EVP_PKEY *key, const guint8 digest[32])
{
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey (NULL, key, NULL);
  g_autofree guint8 *sig = NULL;
  size_t sig_len = 0;
  GBytes *res = NULL;

  if (!ctx || EVP_PKEY_sign_init (ctx) != 1 ||
      EVP_PKEY_CTX_set_signature_md (ctx, EVP_sha256 ()) != 1)
    goto out;

#if OPENSSL_VERSION_NUMBER >= 0x30200000L
  {
    unsigned int nonce_type = 1;
    OSSL_PARAM params[] = {
      OSSL_PARAM_construct_uint (OSSL_SIGNATURE_PARAM_NONCE_TYPE, &nonce_type),
      OSSL_PARAM_construct_end (),
    };

    if (EVP_PKEY_CTX_set_params (ctx, params) != 1)
      goto out;
  }
#endif

  if (EVP_PKEY_sign (ctx, NULL, &sig_len, digest, 32) != 1)
    goto out;

  sig = g_malloc (sig_len);
  if (EVP_PKEY_sign (ctx, sig, &sig_len, digest, 32) != 1)
    goto out;

  res = g_bytes_new (sig, sig_len);

out:
  EVP_PKEY_CTX_free (ctx);
  return res;
}

static gboolean
ecdsa_verify_digest (EVP_PKEY *key, const guint8 digest[32],
                     const guint8 *sig, gsize sig_len)
{
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey (NULL, key, NULL);
  gboolean ok;

  ok = ctx && EVP_PKEY_verify_init (ctx) == 1 &&
       EVP_PKEY_CTX_set_signature_md (ctx, EVP_sha256 ()) == 1 &&
       EVP_PKEY_verify (ctx, sig, sig_len, digest, 32) == 1;

  EVP_PKEY_CTX_free (ctx);
  return ok;
}

static void
sha256 (const guint8 *data, gsize len, guint8 out[32])
{
  unsigned int out_len = 32;

  if (EVP_Digest (data, len, out, &out_len, EVP_sha256 (), NULL) != 1)
    g_error ("validity: SHA-256 failed");
}

/* Signing key for client certificates, derived from the shared secret. */
static EVP_PKEY *
hs_key_new (void)
{
  guint8 seed[16 + 2];
  guint8 hs[EC_COORD_SIZE];
  guint8 d_be[EC_COORD_SIZE];
  guint8 x[EC_COORD_SIZE], y[EC_COORD_SIZE];
  EVP_PKEY *key = NULL;

  memcpy (seed, password_hardcoded + 16, 16);
  seed[16] = seed[17] = 0xaa;

  prf_label (password_hardcoded, 16, "HS_KEY_PAIR_GEN", seed, sizeof (seed), hs, sizeof (hs));
  /* The PRF output is a little endian integer */
  reverse_copy (d_be, hs, sizeof (hs));

  if (ec_public_from_private (d_be, x, y))
    key = ec_key_from_params (d_be, x, y);

  OPENSSL_cleanse (hs, sizeof (hs));
  OPENSSL_cleanse (d_be, sizeof (d_be));
  return key;
}

/* ---------------------------------------------------------------------- */
/* Object lifetime                                                        */
/* ---------------------------------------------------------------------- */

ValidityTls *
validity_tls_new (void)
{
  ValidityTls *self = g_new0 (ValidityTls, 1);

  self->random_func = default_random;
  return self;
}

static void
clear_pairing (ValidityTls *self)
{
  g_clear_pointer (&self->client_key, EVP_PKEY_free);
  g_clear_pointer (&self->server_ecdh_key, EVP_PKEY_free);
  g_clear_pointer (&self->server_cert, g_bytes_unref);
  g_clear_pointer (&self->ecdh_blob, g_bytes_unref);
  g_clear_pointer (&self->priv_blob, g_bytes_unref);
  OPENSSL_cleanse (self->client_d, sizeof (self->client_d));
  memset (self->client_x, 0, sizeof (self->client_x));
  memset (self->client_y, 0, sizeof (self->client_y));
}

void
validity_tls_free (ValidityTls *self)
{
  if (!self)
    return;

  validity_tls_reset_session (self);
  clear_pairing (self);
  OPENSSL_cleanse (self->psk_encryption_key, sizeof (self->psk_encryption_key));
  OPENSSL_cleanse (self->psk_validation_key, sizeof (self->psk_validation_key));
  g_free (self);
}

void
validity_tls_set_random_func (ValidityTls *self, ValidityRandomFunc func, gpointer user_data)
{
  self->random_func = func ? func : default_random;
  self->random_data = func ? user_data : NULL;
}

void
validity_tls_set_host_identity (ValidityTls *self,
                                const gchar *product_name,
                                const gchar *product_serial)
{
  g_autoptr(GByteArray) seed = g_byte_array_new ();

  /* "GWK" || product_name || NUL || serial || NUL */
  g_byte_array_append (seed, (const guint8 *) "GWK", 3);
  g_byte_array_append (seed, (const guint8 *) product_name, strlen (product_name) + 1);
  g_byte_array_append (seed, (const guint8 *) product_serial, strlen (product_serial) + 1);

  validity_tls_prf (password_hardcoded, sizeof (password_hardcoded),
                    seed->data, seed->len,
                    self->psk_encryption_key, KEY_SIZE);
  prf_label (self->psk_encryption_key, KEY_SIZE, "GWK_SIGN",
             gwk_sign_hardcoded, sizeof (gwk_sign_hardcoded),
             self->psk_validation_key, KEY_SIZE);

  OPENSSL_cleanse (seed->data, seed->len);
}

const guint8 *
validity_tls_get_ca_blob (gsize *len)
{
  *len = sizeof (ca_blob);
  return ca_blob;
}

/* ---------------------------------------------------------------------- */
/* Pairing data                                                           */
/* ---------------------------------------------------------------------- */

static gboolean
handle_priv_blob (ValidityTls *self, const guint8 *body, gsize len, GError **error)
{
  guint8 mac[MAC_SIZE];
  g_autofree guint8 *plain = NULL;
  const guint8 *iv, *ct;
  gsize ct_len;
  guint8 pad;

  /* prefix(1) || iv(16) || ciphertext(n*16) || mac(32) */
  if (len < 1 + AES_BLOCK + AES_BLOCK + MAC_SIZE ||
      (len - 1 - AES_BLOCK - MAC_SIZE) % AES_BLOCK != 0 ||
      body[0] != PRIVKEY_BLOB_PREFIX)
    {
      g_set_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                   "Unsupported private key blob (len %" G_GSIZE_FORMAT ", prefix 0x%02x)",
                   len, len ? body[0] : 0);
      return FALSE;
    }

  hmac_sha256 (self->psk_validation_key, KEY_SIZE, body + 1, len - 1 - MAC_SIZE, NULL, 0, mac);
  if (CRYPTO_memcmp (mac, body + len - MAC_SIZE, MAC_SIZE) != 0)
    {
      g_set_error_literal (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_FOREIGN_PAIRING,
                           "Pairing data was created by a different host");
      return FALSE;
    }

  iv = body + 1;
  ct = iv + AES_BLOCK;
  ct_len = len - 1 - AES_BLOCK - MAC_SIZE;
  plain = g_malloc (ct_len);

  if (!aes256_cbc (FALSE, self->psk_encryption_key, iv, ct, ct_len, plain))
    {
      OPENSSL_cleanse (plain, ct_len);
      return set_crypto_error (error, "private key decryption");
    }

  /* Standard PKCS#7 padding; x || y || d, all little endian */
  pad = plain[ct_len - 1];
  if (pad == 0 || pad > AES_BLOCK || ct_len - pad < 3 * EC_COORD_SIZE)
    {
      OPENSSL_cleanse (plain, ct_len);
      g_set_error_literal (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                           "Bad private key padding");
      return FALSE;
    }

  g_clear_pointer (&self->client_key, EVP_PKEY_free);
  reverse_copy (self->client_d, plain + 2 * EC_COORD_SIZE, EC_COORD_SIZE);
  OPENSSL_cleanse (plain, ct_len);

  /* The stored public coordinates are unreliable (some Windows driver
   * versions store zeroes), so always recompute them. */
  if (!ec_public_from_private (self->client_d, self->client_x, self->client_y))
    return set_crypto_error (error, "invalid stored private key");

  self->client_key = ec_key_from_params (self->client_d, self->client_x, self->client_y);
  if (!self->client_key)
    return set_crypto_error (error, "private key import");

  g_clear_pointer (&self->priv_blob, g_bytes_unref);
  self->priv_blob = g_bytes_new (body, len);
  return TRUE;
}

static gboolean
handle_ecdh_blob (ValidityTls *self, const guint8 *body, gsize len, GError **error)
{
  g_autoptr(EVP_PKEY) fw_key = NULL;
  EVP_PKEY *key;
  guint8 digest[32];
  guint8 x[EC_COORD_SIZE], y[EC_COORD_SIZE];
  const guint8 *sig;
  guint32 sig_len;

  /* key(0x90) || sig_len(4, LE) || DER signature || zero padding */
  if (len != VALIDITY_TLS_ECDH_BLOB_SIZE)
    {
      g_set_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                   "Unexpected ECDH blob size %" G_GSIZE_FORMAT, len);
      return FALSE;
    }

  sig_len = body[0x90] | (body[0x91] << 8) | (body[0x92] << 16) | ((guint32) body[0x93] << 24);
  sig = body + 0x94;
  if (sig_len == 0 || sig_len > len - 0x94)
    {
      g_set_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                   "Bad ECDH signature length %u", sig_len);
      return FALSE;
    }

  for (gsize i = 0x94 + sig_len; i < len; i++)
    if (body[i] != 0)
      {
        g_set_error_literal (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                             "Garbage after ECDH signature");
        return FALSE;
      }

  fw_key = ec_key_from_params (NULL, fw_pubkey_x, fw_pubkey_y);
  if (!fw_key)
    return set_crypto_error (error, "firmware key import");

  sha256 (body, 0x90, digest);
  if (!ecdsa_verify_digest (fw_key, digest, sig, sig_len))
    {
      g_set_error_literal (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_CRYPTO,
                           "Sensor key is not signed by the firmware key");
      return FALSE;
    }

  reverse_copy (x, body + 0x08, EC_COORD_SIZE);
  reverse_copy (y, body + 0x4c, EC_COORD_SIZE);
  key = ec_key_from_params (NULL, x, y);
  if (!key)
    return set_crypto_error (error, "sensor key import (not on curve)");

  g_clear_pointer (&self->server_ecdh_key, EVP_PKEY_free);
  self->server_ecdh_key = key;
  g_clear_pointer (&self->ecdh_blob, g_bytes_unref);
  self->ecdh_blob = g_bytes_new (body, len);
  return TRUE;
}

static gboolean
load_flash_blocks (ValidityTls *self, const guint8 *data, gsize len, GError **error)
{
  gsize pos = 0;

  while (pos + FLASH_BLOCK_HDR <= len)
    {
      guint16 id = data[pos] | (data[pos + 1] << 8);
      guint16 size = data[pos + 2] | (data[pos + 3] << 8);
      const guint8 *hash = data + pos + 4;
      const guint8 *body = data + pos + FLASH_BLOCK_HDR;
      guint8 digest[32];

      if (id == FLASH_BLOCK_END)
        break;

      if (pos + FLASH_BLOCK_HDR + size > len)
        {
          g_set_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                       "Truncated pairing block 0x%04x", id);
          return FALSE;
        }

      sha256 (body, size, digest);
      if (memcmp (digest, hash, sizeof (digest)) != 0)
        {
          g_set_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                       "Hash mismatch in pairing block 0x%04x", id);
          return FALSE;
        }

      switch (id)
        {
        case FLASH_BLOCK_PRIVKEY:
          if (!handle_priv_blob (self, body, size, error))
            return FALSE;
          break;

        case FLASH_BLOCK_ECDH:
          if (!handle_ecdh_blob (self, body, size, error))
            return FALSE;
          break;

        case FLASH_BLOCK_CERT:
          if (!validity_tls_pairing_set_server_cert (self, body, size, error))
            return FALSE;
          break;

        case FLASH_BLOCK_CA:
          if (size != sizeof (ca_blob) || memcmp (body, ca_blob, size) != 0)
            fp_dbg ("Pairing data holds unexpected curve parameters (ignored)");
          break;

        case FLASH_BLOCK_EMPTY0:
        case FLASH_BLOCK_EMPTY1:
        case FLASH_BLOCK_EMPTY2:
          for (gsize i = 0; i < size; i++)
            if (body[i] != 0)
              {
                g_set_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                             "Pairing block 0x%04x is not empty", id);
                return FALSE;
              }
          break;

        default:
          fp_dbg ("Ignoring pairing block 0x%04x (%u bytes)", id, size);
        }

      pos += FLASH_BLOCK_HDR + size;
    }

  return TRUE;
}

gboolean
validity_tls_load_flash (ValidityTls *self, const guint8 *data, gsize len, GError **error)
{
  clear_pairing (self);

  /* Drop partially loaded pairing data on failure */
  if (!load_flash_blocks (self, data, len, error))
    {
      clear_pairing (self);
      return FALSE;
    }

  return TRUE;
}

gboolean
validity_tls_has_pairing (ValidityTls *self)
{
  return self->client_key && self->server_cert && self->server_ecdh_key && self->priv_blob;
}

static void
append_flash_block (GByteArray *out, guint16 id, const guint8 *body, gsize len)
{
  guint8 hdr[4] = { id & 0xff, id >> 8, len & 0xff, len >> 8 };
  guint8 digest[32];

  sha256 (body, len, digest);
  g_byte_array_append (out, hdr, sizeof (hdr));
  g_byte_array_append (out, digest, sizeof (digest));
  g_byte_array_append (out, body, len);
}

GBytes *
validity_tls_build_flash (ValidityTls *self, GError **error)
{
  g_autoptr(GByteArray) out = g_byte_array_sized_new (VALIDITY_TLS_FLASH_SIZE);
  static const guint8 zeroes[0x100] = { 0 };
  gsize len;
  const guint8 *p;

  if (!validity_tls_has_pairing (self))
    {
      g_set_error_literal (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                           "No pairing data available");
      return NULL;
    }

  /* Same block order as the vendor driver */
  append_flash_block (out, FLASH_BLOCK_EMPTY0, zeroes, 1);
  p = g_bytes_get_data (self->priv_blob, &len);
  append_flash_block (out, FLASH_BLOCK_PRIVKEY, p, len);
  p = g_bytes_get_data (self->server_cert, &len);
  append_flash_block (out, FLASH_BLOCK_CERT, p, len);
  append_flash_block (out, FLASH_BLOCK_CA, ca_blob, sizeof (ca_blob));
  append_flash_block (out, FLASH_BLOCK_EMPTY1, zeroes, sizeof (zeroes));
  append_flash_block (out, FLASH_BLOCK_EMPTY2, zeroes, sizeof (zeroes));
  p = g_bytes_get_data (self->ecdh_blob, &len);
  append_flash_block (out, FLASH_BLOCK_ECDH, p, len);

  if (out->len > VALIDITY_TLS_FLASH_SIZE)
    {
      g_set_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                   "Pairing data too large (%u bytes)", out->len);
      return NULL;
    }

  while (out->len < VALIDITY_TLS_FLASH_SIZE)
    g_byte_array_append (out, (const guint8 *) "\xff", 1);

  return g_byte_array_free_to_bytes (g_steal_pointer (&out));
}

/* ---------------------------------------------------------------------- */
/* New pairing                                                            */
/* ---------------------------------------------------------------------- */

gboolean
validity_tls_pairing_begin (ValidityTls *self, GError **error)
{
  clear_pairing (self);
  validity_tls_reset_session (self);

  self->client_key = ec_generate (self, self->client_d, self->client_x, self->client_y);
  if (!self->client_key)
    return set_crypto_error (error, "host key generation");

  return TRUE;
}

GBytes *
validity_tls_pairing_get_client_cert (ValidityTls *self, GError **error)
{
  g_autoptr(EVP_PKEY) hs_key = NULL;
  g_autoptr(GBytes) sig = NULL;
  guint8 cert[VALIDITY_TLS_PAIRING_CERT_LEN] = { 0 };
  guint8 digest[32];
  const guint8 *sig_data;
  gsize sig_len;
  const gsize body_len = 8 + EC_COORD_SIZE + 0x24 + EC_COORD_SIZE + 0x4c;

  if (!self->client_key)
    {
      g_set_error_literal (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                           "No host key; pairing was not started");
      return NULL;
    }

  /* LE32(0x17) || LE32(0x20) || X(LE) || 0x24 zeroes || Y(LE) || 0x4c zeroes */
  cert[0] = 0x17;
  cert[4] = 0x20;
  reverse_copy (cert + 8, self->client_x, EC_COORD_SIZE);
  reverse_copy (cert + 8 + EC_COORD_SIZE + 0x24, self->client_y, EC_COORD_SIZE);

  hs_key = hs_key_new ();
  if (!hs_key)
    {
      set_crypto_error (error, "certificate signing key derivation");
      return NULL;
    }

  sha256 (cert, body_len, digest);
  sig = ecdsa_sign_digest (hs_key, digest);
  if (!sig)
    {
      set_crypto_error (error, "certificate signing");
      return NULL;
    }

  sig_data = g_bytes_get_data (sig, &sig_len);
  if (body_len + 4 + sig_len > sizeof (cert))
    {
      set_crypto_error (error, "certificate signature too long");
      return NULL;
    }

  cert[body_len + 0] = sig_len & 0xff;
  cert[body_len + 1] = (sig_len >> 8) & 0xff;
  memcpy (cert + body_len + 4, sig_data, sig_len);

  return g_bytes_new (cert, sizeof (cert));
}

gboolean
validity_tls_pairing_set_server_cert (ValidityTls *self, const guint8 *cert, gsize len,
                                      GError **error)
{
  /* It has to fit into the pairing data and a 16-bit length field */
  if (len == 0 || len > VALIDITY_TLS_MAX_CERT_LEN)
    {
      g_set_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                   "Unexpected sensor certificate size %" G_GSIZE_FORMAT, len);
      return FALSE;
    }

  g_clear_pointer (&self->server_cert, g_bytes_unref);
  self->server_cert = g_bytes_new (cert, len);
  return TRUE;
}

gboolean
validity_tls_pairing_set_server_ecdh (ValidityTls *self, const guint8 *blob, gsize len, GError **error)
{
  return handle_ecdh_blob (self, blob, len, error);
}

gboolean
validity_tls_pairing_finish (ValidityTls *self, GError **error)
{
  guint8 plain[3 * EC_COORD_SIZE + AES_BLOCK];
  guint8 blob[1 + AES_BLOCK + sizeof (plain) + MAC_SIZE];
  const gsize pad = AES_BLOCK - (3 * EC_COORD_SIZE) % AES_BLOCK;

  if (!self->client_key)
    {
      g_set_error_literal (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                           "No host key; pairing was not started");
      return FALSE;
    }

  /* x || y || d (little endian) with PKCS#7 padding */
  reverse_copy (plain, self->client_x, EC_COORD_SIZE);
  reverse_copy (plain + EC_COORD_SIZE, self->client_y, EC_COORD_SIZE);
  reverse_copy (plain + 2 * EC_COORD_SIZE, self->client_d, EC_COORD_SIZE);
  memset (plain + 3 * EC_COORD_SIZE, pad, pad);

  blob[0] = PRIVKEY_BLOB_PREFIX;
  get_random (self, blob + 1, AES_BLOCK);
  if (!aes256_cbc (TRUE, self->psk_encryption_key, blob + 1, plain, sizeof (plain),
                   blob + 1 + AES_BLOCK))
    {
      OPENSSL_cleanse (plain, sizeof (plain));
      return set_crypto_error (error, "private key encryption");
    }
  OPENSSL_cleanse (plain, sizeof (plain));

  hmac_sha256 (self->psk_validation_key, KEY_SIZE, blob + 1, AES_BLOCK + sizeof (plain),
               NULL, 0, blob + 1 + AES_BLOCK + sizeof (plain));

  g_clear_pointer (&self->priv_blob, g_bytes_unref);
  self->priv_blob = g_bytes_new (blob, sizeof (blob));

  if (!validity_tls_has_pairing (self))
    {
      g_set_error_literal (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                           "Incomplete pairing data");
      return FALSE;
    }

  return TRUE;
}

/* ---------------------------------------------------------------------- */
/* Records                                                                */
/* ---------------------------------------------------------------------- */

void
validity_tls_reset_session (ValidityTls *self)
{
  g_clear_pointer (&self->handshake_hash, EVP_MD_CTX_free);
  OPENSSL_cleanse (self->master_secret, sizeof (self->master_secret));
  OPENSSL_cleanse (self->sign_key, sizeof (self->sign_key));
  OPENSSL_cleanse (self->validation_key, sizeof (self->validation_key));
  OPENSSL_cleanse (self->encryption_key, sizeof (self->encryption_key));
  OPENSSL_cleanse (self->decryption_key, sizeof (self->decryption_key));
  self->keys_ready = FALSE;
  self->secure_rx = FALSE;
  self->secure_tx = FALSE;
}

gboolean
validity_tls_is_established (ValidityTls *self)
{
  return self->secure_rx && self->secure_tx;
}

static void
hash_update (ValidityTls *self, const guint8 *data, gsize len)
{
  if (EVP_DigestUpdate (self->handshake_hash, data, len) != 1)
    g_error ("validity: SHA-256 update failed");
}

static void
hash_peek (ValidityTls *self, guint8 out[32])
{
  EVP_MD_CTX *copy = EVP_MD_CTX_new ();
  unsigned int len = 32;

  if (!copy || EVP_MD_CTX_copy_ex (copy, self->handshake_hash) != 1 ||
      EVP_DigestFinal_ex (copy, out, &len) != 1)
    g_error ("validity: SHA-256 finalization failed");

  EVP_MD_CTX_free (copy);
}

static void
record_header (guint8 hdr[5], guint8 type, gsize len)
{
  hdr[0] = type;
  hdr[1] = 0x03;
  hdr[2] = 0x03;
  hdr[3] = (len >> 8) & 0xff;
  hdr[4] = len & 0xff;
}

/* MAC-then-encrypt: iv || AES-CBC(data || HMAC(hdr || data) || padding) */
static GBytes *
protect (ValidityTls *self, guint8 type, const guint8 *data, gsize len, GError **error)
{
  guint8 hdr[5];
  gsize plain_len = len + MAC_SIZE;
  gsize pad = AES_BLOCK - plain_len % AES_BLOCK;
  g_autofree guint8 *plain = g_malloc (plain_len + pad);
  guint8 *out = g_malloc (AES_BLOCK + plain_len + pad);

  record_header (hdr, type, len);
  memcpy (plain, data, len);
  hmac_sha256 (self->sign_key, KEY_SIZE, hdr, sizeof (hdr), data, len, plain + len);
  /* TLS-style padding: every padding byte holds (pad length - 1) */
  memset (plain + plain_len, pad - 1, pad);

  get_random (self, out, AES_BLOCK);
  if (!aes256_cbc (TRUE, self->encryption_key, out, plain, plain_len + pad, out + AES_BLOCK))
    {
      OPENSSL_cleanse (plain, plain_len + pad);
      g_free (out);
      set_crypto_error (error, "record encryption");
      return NULL;
    }

  OPENSSL_cleanse (plain, plain_len + pad);
  return g_bytes_new_take (out, AES_BLOCK + plain_len + pad);
}

static GBytes *
unprotect (ValidityTls *self, guint8 type, const guint8 *data, gsize len, GError **error)
{
  g_autofree guint8 *plain = NULL;
  gsize plain_len, content_len;
  guint8 hdr[5];
  guint8 mac[MAC_SIZE];
  guint8 pad;

  if (len < AES_BLOCK + AES_BLOCK || len % AES_BLOCK != 0)
    {
      g_set_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                   "Bad encrypted record length %" G_GSIZE_FORMAT, len);
      return NULL;
    }

  plain_len = len - AES_BLOCK;
  plain = g_malloc (plain_len);
  if (!aes256_cbc (FALSE, self->decryption_key, data, data + AES_BLOCK, plain_len, plain))
    {
      OPENSSL_cleanse (plain, plain_len);
      set_crypto_error (error, "record decryption");
      return NULL;
    }

  pad = plain[plain_len - 1];
  if ((gsize) pad + 1 + MAC_SIZE > plain_len)
    {
      OPENSSL_cleanse (plain, plain_len);
      g_set_error_literal (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                           "Bad record padding");
      return NULL;
    }

  content_len = plain_len - pad - 1 - MAC_SIZE;
  record_header (hdr, type, content_len);
  hmac_sha256 (self->validation_key, KEY_SIZE, hdr, sizeof (hdr), plain, content_len, mac);
  if (CRYPTO_memcmp (mac, plain + content_len, MAC_SIZE) != 0)
    {
      OPENSSL_cleanse (plain, plain_len);
      g_set_error_literal (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_CRYPTO,
                           "Record MAC verification failed");
      return NULL;
    }

  {
    GBytes *res = g_bytes_new (plain, content_len);

    OPENSSL_cleanse (plain, plain_len);
    return res;
  }
}

static gboolean
append_record (ValidityTls *self, GByteArray *out, guint8 type,
               const guint8 *data, gsize len, GError **error)
{
  g_autoptr(GBytes) protected = NULL;
  guint8 hdr[5];

  if (self->secure_tx)
    {
      protected = protect (self, type, data, len, error);
      if (!protected)
        return FALSE;
      data = g_bytes_get_data (protected, &len);
    }

  if (len > G_MAXUINT16)
    {
      g_set_error_literal (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                           "Record too large");
      return FALSE;
    }

  record_header (hdr, type, len);
  g_byte_array_append (out, hdr, sizeof (hdr));
  g_byte_array_append (out, data, len);
  return TRUE;
}

/* Appends a handshake message (type || 24-bit length || body). */
static void
append_handshake_msg (ValidityTls *self, GByteArray *out, guint8 type,
                      const guint8 *body, gsize len, gboolean hash)
{
  guint8 hdr[4] = { type, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff };
  guint start = out->len;

  g_byte_array_append (out, hdr, sizeof (hdr));
  g_byte_array_append (out, body, len);
  if (hash)
    hash_update (self, out->data + start, out->len - start);
}

/* ---------------------------------------------------------------------- */
/* Response parsing                                                       */
/* ---------------------------------------------------------------------- */

typedef struct
{
  gboolean server_hello;
  gboolean cert_request;
  gboolean hello_done;
  gboolean finished;
} HandshakeSeen;

static gboolean
handle_server_hello_msg (ValidityTls *self, const guint8 *p, gsize len, GError **error)
{
  gsize sessid_len;
  guint16 suite;

  /* version(2) random(32) sessid_len(1) sessid suite(2) compression(1) */
  if (len < 2 + RANDOM_SIZE + 1)
    goto bad;

  if (p[0] != 0x03 || p[1] != 0x03)
    {
      g_set_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                   "Unexpected TLS version %02x%02x", p[0], p[1]);
      return FALSE;
    }

  memcpy (self->server_random, p + 2, RANDOM_SIZE);
  sessid_len = p[2 + RANDOM_SIZE];
  if (len != 2 + RANDOM_SIZE + 1 + sessid_len + 2 + 1)
    goto bad;

  p += 2 + RANDOM_SIZE + 1 + sessid_len;
  suite = (p[0] << 8) | p[1];
  if (suite != CIPHER_SUITE_ECDH_ECDSA_AES256_CBC_SHA)
    {
      g_set_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                   "Sensor selected unsupported cipher suite 0x%04x", suite);
      return FALSE;
    }

  if (p[2] != 0)
    {
      g_set_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                   "Sensor selected unsupported compression 0x%02x", p[2]);
      return FALSE;
    }

  return TRUE;

bad:
  g_set_error_literal (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                       "Malformed ServerHello");
  return FALSE;
}

static gboolean
handle_handshake_msgs (ValidityTls *self, const guint8 *data, gsize len,
                       HandshakeSeen *seen, GError **error)
{
  gsize pos = 0;

  while (pos < len)
    {
      guint8 type;
      gsize body_len;
      const guint8 *body;

      if (len - pos < 4)
        {
          g_set_error_literal (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                               "Truncated handshake message header");
          return FALSE;
        }

      type = data[pos];
      body_len = (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3];
      body = data + pos + 4;
      if (body_len > len - pos - 4)
        {
          g_set_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                       "Truncated handshake message 0x%02x", type);
          return FALSE;
        }

      switch (type)
        {
        case HS_SERVER_HELLO:
          if (!handle_server_hello_msg (self, body, body_len, error))
            return FALSE;
          seen->server_hello = TRUE;
          break;

        case HS_CERTIFICATE_REQUEST:
          /* certificate type list { ecdsa_sign }, empty algorithm and CA lists */
          if (body_len != 4 || body[0] != 0x01 || body[1] != 0x40 || body[2] != 0 || body[3] != 0)
            {
              g_set_error_literal (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                                   "Unsupported CertificateRequest");
              return FALSE;
            }
          seen->cert_request = TRUE;
          break;

        case HS_SERVER_HELLO_DONE:
          if (body_len != 0)
            {
              g_set_error_literal (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                                   "Non-empty ServerHelloDone");
              return FALSE;
            }
          seen->hello_done = TRUE;
          break;

        case HS_FINISHED:
          {
            guint8 hs_hash[32];
            guint8 expected[VERIFY_DATA_SIZE];

            if (!self->keys_ready)
              {
                g_set_error_literal (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                                     "Finished before key exchange");
                return FALSE;
              }

            hash_peek (self, hs_hash);
            prf_label (self->master_secret, MASTER_SIZE, "server finished",
                       hs_hash, sizeof (hs_hash), expected, sizeof (expected));
            if (body_len != VERIFY_DATA_SIZE ||
                CRYPTO_memcmp (expected, body, VERIFY_DATA_SIZE) != 0)
              {
                g_set_error_literal (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_CRYPTO,
                                     "Server Finished verification failed");
                return FALSE;
              }
            seen->finished = TRUE;
          }
          break;

        default:
          g_set_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                       "Unknown handshake message 0x%02x", type);
          return FALSE;
        }

      hash_update (self, data + pos, 4 + body_len);
      pos += 4 + body_len;
    }

  return TRUE;
}

/* Parses all records of a response.  Application data is appended to @app
 * (may be NULL if none is expected). */
static gboolean
parse_records (ValidityTls *self, const guint8 *rsp, gsize len,
               HandshakeSeen *seen, GByteArray *app, GError **error)
{
  gsize pos = 0;

  /* Without TLS framing the sensor replies with a bare 16-bit status */
  if (len == 2)
    {
      g_set_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                   "Sensor rejected the request with status 0x%04x",
                   rsp[0] | (rsp[1] << 8));
      return FALSE;
    }

  while (pos < len)
    {
      guint8 type;
      gsize rec_len;
      const guint8 *rec;

      if (len - pos < 5)
        {
          g_set_error_literal (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                               "Truncated record header");
          return FALSE;
        }

      type = rsp[pos];
      rec_len = (rsp[pos + 3] << 8) | rsp[pos + 4];
      rec = rsp + pos + 5;

      if (rsp[pos + 1] != 0x03 || rsp[pos + 2] != 0x03)
        {
          g_set_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                       "Unexpected record version %02x%02x", rsp[pos + 1], rsp[pos + 2]);
          return FALSE;
        }

      if (rec_len > len - pos - 5)
        {
          g_set_error_literal (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                               "Truncated record");
          return FALSE;
        }

      switch (type)
        {
        case TLS_CONTENT_HANDSHAKE:
          if (!seen)
            goto unexpected;

          if (self->secure_rx)
            {
              g_autoptr(GBytes) plain = unprotect (self, type, rec, rec_len, error);
              gsize plain_len;
              const guint8 *p;

              if (!plain)
                return FALSE;
              p = g_bytes_get_data (plain, &plain_len);
              if (!handle_handshake_msgs (self, p, plain_len, seen, error))
                return FALSE;
            }
          else if (!handle_handshake_msgs (self, rec, rec_len, seen, error))
            {
              return FALSE;
            }
          break;

        case TLS_CONTENT_CCS:
          if (!seen || rec_len != 1 || rec[0] != 0x01 || !self->keys_ready)
            goto unexpected;
          self->secure_rx = TRUE;
          break;

        case TLS_CONTENT_APP_DATA:
          {
            g_autoptr(GBytes) plain = NULL;

            if (!self->secure_rx || !app)
              goto unexpected;

            plain = unprotect (self, type, rec, rec_len, error);
            if (!plain)
              return FALSE;
            g_byte_array_append (app, g_bytes_get_data (plain, NULL), g_bytes_get_size (plain));
          }
          break;

        case TLS_CONTENT_ALERT:
          g_set_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                       "Sensor sent TLS alert (%" G_GSIZE_FORMAT " bytes, level %d, code %d)",
                       rec_len, rec_len > 0 ? rec[0] : -1, rec_len > 1 ? rec[1] : -1);
          return FALSE;

        default:
          goto unexpected;
        }

      pos += 5 + rec_len;
      continue;

unexpected:
      g_set_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                   "Unexpected record type 0x%02x", type);
      return FALSE;
    }

  return TRUE;
}

/* ---------------------------------------------------------------------- */
/* Handshake                                                              */
/* ---------------------------------------------------------------------- */

GBytes *
validity_tls_build_client_hello (ValidityTls *self, GError **error)
{
  g_autoptr(GByteArray) body = g_byte_array_new ();
  g_autoptr(GByteArray) msg = g_byte_array_new ();
  g_autoptr(GByteArray) out = g_byte_array_new ();
  static const guint8 version[] = { 0x03, 0x03 };
  /* 7 byte all-zero session id */
  static const guint8 session_id[] = { 0x07, 0, 0, 0, 0, 0, 0, 0 };
  static const guint8 suites[] = {
    0x00, 0x06,
    0xc0, 0x05, /* TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA */
    0x00, 0x3d, /* TLS_RSA_WITH_AES_256_CBC_SHA256 */
    0x00, 0x8d, /* TLS_PSK_WITH_AES_256_CBC_SHA */
  };
  static const guint8 compression[] = { 0x00 };
  /* The extension block length is two bytes short of the real length.
   * The sensor expects exactly this (vendor driver quirk). */
  static const guint8 extensions[] = {
    0x00, 0x0a,
    0x00, 0x04, 0x00, 0x02, 0x00, 0x17,       /* truncated_hmac, 0x17 */
    0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,       /* ec_point_formats: uncompressed */
  };

  if (!validity_tls_has_pairing (self))
    {
      g_set_error_literal (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                           "No pairing data available");
      return NULL;
    }

  validity_tls_reset_session (self);
  self->handshake_hash = EVP_MD_CTX_new ();
  if (!self->handshake_hash || EVP_DigestInit_ex (self->handshake_hash, EVP_sha256 (), NULL) != 1)
    {
      set_crypto_error (error, "handshake hash");
      return NULL;
    }

  get_random (self, self->client_random, RANDOM_SIZE);

  g_byte_array_append (body, version, sizeof (version));
  g_byte_array_append (body, self->client_random, RANDOM_SIZE);
  g_byte_array_append (body, session_id, sizeof (session_id));
  g_byte_array_append (body, suites, sizeof (suites));
  g_byte_array_append (body, compression, sizeof (compression));
  g_byte_array_append (body, extensions, sizeof (extensions));

  append_handshake_msg (self, msg, HS_CLIENT_HELLO, body->data, body->len, TRUE);

  g_byte_array_append (out, handshake_cmd_prefix, sizeof (handshake_cmd_prefix));
  if (!append_record (self, out, TLS_CONTENT_HANDSHAKE, msg->data, msg->len, error))
    return NULL;

  return g_byte_array_free_to_bytes (g_steal_pointer (&out));
}

static gboolean
make_session_keys (ValidityTls *self, GError **error)
{
  g_autoptr(EVP_PKEY) session_key = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  guint8 session_d[EC_COORD_SIZE];
  guint8 pre_master[EC_COORD_SIZE];
  guint8 seed[2 * RANDOM_SIZE];
  guint8 key_block[KEY_BLOCK_SIZE];
  size_t pre_master_len = sizeof (pre_master);
  gboolean ok;

  /* Ephemeral client key; the server key is the static key from pairing */
  session_key = ec_generate (self, session_d, self->session_x, self->session_y);
  OPENSSL_cleanse (session_d, sizeof (session_d));
  if (!session_key)
    return set_crypto_error (error, "session key generation");

  ctx = EVP_PKEY_CTX_new_from_pkey (NULL, session_key, NULL);
  ok = ctx && EVP_PKEY_derive_init (ctx) == 1 &&
       EVP_PKEY_derive_set_peer (ctx, self->server_ecdh_key) == 1 &&
       EVP_PKEY_derive (ctx, pre_master, &pre_master_len) == 1 &&
       pre_master_len == sizeof (pre_master);
  EVP_PKEY_CTX_free (ctx);
  if (!ok)
    return set_crypto_error (error, "ECDH");

  memcpy (seed, self->client_random, RANDOM_SIZE);
  memcpy (seed + RANDOM_SIZE, self->server_random, RANDOM_SIZE);

  prf_label (pre_master, sizeof (pre_master), "master secret", seed, sizeof (seed),
             self->master_secret, MASTER_SIZE);
  prf_label (self->master_secret, MASTER_SIZE, "key expansion", seed, sizeof (seed),
             key_block, sizeof (key_block));

  memcpy (self->sign_key, key_block + 0x00, KEY_SIZE);
  memcpy (self->validation_key, key_block + 0x20, KEY_SIZE);
  memcpy (self->encryption_key, key_block + 0x40, KEY_SIZE);
  memcpy (self->decryption_key, key_block + 0x60, KEY_SIZE);

  OPENSSL_cleanse (pre_master, sizeof (pre_master));
  OPENSSL_cleanse (key_block, sizeof (key_block));

  self->keys_ready = TRUE;
  return TRUE;
}

gboolean
validity_tls_handle_server_hello (ValidityTls *self, const guint8 *rsp, gsize len, GError **error)
{
  HandshakeSeen seen = { 0 };

  if (!self->handshake_hash || self->keys_ready)
    {
      g_set_error_literal (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                           "Unexpected server hello");
      return FALSE;
    }

  if (!parse_records (self, rsp, len, &seen, NULL, error))
    return FALSE;

  if (!seen.server_hello || !seen.cert_request || !seen.hello_done || seen.finished)
    {
      g_set_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                   "Incomplete server hello flight (hello %d, cert request %d, done %d)",
                   seen.server_hello, seen.cert_request, seen.hello_done);
      return FALSE;
    }

  return make_session_keys (self, error);
}

GBytes *
validity_tls_build_client_finish (ValidityTls *self, GError **error)
{
  g_autoptr(GByteArray) flight = g_byte_array_new ();
  g_autoptr(GByteArray) body = g_byte_array_new ();
  g_autoptr(GByteArray) finished = g_byte_array_new ();
  g_autoptr(GByteArray) out = g_byte_array_new ();
  g_autoptr(GBytes) sig = NULL;
  static const guint8 ccs[] = { 0x01 };
  guint8 hs_hash[32];
  guint8 verify_data[VERIFY_DATA_SIZE];
  const guint8 *cert;
  gsize cert_len;
  guint8 hdr[3];

  if (!self->keys_ready || self->secure_tx)
    {
      g_set_error_literal (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                           "Handshake is not awaiting the client finish");
      return NULL;
    }

  /* Certificate. Both 24-bit length fields hold the bare certificate length. */
  cert = g_bytes_get_data (self->server_cert, &cert_len);
  hdr[0] = 0;
  hdr[1] = (cert_len >> 8) & 0xff;
  hdr[2] = cert_len & 0xff;
  g_byte_array_append (body, hdr, sizeof (hdr));
  g_byte_array_append (body, hdr, sizeof (hdr));
  /* Sensor quirk, not standard TLS */
  g_byte_array_append (body, (const guint8 *) "\xac\x16", 2);
  g_byte_array_append (body, cert, cert_len);
  append_handshake_msg (self, flight, HS_CERTIFICATE, body->data, body->len, TRUE);

  /* ClientKeyExchange: uncompressed point, no length prefix */
  g_byte_array_set_size (body, 0);
  g_byte_array_append (body, (const guint8 *) "\x04", 1);
  g_byte_array_append (body, self->session_x, EC_COORD_SIZE);
  g_byte_array_append (body, self->session_y, EC_COORD_SIZE);
  append_handshake_msg (self, flight, HS_CLIENT_KEY_EXCHANGE, body->data, body->len, TRUE);

  /* CertificateVerify: bare DER ECDSA signature over the transcript hash */
  hash_peek (self, hs_hash);
  sig = ecdsa_sign_digest (self->client_key, hs_hash);
  if (!sig)
    {
      set_crypto_error (error, "CertificateVerify signature");
      return NULL;
    }
  append_handshake_msg (self, flight, HS_CERTIFICATE_VERIFY,
                        g_bytes_get_data (sig, NULL), g_bytes_get_size (sig), TRUE);

  g_byte_array_append (out, handshake_cmd_prefix, sizeof (handshake_cmd_prefix));
  if (!append_record (self, out, TLS_CONTENT_HANDSHAKE, flight->data, flight->len, error) ||
      !append_record (self, out, TLS_CONTENT_CCS, ccs, sizeof (ccs), error))
    return NULL;

  /* Finished: the sensor does not include the client Finished message in
   * the transcript it uses for its own Finished, so don't hash it. */
  self->secure_tx = TRUE;
  hash_peek (self, hs_hash);
  prf_label (self->master_secret, MASTER_SIZE, "client finished",
             hs_hash, sizeof (hs_hash), verify_data, sizeof (verify_data));
  append_handshake_msg (self, finished, HS_FINISHED, verify_data, sizeof (verify_data), FALSE);

  if (!append_record (self, out, TLS_CONTENT_HANDSHAKE, finished->data, finished->len, error))
    return NULL;

  return g_byte_array_free_to_bytes (g_steal_pointer (&out));
}

gboolean
validity_tls_handle_server_finish (ValidityTls *self, const guint8 *rsp, gsize len, GError **error)
{
  HandshakeSeen seen = { 0 };

  if (!self->secure_tx || self->secure_rx)
    {
      g_set_error_literal (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                           "Handshake is not awaiting the server finish");
      return FALSE;
    }

  if (!parse_records (self, rsp, len, &seen, NULL, error))
    return FALSE;

  if (!self->secure_rx || !seen.finished || seen.server_hello)
    {
      g_set_error_literal (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                           "Incomplete server finished flight");
      return FALSE;
    }

  return TRUE;
}

/* ---------------------------------------------------------------------- */
/* Application data                                                       */
/* ---------------------------------------------------------------------- */

GBytes *
validity_tls_wrap (ValidityTls *self, const guint8 *data, gsize len, GError **error)
{
  g_autoptr(GByteArray) out = g_byte_array_new ();

  if (!validity_tls_is_established (self))
    {
      g_set_error_literal (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                           "Secure channel not established");
      return NULL;
    }

  if (!append_record (self, out, TLS_CONTENT_APP_DATA, data, len, error))
    return NULL;

  return g_byte_array_free_to_bytes (g_steal_pointer (&out));
}

GBytes *
validity_tls_unwrap (ValidityTls *self, const guint8 *rsp, gsize len, GError **error)
{
  g_autoptr(GByteArray) app = g_byte_array_new ();

  if (!validity_tls_is_established (self))
    {
      g_set_error_literal (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO,
                           "Secure channel not established");
      return NULL;
    }

  if (!parse_records (self, rsp, len, NULL, app, error))
    return NULL;

  return g_byte_array_free_to_bytes (g_steal_pointer (&app));
}
