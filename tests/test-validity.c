/*
 * Unit tests for the validity driver's protocol and secure channel code
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

#include <glib.h>
#include <string.h>

#include "fpi-device.h"
#include "drivers/validity/validity-proto.h"
#include "drivers/validity/validity-tls.h"

static GKeyFile *vectors;

static GBytes *
vec (const gchar *group, const gchar *key)
{
  g_autofree gchar *hex = NULL;

  g_autoptr(GError) error = NULL;
  gsize len;
  guint8 *data;

  hex = g_key_file_get_string (vectors, group, key, &error);
  g_assert_no_error (error);

  len = strlen (hex);
  g_assert_cmpuint (len % 2, ==, 0);
  data = g_malloc (len / 2 + 1);
  for (gsize i = 0; i < len / 2; i++)
    {
      gint hi = g_ascii_xdigit_value (hex[2 * i]);
      gint lo = g_ascii_xdigit_value (hex[2 * i + 1]);

      g_assert_cmpint (hi, >=, 0);
      g_assert_cmpint (lo, >=, 0);
      data[i] = (hi << 4) | lo;
    }

  return g_bytes_new_take (data, len / 2);
}

static void
assert_bytes_equal (GBytes *actual, GBytes *expected)
{
  gsize a_len, e_len;
  const guint8 *a = g_bytes_get_data (actual, &a_len);
  const guint8 *e = g_bytes_get_data (expected, &e_len);

  g_assert_cmpmem (a, a_len, e, e_len);
}

/* Sets up the sensor state the same way the driver does when opening. */
static void
sensor_setup (ValiditySensor *sensor, ValidityRomInfo *rom)
{
  g_autoptr(GBytes) rom_rsp = vec ("sensor", "rom_info");
  g_autoptr(GBytes) bits_rsp = vec ("sensor", "factory_bits_rsp");
  g_autoptr(GBytes) entry = NULL;
  g_autoptr(GBytes) values = NULL;
  g_autoptr(GBytes) expected_values = vec ("sensor", "factory_calibration_values");
  g_autoptr(GError) error = NULL;
  const ValiditySensorProfile *profile;

  g_assert_true (validity_parse_rom_info (g_bytes_get_data (rom_rsp, NULL),
                                          g_bytes_get_size (rom_rsp), rom, &error));
  g_assert_no_error (error);
  g_assert_cmpuint (rom->major, ==, 6);
  g_assert_cmpuint (rom->minor, ==, 7);
  g_assert_cmpuint (rom->product, ==, 0x30);
  g_assert_cmpuint (rom->flags, ==, 0x23);

  profile = validity_sensor_profile_lookup (0x0190, 0x0061, rom);
  g_assert_nonnull (profile);
  g_assert_cmpuint (profile->sensor_type, ==, 0x199);

  entry = validity_parse_factory_bits (g_bytes_get_data (bits_rsp, NULL),
                                       g_bytes_get_size (bits_rsp), 3, &error);
  g_assert_no_error (error);
  values = g_bytes_new_from_bytes (entry, 4, g_bytes_get_size (entry) - 4);
  assert_bytes_equal (values, expected_values);

  g_assert_true (validity_sensor_init (sensor, profile, values, &error));
  g_assert_no_error (error);
  g_assert_cmpuint (sensor->lines_per_frame, ==, 224);
}

static void
check_capture_cmd (ValiditySensor *sensor, ValidityCaptureMode mode, const gchar *key)
{
  g_autoptr(GBytes) expected = vec ("sensor", key);
  g_autoptr(GBytes) cmd = NULL;
  g_autoptr(GError) error = NULL;

  cmd = validity_build_capture_cmd (sensor, mode, &error);
  g_assert_no_error (error);
  assert_bytes_equal (cmd, expected);
}

static void
test_capture_program_uncalibrated (void)
{
  ValiditySensor sensor = { 0 };
  ValidityRomInfo rom;

  sensor_setup (&sensor, &rom);
  check_capture_cmd (&sensor, VALIDITY_CAPTURE_CALIBRATE, "cmd02_CALIBRATE_nocalib");
  validity_sensor_clear (&sensor);
}

static void
test_calibration_and_programs (void)
{
  ValiditySensor sensor = { 0 };
  ValidityRomInfo rom;

  g_autoptr(GError) error = NULL;

  sensor_setup (&sensor, &rom);

  for (guint i = 0; i < 3; i++)
    {
      g_autofree gchar *frame_key = g_strdup_printf ("calib_frame%u", i);
      g_autofree gchar *data_key = g_strdup_printf ("calib_data%u", i);
      g_autoptr(GBytes) frame = vec ("sensor", frame_key);
      g_autoptr(GBytes) expected = vec ("sensor", data_key);

      g_assert_cmpuint (g_bytes_get_size (frame), ==, validity_calibration_frame_bytes (&sensor));
      g_assert_true (validity_calibration_process (&sensor, g_bytes_get_data (frame, NULL),
                                                   g_bytes_get_size (frame), &error));
      g_assert_no_error (error);
      assert_bytes_equal (sensor.calib_data, expected);
    }

  {
    g_autoptr(GBytes) frame = vec ("sensor", "calib_frame3");
    g_autoptr(GBytes) expected = vec ("sensor", "clean_slate");
    g_autoptr(GBytes) clean_slate = NULL;
    guint16 payload_len;
    const guint8 *cs;

    clean_slate = validity_calibration_build_clean_slate (&sensor, g_bytes_get_data (frame, NULL),
                                                          g_bytes_get_size (frame), &error);
    g_assert_no_error (error);
    assert_bytes_equal (clean_slate, expected);

    cs = g_bytes_get_data (clean_slate, NULL);
    g_assert_true (validity_clean_slate_header_valid (cs, VALIDITY_CLEAN_SLATE_HDR_SIZE,
                                                      &payload_len));
    g_assert_cmpuint (payload_len, ==, validity_clean_slate_payload_size (&sensor));
    g_assert_cmpuint (payload_len + VALIDITY_CLEAN_SLATE_HDR_SIZE, ==,
                      g_bytes_get_size (clean_slate));
    g_assert_true (validity_clean_slate_payload_valid (cs, cs + VALIDITY_CLEAN_SLATE_HDR_SIZE,
                                                       payload_len));
  }

  check_capture_cmd (&sensor, VALIDITY_CAPTURE_CALIBRATE, "cmd02_CALIBRATE");
  check_capture_cmd (&sensor, VALIDITY_CAPTURE_IDENTIFY, "cmd02_IDENTIFY");
  check_capture_cmd (&sensor, VALIDITY_CAPTURE_ENROLL, "cmd02_ENROLL");

  validity_sensor_clear (&sensor);
}

/* The sensor sometimes ends the calibration stream early; only the second
 * frame is used, so truncated data must give the same result. */
static void
test_calibration_short_data (void)
{
  ValiditySensor full = { 0 }, part = { 0 };
  ValidityRomInfo rom;

  g_autoptr(GBytes) frame = vec ("sensor", "calib_frame0");
  g_autoptr(GError) error = NULL;
  const gsize short_len = 70680;   /* observed on hardware */
  const gsize frame_size = 224 * 120;

  sensor_setup (&full, &rom);
  sensor_setup (&part, &rom);

  g_assert_true (validity_calibration_process (&full, g_bytes_get_data (frame, NULL),
                                               g_bytes_get_size (frame), &error));
  g_assert_no_error (error);
  g_assert_true (validity_calibration_process (&part, g_bytes_get_data (frame, NULL),
                                               short_len, &error));
  g_assert_no_error (error);
  assert_bytes_equal (part.calib_data, full.calib_data);

  /* Less than two frames is an error */
  g_assert_false (validity_calibration_process (&part, g_bytes_get_data (frame, NULL),
                                                2 * frame_size - 1, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);

  validity_sensor_clear (&full);
  validity_sensor_clear (&part);
}

static void
test_parse_image (void)
{
  g_autofree guint8 *rsp = g_malloc0 (6 + 12 + 112 * 112);

  g_autoptr(GError) error = NULL;
  ValidityImage image;

  rsp[2] = (12 + 112 * 112) & 0xff;
  rsp[3] = (12 + 112 * 112) >> 8;
  rsp[6] = 112;
  rsp[8] = 112;
  rsp[10] = 0x4d;
  rsp[11] = 0x01;
  rsp[12] = 8;
  rsp[6 + 12] = 0xab;

  g_assert_true (validity_parse_image (rsp, 6 + 12 + 112 * 112, &image, &error));
  g_assert_no_error (error);
  g_assert_cmpuint (image.width, ==, 112);
  g_assert_cmpuint (image.height, ==, 112);
  g_assert_cmpuint (image.pixels[0], ==, 0xab);
  g_free (image.pixels);

  /* Truncated reply */
  g_assert_false (validity_parse_image (rsp, 6 + 12 + 100, &image, &error));
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
}

static void
test_image_prepare (void)
{
  static const guint8 src[] = { 0, 100, 200, 50 };
  /* Computed independently: bilinear 2x upscale, 1 pixel edge replication */
  static const guint8 expected[] = {
    0,   0,   25,  75, 100, 100,
    0,   0,   25,  75, 100, 100,
    50,  50,  59,  78,  88,  88,
    150, 150, 128, 84,  63,  63,
    200, 200, 163, 88,  50,  50,
    200, 200, 163, 88,  50,  50,
  };
  g_autofree guint8 *out = NULL;
  guint w, h;

  out = validity_image_prepare (src, 2, 2, 2, 1, &w, &h);
  g_assert_cmpuint (w, ==, 6);
  g_assert_cmpuint (h, ==, 6);
  g_assert_cmpmem (out, w * h, expected, sizeof (expected));

  /* The production geometry */
  g_clear_pointer (&out, g_free);
  {
    g_autofree guint8 *img = g_malloc0 (112 * 112);

    out = validity_image_prepare (img, 112, 112, 2, 16, &w, &h);
    g_assert_cmpuint (w, ==, 256);
    g_assert_cmpuint (h, ==, 256);
  }
}

static void
test_tls_prf (void)
{
  g_autoptr(GBytes) secret = vec ("tls", "prf_secret");
  g_autoptr(GBytes) seed = vec ("tls", "prf_seed");
  g_autoptr(GBytes) expected = vec ("tls", "prf_out");
  guint8 out[100];

  validity_tls_prf (g_bytes_get_data (secret, NULL), g_bytes_get_size (secret),
                    g_bytes_get_data (seed, NULL), g_bytes_get_size (seed),
                    out, sizeof (out));
  g_assert_cmpmem (out, sizeof (out), g_bytes_get_data (expected, NULL),
                   g_bytes_get_size (expected));
}

static void
counter_random (guint8 *buf, gsize len, gpointer user_data)
{
  guint8 *counter = user_data;

  for (gsize i = 0; i < len; i++)
    buf[i] = (*counter)++ ^ 0x5a;
}

/* Builds pairing data with a real sensor ECDH blob and checks that it can
 * be stored and reloaded, and that a different host identity is detected. */
static void
test_tls_pairing_roundtrip (void)
{
  g_autoptr(ValidityTls) tls = validity_tls_new ();
  g_autoptr(ValidityTls) other = validity_tls_new ();
  g_autoptr(ValidityTls) foreign = validity_tls_new ();
  g_autoptr(GBytes) ecdh_rsp = vec ("tls", "ecdh_rsp");
  g_autoptr(GBytes) blob = NULL;
  g_autoptr(GBytes) cert = NULL;
  g_autoptr(GBytes) flash = NULL;
  g_autoptr(GBytes) flash2 = NULL;
  g_autoptr(GError) error = NULL;
  static const guint8 server_cert[] = { 0x01, 0x02, 0x03, 0x04 };
  guint8 counter = 0;
  const guint8 *f;

  validity_tls_set_random_func (tls, counter_random, &counter);
  validity_tls_set_host_identity (tls, "Product", "Serial");

  g_assert_true (validity_tls_pairing_begin (tls, &error));
  g_assert_no_error (error);

  cert = validity_tls_pairing_get_client_cert (tls, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (g_bytes_get_size (cert), ==, VALIDITY_TLS_PAIRING_CERT_LEN);
  f = g_bytes_get_data (cert, NULL);
  g_assert_cmpuint (f[0], ==, 0x17);
  g_assert_cmpuint (f[4], ==, 0x20);

  g_assert_true (validity_tls_pairing_set_server_cert (tls, server_cert, sizeof (server_cert),
                                                       &error));
  g_assert_no_error (error);

  blob = validity_parse_ecdh_reply (g_bytes_get_data (ecdh_rsp, NULL),
                                    g_bytes_get_size (ecdh_rsp), &error);
  g_assert_no_error (error);
  g_assert_true (validity_tls_pairing_set_server_ecdh (tls, g_bytes_get_data (blob, NULL),
                                                       g_bytes_get_size (blob), &error));
  g_assert_no_error (error);

  g_assert_true (validity_tls_pairing_finish (tls, &error));
  g_assert_no_error (error);
  g_assert_true (validity_tls_has_pairing (tls));

  flash = validity_tls_build_flash (tls, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (g_bytes_get_size (flash), ==, VALIDITY_TLS_FLASH_SIZE);

  /* Same identity: loads and reproduces the identical flash image */
  validity_tls_set_host_identity (other, "Product", "Serial");
  g_assert_true (validity_tls_load_flash (other, g_bytes_get_data (flash, NULL),
                                          g_bytes_get_size (flash), &error));
  g_assert_no_error (error);
  g_assert_true (validity_tls_has_pairing (other));
  flash2 = validity_tls_build_flash (other, &error);
  g_assert_no_error (error);
  assert_bytes_equal (flash2, flash);

  /* Another identity: detected as foreign pairing */
  validity_tls_set_host_identity (foreign, "Product", "Other serial");
  g_assert_false (validity_tls_load_flash (foreign, g_bytes_get_data (flash, NULL),
                                           g_bytes_get_size (flash), &error));
  g_assert_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_FOREIGN_PAIRING);
  g_clear_error (&error);
  /* Nothing partially loaded remains */
  g_assert_false (validity_tls_has_pairing (foreign));
  g_assert_null (validity_tls_build_flash (foreign, &error));
  g_assert_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO);
  g_clear_error (&error);

  /* Corrupted block hash */
  {
    g_autofree guint8 *bad = g_memdup2 (g_bytes_get_data (flash, NULL), VALIDITY_TLS_FLASH_SIZE);

    bad[4] ^= 0x01;
    g_assert_false (validity_tls_load_flash (other, bad, VALIDITY_TLS_FLASH_SIZE, &error));
    g_assert_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO);
    g_clear_error (&error);
    g_assert_false (validity_tls_has_pairing (other));
  }

  /* Erased flash: no pairing, no error */
  {
    guint8 erased[VALIDITY_TLS_FLASH_SIZE];

    memset (erased, 0xff, sizeof (erased));
    g_assert_true (validity_tls_load_flash (foreign, erased, sizeof (erased), &error));
    g_assert_no_error (error);
    g_assert_false (validity_tls_has_pairing (foreign));
  }
}

static void
test_tls_misuse (void)
{
  g_autoptr(ValidityTls) tls = validity_tls_new ();
  g_autoptr(GError) error = NULL;
  g_autofree guint8 *big = g_malloc0 (VALIDITY_TLS_MAX_CERT_LEN + 1);

  /* Out of order calls report errors instead of crashing */
  g_assert_null (validity_tls_build_client_hello (tls, &error));
  g_assert_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO);
  g_clear_error (&error);
  g_assert_null (validity_tls_build_client_finish (tls, &error));
  g_assert_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO);
  g_clear_error (&error);
  g_assert_false (validity_tls_handle_server_hello (tls, (const guint8 *) "\0\0", 2, &error));
  g_assert_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO);
  g_clear_error (&error);
  g_assert_null (validity_tls_pairing_get_client_cert (tls, &error));
  g_assert_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO);
  g_clear_error (&error);
  g_assert_null (validity_tls_wrap (tls, (const guint8 *) "x", 1, &error));
  g_assert_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO);
  g_clear_error (&error);

  /* Certificates that can't fit into the pairing data are rejected */
  g_assert_false (validity_tls_pairing_set_server_cert (tls, big, VALIDITY_TLS_MAX_CERT_LEN + 1,
                                                        &error));
  g_assert_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO);
  g_clear_error (&error);
  g_assert_false (validity_tls_pairing_set_server_cert (tls, big, 0, &error));
  g_assert_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_PROTO);
}

static void
test_tls_ecdh_tampered (void)
{
  g_autoptr(ValidityTls) tls = validity_tls_new ();
  g_autoptr(GBytes) ecdh_rsp = vec ("tls", "ecdh_rsp");
  g_autoptr(GBytes) blob = NULL;
  g_autoptr(GError) error = NULL;
  g_autofree guint8 *data = NULL;
  gsize len;

  blob = validity_parse_ecdh_reply (g_bytes_get_data (ecdh_rsp, NULL),
                                    g_bytes_get_size (ecdh_rsp), &error);
  g_assert_no_error (error);

  data = g_bytes_unref_to_data (g_steal_pointer (&blob), &len);
  data[0x10] ^= 0x01;

  g_assert_false (validity_tls_pairing_set_server_ecdh (tls, data, len, &error));
  g_assert_error (error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_CRYPTO);
}

int
main (int argc, char *argv[])
{
  g_autoptr(GError) error = NULL;
  g_autofree gchar *path = NULL;

  g_test_init (&argc, &argv, NULL);

  path = g_test_build_filename (G_TEST_DIST, "validity-unit", "vectors.ini", NULL);
  vectors = g_key_file_new ();
  if (!g_key_file_load_from_file (vectors, path, G_KEY_FILE_NONE, &error))
    g_error ("Cannot load %s: %s", path, error->message);

  g_test_add_func ("/validity/capture-program/uncalibrated", test_capture_program_uncalibrated);
  g_test_add_func ("/validity/calibration-and-programs", test_calibration_and_programs);
  g_test_add_func ("/validity/calibration-short-data", test_calibration_short_data);
  g_test_add_func ("/validity/parse-image", test_parse_image);
  g_test_add_func ("/validity/image-prepare", test_image_prepare);
  g_test_add_func ("/validity/tls/prf", test_tls_prf);
  g_test_add_func ("/validity/tls/pairing-roundtrip", test_tls_pairing_roundtrip);
  g_test_add_func ("/validity/tls/ecdh-tampered", test_tls_ecdh_tampered);
  g_test_add_func ("/validity/tls/misuse", test_tls_misuse);

  return g_test_run ();
}
