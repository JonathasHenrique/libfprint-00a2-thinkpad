/*
 * Synaptics/Validity "VSI" match-on-host sensors (06cb:00a2)
 *
 * Copyright (C) 2026 Aurel Farkasovsky
 *
 * The protocol knowledge implemented here was originally reverse engineered
 * by the python-validity project (Copyright (c) 2020 uunicorn, MIT License,
 * see LICENSE.python-validity in this directory) and extended for the
 * match-on-host 06cb:00a2 sensor by analyzing the vendor Windows driver.
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

/*
 * Overview
 * ========
 *
 * The sensor is driven over three bulk endpoints and one interrupt endpoint:
 *
 *   EP 0x01/0x81  command/response pairs; after the secure channel is up,
 *                 commands are wrapped in a TLS-like record layer
 *   EP 0x82       raw frame data (only used for calibration)
 *   EP 0x83       short event packets (scan started, finger down, ...)
 *
 * Opening the device:
 *   1. USB reset (resets the sensor MCU and any stale secure session)
 *   2. plain commands: ROM info, reset info, firmware info, vendor init blob
 *   3. flash layout and pairing data (stored on the sensor itself)
 *   4. if the sensor is blank or paired with another host: provisioning,
 *      i.e. factory wipe, partitioning, key exchange, firmware upload
 *   5. secure channel handshake, sensor identification, calibration
 *
 * The firmware reconstructs a 112x112 8-bit image after each touch, which
 * is handed to libfprint's NBIS based matcher (the sensor does not match
 * on chip with this firmware).
 */

#define FP_COMPONENT "validity"

#include "drivers_api.h"
#include "fpi-byte-utils.h"
#include "validity.h"
#include "validity-proto.h"
#include "validity-tls.h"
#include "validity-vendor.h"

#include <openssl/evp.h>

#define EP_CMD_OUT 0x01
#define EP_CMD_IN 0x81
#define EP_DATA_IN 0x82
#define EP_INT_IN 0x83

#define CMD_TIMEOUT_MS 15000
#define CMD_RSP_MAX 0x10000
#define INT_PKT_MAX 64
#define IMAGE_MAX 0x10000

/* Finger lift detection: the finger-down event of a fresh capture program
 * fires within a few ms if a finger is resting on the sensor. */
#define FINGER_OFF_WINDOW_MS 300
#define FINGER_OFF_RETRY_MS 100

#define MAX_OPEN_RESTARTS 2

#define FACTORY_BITS_TAG 0x0e00
#define FACTORY_CALIB_SUBTAG 3
#define FACTORY_CALIB_SKIP 4

/* ROM patch level of the sensors this driver was tested with */
#define VALIDITY_ROM_PATCH_LEVEL 0xd103

#define REG_FWEXT_CTRL 0x8000205c
#define REG_FWEXT_STATE 0x80002080

/*
 * Image preparation and matching parameters, from measurements with
 * genuine and impostor images of this sensor (see README.md):
 *  - at native size NBIS finds ~6 minutiae and all scores are 0;
 *  - 2x upscaling gives ~13 minutiae;
 *  - padding by 16 replicated edge pixels lets the detector use the blocks
 *    along the sensor edge: with perimeter removal ~16 minutiae remain and
 *    false rejections drop from 6.4% to 4.9% (threshold 10);
 *  - more padding, or padding with a flat color, produces artificial
 *    minutiae that match between different fingers;
 *  - the highest impostor score with these settings was 4.
 * The sensor covers only a small part of the finger, so many enroll
 * stages are needed to cover enough of it.
 */
#define VALIDITY_IMAGE_SIZE 112
#define VALIDITY_IMAGE_SCALE 2
#define VALIDITY_IMAGE_PAD 16
#define VALIDITY_BZ3_THRESHOLD 8
#define VALIDITY_ENROLL_STAGES 15

/* Partitions erased after pairing, in vendor order */
static const guint8 pairing_erase_order[] = {
  VALIDITY_PARTITION_TLS,
  VALIDITY_PARTITION_FWEXT,
  VALIDITY_PARTITION_UNKNOWN5,
  VALIDITY_PARTITION_CALIBRATION,
  VALIDITY_PARTITION_TEMPLATES,
};

/* Flash layout written when provisioning; must match the signed layout
 * in the vendor data (partition-signature.bin). */
static const ValidityPartition pairing_layout[] = {
  /* id, type, access level, offset, size */
  { VALIDITY_PARTITION_TLS,         4, 7, 0x00001000, 0x00001000 },
  { VALIDITY_PARTITION_FWEXT,       1, 2, 0x00002000, 0x0003e000 },
  { VALIDITY_PARTITION_UNKNOWN5,    5, 3, 0x00040000, 0x00008000 },
  { VALIDITY_PARTITION_CALIBRATION, 6, 3, 0x00048000, 0x00008000 },
  { VALIDITY_PARTITION_TEMPLATES,   3, 5, 0x00050000, 0x00080000 },
};

typedef enum {
  PROVISION_NONE,
  PROVISION_PAIR,           /* blank sensor */
  PROVISION_WIPE_AND_PAIR,  /* sensor paired with another host */
} ProvisionKind;

struct _FpiDeviceValidity
{
  FpImageDevice       parent;

  ValidityTls        *tls;
  ValidityVendorData *vendor;
  ValidityRomInfo     rom;
  ValidityFlashInfo   flash;
  ValiditySensor      sensor;

  gboolean            test_mode;
  guint64             rng_counter;

  ProvisionKind       provision;
  guint               open_restarts;

  /* Capture */
  FpiSsm       *capture_ssm;
  GCancellable *capture_cancel;
  gboolean      deactivating;
  ValidityImage image;
  gboolean      finger_present;
  gboolean      needs_reconnect;
};

G_DEFINE_TYPE (FpiDeviceValidity, fpi_device_validity, FP_TYPE_IMAGE_DEVICE);

/* ---------------------------------------------------------------------- */
/* Helpers                                                                */
/* ---------------------------------------------------------------------- */

static GError *
proto_error_new (const gchar *what, GError *cause)
{
  return fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "%s: %s", what,
                                   cause ? cause->message : "internal error");
}

/* Deterministic random stream for emulation/testing:
 * SHA-256("libfprint-validity-test" || LE64(counter)) */
static void
test_random (guint8 *buf, gsize len, gpointer user_data)
{
  FpiDeviceValidity *self = user_data;

  while (len > 0)
    {
      static const gchar label[] = "libfprint-validity-test";
      guint8 input[sizeof (label) - 1 + 8];
      guint8 block[32];
      unsigned int block_len = sizeof (block);
      gsize n;

      memcpy (input, label, sizeof (label) - 1);
      FP_WRITE_UINT64_LE (input + sizeof (label) - 1, self->rng_counter);
      self->rng_counter++;

      if (EVP_Digest (input, sizeof (input), block, &block_len, EVP_sha256 (), NULL) != 1)
        g_error ("validity: SHA-256 failed");

      n = MIN (len, sizeof (block));
      memcpy (buf, block, n);
      buf += n;
      len -= n;
    }
}

static gchar *
read_dmi_attr (const gchar *name, GError **error)
{
  g_autofree gchar *path = g_build_filename ("/sys/class/dmi/id", name, NULL);
  g_autofree gchar *contents = NULL;

  if (!g_file_get_contents (path, &contents, NULL, error))
    return NULL;

  return g_strdup (g_strstrip (contents));
}

/* The pairing key stored on the sensor is bound to this host's identity. */
static gboolean
setup_host_identity (FpiDeviceValidity *self, GError **error)
{
  g_autofree gchar *product = NULL;
  g_autofree gchar *serial = NULL;

  g_autoptr(GError) local_error = NULL;

  if (self->test_mode)
    {
      validity_tls_set_host_identity (self->tls, "libfprint-test", "0");
      return TRUE;
    }

  product = read_dmi_attr ("product_name", &local_error);
  if (product)
    serial = read_dmi_attr ("product_serial", &local_error);

  if (!product || !serial)
    {
      /* No fallback identity: with a wrong identity the sensor looks paired
       * with another host and would be re-provisioned. */
      *error = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                         "Cannot read the host identity (%s); "
                                         "the sensor can only be used with root privileges",
                                         local_error->message);
      return FALSE;
    }

  validity_tls_set_host_identity (self->tls, product, serial);
  return TRUE;
}

static gboolean
usb_reset (FpiDeviceValidity *self, GError **error)
{
  GUsbDevice *usb_dev = fpi_device_get_usb_device (FP_DEVICE (self));

  validity_tls_reset_session (self->tls);

  /* Resets the sensor MCU without re-enumeration; claimed interfaces are
   * restored by libusb. */
  return g_usb_device_reset (usb_dev, error);
}

/* ---------------------------------------------------------------------- */
/* Command transport                                                      */
/* ---------------------------------------------------------------------- */

typedef void (*CmdHandler) (FpiDeviceValidity *self,
                            FpiSsm            *ssm,
                            const guint8      *rsp,
                            gsize              len);

typedef struct
{
  gboolean     secure;
  CmdHandler   handler;
  const gchar *what;
} CmdData;

static void
cmd_in_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (dev);
  g_autofree CmdData *cmd = user_data;

  g_autoptr(GBytes) plain = NULL;
  const guint8 *rsp = transfer->buffer;
  gsize len = transfer->actual_length;

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  if (cmd->secure)
    {
      g_autoptr(GError) tls_error = NULL;

      plain = validity_tls_unwrap (self->tls, rsp, len, &tls_error);
      if (!plain)
        {
          fpi_ssm_mark_failed (transfer->ssm, proto_error_new (cmd->what, tls_error));
          return;
        }
      rsp = g_bytes_get_data (plain, &len);
    }

  if (cmd->handler)
    {
      cmd->handler (self, transfer->ssm, rsp, len);
    }
  else
    {
      GError *status_error = NULL;

      if (validity_check_status (rsp, len, cmd->what, &status_error))
        fpi_ssm_next_state (transfer->ssm);
      else
        fpi_ssm_mark_failed (transfer->ssm, status_error);
    }
}

static void
cmd_out_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  FpiUsbTransfer *in;

  if (error)
    {
      g_free (user_data);
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  in = fpi_usb_transfer_new (dev);
  in->ssm = transfer->ssm;
  fpi_usb_transfer_fill_bulk (in, EP_CMD_IN, CMD_RSP_MAX);
  fpi_usb_transfer_submit (in, CMD_TIMEOUT_MS, NULL, cmd_in_cb, user_data);
}

/* Sends @data (wrapped in the secure channel if @secure) and invokes
 * @handler with the (decrypted) response.  Without a handler, the response
 * status must be zero and the state machine advances. */
static void
send_cmd (FpiDeviceValidity *self, FpiSsm *ssm, const guint8 *data, gsize len,
          gboolean secure, const gchar *what, CmdHandler handler)
{
  g_autoptr(GBytes) wrapped = NULL;
  FpiUsbTransfer *out;
  CmdData *cmd;

  if (secure)
    {
      g_autoptr(GError) tls_error = NULL;

      wrapped = validity_tls_wrap (self->tls, data, len, &tls_error);
      if (!wrapped)
        {
          fpi_ssm_mark_failed (ssm, proto_error_new (what, tls_error));
          return;
        }
      data = g_bytes_get_data (wrapped, &len);
    }

  cmd = g_new0 (CmdData, 1);
  cmd->secure = secure;
  cmd->handler = handler;
  cmd->what = what;

  out = fpi_usb_transfer_new (FP_DEVICE (self));
  out->ssm = ssm;
  out->short_is_error = TRUE;
  fpi_usb_transfer_fill_bulk_full (out, EP_CMD_OUT, g_memdup2 (data, len), len, g_free);
  fpi_usb_transfer_submit (out, CMD_TIMEOUT_MS, NULL, cmd_out_cb, cmd);
}

static void
send_cmd_bytes (FpiDeviceValidity *self, FpiSsm *ssm, GBytes *bytes,
                gboolean secure, const gchar *what, CmdHandler handler)
{
  gsize len;
  const guint8 *data = g_bytes_get_data (bytes, &len);

  send_cmd (self, ssm, data, len, secure, what, handler);
}

static void
send_vendor_blob (FpiDeviceValidity *self, FpiSsm *ssm, ValidityVendorFile file,
                  gboolean secure, const gchar *what, CmdHandler handler)
{
  g_autoptr(GBytes) blob = NULL;
  GError *error = NULL;

  blob = validity_vendor_data_get (self->vendor, file, &error);
  if (!blob)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  send_cmd_bytes (self, ssm, blob, secure, what, handler);
}

static void
handler_ignore_status (FpiDeviceValidity *self, FpiSsm *ssm, const guint8 *rsp, gsize len)
{
  fp_dbg ("Ignoring reply status 0x%04x", validity_rsp_status (rsp, len));
  fpi_ssm_next_state (ssm);
}

/* "Commit" of pending flash operations; nothing to commit is fine. */
static void
handler_cleanup (FpiDeviceValidity *self, FpiSsm *ssm, const guint8 *rsp, gsize len)
{
  guint16 status = validity_rsp_status (rsp, len);

  if (status == VALIDITY_STATUS_OK || status == VALIDITY_STATUS_NOTHING_TO_COMMIT)
    fpi_ssm_next_state (ssm);
  else
    fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                        "Flash commit failed with status 0x%04x",
                                                        status));
}

static const guint8 cmd_cleanup[] = { VALIDITY_CMD_CLEANUP };

/* ---------------------------------------------------------------------- */
/* Secure channel handshake                                               */
/* ---------------------------------------------------------------------- */

enum {
  HANDSHAKE_HELLO,
  HANDSHAKE_FINISH,
  HANDSHAKE_NUM_STATES,
};

static void
handshake_server_hello (FpiDeviceValidity *self, FpiSsm *ssm, const guint8 *rsp, gsize len)
{
  g_autoptr(GError) error = NULL;

  if (!validity_tls_handle_server_hello (self->tls, rsp, len, &error))
    fpi_ssm_mark_failed (ssm, proto_error_new ("TLS handshake", error));
  else
    fpi_ssm_next_state (ssm);
}

static void
handshake_server_finish (FpiDeviceValidity *self, FpiSsm *ssm, const guint8 *rsp, gsize len)
{
  g_autoptr(GError) error = NULL;

  if (!validity_tls_handle_server_finish (self->tls, rsp, len, &error))
    {
      fpi_ssm_mark_failed (ssm, proto_error_new ("TLS handshake", error));
      return;
    }

  fp_dbg ("Secure channel established");
  fpi_ssm_next_state (ssm);
}

static void
handshake_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (dev);

  g_autoptr(GBytes) msg = NULL;
  g_autoptr(GError) error = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case HANDSHAKE_HELLO:
      msg = validity_tls_build_client_hello (self->tls, &error);
      if (!msg)
        break;
      send_cmd_bytes (self, ssm, msg, FALSE, "TLS client hello", handshake_server_hello);
      return;

    case HANDSHAKE_FINISH:
      msg = validity_tls_build_client_finish (self->tls, &error);
      if (!msg)
        break;
      send_cmd_bytes (self, ssm, msg, FALSE, "TLS client finish", handshake_server_finish);
      return;
    }

  fpi_ssm_mark_failed (ssm, proto_error_new ("TLS handshake", error));
}

static FpiSsm *
handshake_ssm_new (FpiDeviceValidity *self)
{
  return fpi_ssm_new (FP_DEVICE (self), handshake_run_state, HANDSHAKE_NUM_STATES);
}

/* ---------------------------------------------------------------------- */
/* Flash access                                                           */
/* ---------------------------------------------------------------------- */

typedef struct
{
  guint8      partition;
  guint32     offset;
  GBytes     *data;      /* write: data to write */
  gsize       pos;
  gsize       len;       /* read: number of bytes to read */
  GByteArray *result;    /* read: accumulated data */
} FlashOp;

static void
flash_op_free (gpointer p)
{
  FlashOp *op = p;

  g_clear_pointer (&op->data, g_bytes_unref);
  g_clear_pointer (&op->result, g_byte_array_unref);
  g_free (op);
}

/* --- Write: (unlock, write chunk, commit) per chunk ---------------------- */

enum {
  FLASH_WRITE_UNLOCK,
  FLASH_WRITE_CHUNK,
  FLASH_WRITE_COMMIT,
  FLASH_WRITE_NEXT,
  FLASH_WRITE_NUM_STATES,
};

static void
flash_write_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (dev);
  FlashOp *op = fpi_ssm_get_data (ssm);
  gsize total;
  const guint8 *data = g_bytes_get_data (op->data, &total);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case FLASH_WRITE_UNLOCK:
      send_vendor_blob (self, ssm, VALIDITY_VENDOR_DB_WRITE_ENABLE, TRUE,
                        "Flash write unlock", NULL);
      break;

    case FLASH_WRITE_CHUNK:
      {
        gsize n = MIN (VALIDITY_FLASH_CHUNK, total - op->pos);
        g_autoptr(GBytes) cmd = validity_cmd_flash_write (op->partition, op->offset + op->pos,
                                                          data + op->pos, n);

        op->pos += n;
        send_cmd_bytes (self, ssm, cmd, TRUE, "Flash write", NULL);
      }
      break;

    case FLASH_WRITE_COMMIT:
      send_cmd (self, ssm, cmd_cleanup, sizeof (cmd_cleanup), TRUE, "Flash commit",
                handler_cleanup);
      break;

    case FLASH_WRITE_NEXT:
      if (op->pos < total)
        fpi_ssm_jump_to_state (ssm, FLASH_WRITE_UNLOCK);
      else
        fpi_ssm_next_state (ssm);
      break;
    }
}

static FpiSsm *
flash_write_ssm_new (FpiDeviceValidity *self, guint8 partition, guint32 offset, GBytes *data)
{
  FpiSsm *ssm;
  FlashOp *op;

  g_return_val_if_fail (data != NULL && g_bytes_get_size (data) > 0, NULL);

  ssm = fpi_ssm_new (FP_DEVICE (self), flash_write_run_state, FLASH_WRITE_NUM_STATES);
  op = g_new0 (FlashOp, 1);
  op->partition = partition;
  op->offset = offset;
  op->data = g_bytes_ref (data);
  fpi_ssm_set_data (ssm, op, flash_op_free);
  return ssm;
}

/* --- Erase: unlock, erase, commit ---------------------------------------- */

enum {
  FLASH_ERASE_UNLOCK,
  FLASH_ERASE_ERASE,
  FLASH_ERASE_COMMIT,
  FLASH_ERASE_NUM_STATES,
};

static void
flash_erase_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (dev);
  FlashOp *op = fpi_ssm_get_data (ssm);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case FLASH_ERASE_UNLOCK:
      send_vendor_blob (self, ssm, VALIDITY_VENDOR_DB_WRITE_ENABLE, TRUE,
                        "Flash erase unlock", NULL);
      break;

    case FLASH_ERASE_ERASE:
      {
        guint8 cmd[] = { VALIDITY_CMD_FLASH_ERASE, op->partition };

        fp_dbg ("Erasing flash partition %u", op->partition);
        send_cmd (self, ssm, cmd, sizeof (cmd), TRUE, "Flash erase", NULL);
      }
      break;

    case FLASH_ERASE_COMMIT:
      send_cmd (self, ssm, cmd_cleanup, sizeof (cmd_cleanup), TRUE, "Flash commit",
                handler_cleanup);
      break;
    }
}

static FpiSsm *
flash_erase_ssm_new (FpiDeviceValidity *self, guint8 partition)
{
  FpiSsm *ssm = fpi_ssm_new (FP_DEVICE (self), flash_erase_run_state, FLASH_ERASE_NUM_STATES);
  FlashOp *op = g_new0 (FlashOp, 1);

  op->partition = partition;
  fpi_ssm_set_data (ssm, op, flash_op_free);
  return ssm;
}

/* --- Read (secure channel), in chunks ------------------------------------ */

enum {
  FLASH_READ_CHUNK,
  FLASH_READ_NEXT,
  FLASH_READ_NUM_STATES,
};

static void
flash_read_chunk_done (FpiDeviceValidity *self, FpiSsm *ssm, const guint8 *rsp, gsize len)
{
  FlashOp *op = fpi_ssm_get_data (ssm);

  g_autoptr(GBytes) data = NULL;
  GError *error = NULL;

  data = validity_parse_flash_read (rsp, len, &error);
  if (!data)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  /* Every chunk must make progress and stay within the request */
  if (g_bytes_get_size (data) == 0 ||
      g_bytes_get_size (data) > MIN (VALIDITY_FLASH_CHUNK, op->len - op->pos))
    {
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                          "Flash read returned %" G_GSIZE_FORMAT
                                                          " bytes",
                                                          g_bytes_get_size (data)));
      return;
    }

  g_byte_array_append (op->result, g_bytes_get_data (data, NULL), g_bytes_get_size (data));
  op->pos += g_bytes_get_size (data);
  fpi_ssm_next_state (ssm);
}

static void
flash_read_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (dev);
  FlashOp *op = fpi_ssm_get_data (ssm);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case FLASH_READ_CHUNK:
      {
        gsize n = MIN (VALIDITY_FLASH_CHUNK, op->len - op->pos);
        g_autoptr(GBytes) cmd = validity_cmd_flash_read (op->partition, op->offset + op->pos, n);

        send_cmd_bytes (self, ssm, cmd, TRUE, "Flash read", flash_read_chunk_done);
      }
      break;

    case FLASH_READ_NEXT:
      if (op->pos < op->len)
        fpi_ssm_jump_to_state (ssm, FLASH_READ_CHUNK);
      else
        fpi_ssm_next_state (ssm);
      break;
    }
}

/* Reads @len bytes into @result (owned by the caller), which is complete
 * when the parent state machine advances to its next state. */
static FpiSsm *
flash_read_ssm_new (FpiDeviceValidity *self, guint8 partition, guint32 offset, gsize len,
                    GByteArray *result)
{
  FpiSsm *ssm;
  FlashOp *op;

  g_return_val_if_fail (len > 0 && result != NULL, NULL);

  ssm = fpi_ssm_new (FP_DEVICE (self), flash_read_run_state, FLASH_READ_NUM_STATES);
  op = g_new0 (FlashOp, 1);
  g_byte_array_set_size (result, 0);
  op->partition = partition;
  op->offset = offset;
  op->len = len;
  op->result = g_byte_array_ref (result);
  fpi_ssm_set_data (ssm, op, flash_op_free);
  return ssm;
}

/* ---------------------------------------------------------------------- */
/* Firmware extension upload                                              */
/* ---------------------------------------------------------------------- */

#define FWEXT_SIGNATURE_SIZE 0x100

enum {
  FWEXT_PREPARE,
  FWEXT_REG_WRITE,
  FWEXT_REG_READ,
  FWEXT_IDENTIFY,
  FWEXT_WRITE,
  FWEXT_SIGNATURE,
  FWEXT_VERIFY,
  FWEXT_NUM_STATES,
};

typedef struct
{
  GBytes *image;
  GBytes *signature;
} FwextData;

static void
fwext_data_free (gpointer p)
{
  FwextData *data = p;

  g_clear_pointer (&data->image, g_bytes_unref);
  g_clear_pointer (&data->signature, g_bytes_unref);
  g_free (data);
}

/* The .xpfwext file is a text header terminated by 0x1a, followed by the
 * encrypted image and a 256 byte signature. */
static gboolean
fwext_split (GBytes *file, FwextData *data, GError **error)
{
  gsize len;
  const guint8 *p = g_bytes_get_data (file, &len);
  const guint8 *end = memchr (p, 0x1a, len);
  gsize body;

  if (!end)
    goto bad;

  body = len - (end + 1 - p);
  if (body <= FWEXT_SIGNATURE_SIZE)
    goto bad;

  data->image = g_bytes_new_from_bytes (file, end + 1 - p, body - FWEXT_SIGNATURE_SIZE);
  data->signature = g_bytes_new_from_bytes (file, len - FWEXT_SIGNATURE_SIZE,
                                            FWEXT_SIGNATURE_SIZE);
  return TRUE;

bad:
  g_set_error_literal (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                       "Malformed firmware extension file");
  return FALSE;
}

static void
fwext_reg_read_done (FpiDeviceValidity *self, FpiSsm *ssm, const guint8 *rsp, gsize len)
{
  GError *error = NULL;
  guint32 value;

  if (!validity_check_status (rsp, len, "Register read", &error))
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  if (len != 2 + 4)
    {
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                          "Malformed register read reply"));
      return;
    }

  value = FP_READ_UINT32_LE (rsp + 2);
  if (value != 2 && value != 3)
    {
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                          "Sensor not ready for firmware upload "
                                                          "(state %u)", value));
      return;
    }

  fpi_ssm_next_state (ssm);
}

static void
fwext_verify_done (FpiDeviceValidity *self, FpiSsm *ssm, const guint8 *rsp, gsize len)
{
  ValidityFwInfo info;
  GError *error = NULL;

  if (!validity_parse_fw_info (rsp, len, &info, &error))
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  if (!info.present)
    {
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                          "Firmware extension was not accepted"));
      return;
    }

  fp_info ("Firmware extension %u.%u uploaded (%u modules)", info.major, info.minor,
           info.n_modules);
  fpi_ssm_next_state (ssm);
}

static void
fwext_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (dev);
  FwextData *data = fpi_ssm_get_data (ssm);
  GError *error = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case FWEXT_PREPARE:
      {
        g_autoptr(GBytes) file = validity_vendor_data_get (self->vendor, VALIDITY_VENDOR_FWEXT,
                                                           &error);

        if (!file || !fwext_split (file, data, &error))
          {
            fpi_ssm_mark_failed (ssm, error);
            return;
          }
        fp_info ("Uploading firmware extension (%" G_GSIZE_FORMAT " bytes)",
                 g_bytes_get_size (data->image));
        fpi_ssm_next_state (ssm);
      }
      break;

    case FWEXT_REG_WRITE:
      {
        guint8 cmd[10] = { 0x08 };

        FP_WRITE_UINT32_LE (cmd + 1, REG_FWEXT_CTRL);
        FP_WRITE_UINT32_LE (cmd + 5, 7);
        cmd[9] = 4;
        send_cmd (self, ssm, cmd, sizeof (cmd), TRUE, "Register write", NULL);
      }
      break;

    case FWEXT_REG_READ:
      {
        guint8 cmd[6] = { 0x07 };

        FP_WRITE_UINT32_LE (cmd + 1, REG_FWEXT_STATE);
        cmd[5] = 4;
        send_cmd (self, ssm, cmd, sizeof (cmd), TRUE, "Register read", fwext_reg_read_done);
      }
      break;

    case FWEXT_IDENTIFY:
      {
        static const guint8 cmd[] = { VALIDITY_CMD_IDENTIFY_SENSOR };

        send_cmd (self, ssm, cmd, sizeof (cmd), TRUE, "Sensor identification", NULL);
      }
      break;

    case FWEXT_WRITE:
      fpi_ssm_start_subsm (ssm, flash_write_ssm_new (self, VALIDITY_PARTITION_FWEXT, 0,
                                                     data->image));
      break;

    case FWEXT_SIGNATURE:
      {
        g_autoptr(GBytes) cmd = validity_cmd_fw_signature (VALIDITY_PARTITION_FWEXT,
                                                           g_bytes_get_data (data->signature, NULL),
                                                           g_bytes_get_size (data->signature));

        send_cmd_bytes (self, ssm, cmd, TRUE, "Firmware signature", NULL);
      }
      break;

    case FWEXT_VERIFY:
      {
        static const guint8 cmd[] = { VALIDITY_CMD_FW_INFO, VALIDITY_PARTITION_FWEXT };

        send_cmd (self, ssm, cmd, sizeof (cmd), TRUE, "Firmware info", fwext_verify_done);
      }
      break;
    }
}

static FpiSsm *
fwext_ssm_new (FpiDeviceValidity *self)
{
  FpiSsm *ssm = fpi_ssm_new (FP_DEVICE (self), fwext_run_state, FWEXT_NUM_STATES);

  fpi_ssm_set_data (ssm, g_new0 (FwextData, 1), fwext_data_free);
  return ssm;
}

/* ---------------------------------------------------------------------- */
/* Provisioning (pairing the sensor with this host)                       */
/* ---------------------------------------------------------------------- */

enum {
  PROVISION_CHECK,
  PROVISION_WIPE_UNLOCK,
  PROVISION_WIPE,
  PROVISION_WIPE_RESET,
  PROVISION_UNLOCK,
  PROVISION_PARTITION,
  PROVISION_ROM_INFO,
  PROVISION_GET_ECDH,
  PROVISION_COMMIT,
  PROVISION_PAIR_KEYS,
  PROVISION_HANDSHAKE,
  PROVISION_ERASE,
  PROVISION_ERASE_NEXT,
  PROVISION_WRITE_PAIRING,
  PROVISION_FWEXT,
  PROVISION_RESET,
  PROVISION_NUM_STATES,
};

typedef struct
{
  guint                  erase_idx;
  const ValidityFlashIc *ic;
} ProvisionData;

static void
provision_partition_done (FpiDeviceValidity *self, FpiSsm *ssm, const guint8 *rsp, gsize len)
{
  g_autoptr(GBytes) cert = NULL;
  GError *error = NULL;

  g_autoptr(GError) tls_error = NULL;

  cert = validity_parse_pairing_cert (rsp, len, &error);
  if (!cert)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  if (!validity_tls_pairing_set_server_cert (self->tls, g_bytes_get_data (cert, NULL),
                                             g_bytes_get_size (cert), &tls_error))
    {
      fpi_ssm_mark_failed (ssm, proto_error_new ("Pairing", tls_error));
      return;
    }

  fpi_ssm_next_state (ssm);
}

static void
provision_ecdh_done (FpiDeviceValidity *self, FpiSsm *ssm, const guint8 *rsp, gsize len)
{
  g_autoptr(GBytes) blob = NULL;
  g_autoptr(GError) tls_error = NULL;
  GError *error = NULL;

  blob = validity_parse_ecdh_reply (rsp, len, &error);
  if (!blob)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  if (!validity_tls_pairing_set_server_ecdh (self->tls, g_bytes_get_data (blob, NULL),
                                             g_bytes_get_size (blob), &tls_error))
    {
      fpi_ssm_mark_failed (ssm, proto_error_new ("Sensor key", tls_error));
      return;
    }

  fpi_ssm_next_state (ssm);
}

static void
provision_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (dev);
  ProvisionData *data = fpi_ssm_get_data (ssm);
  GError *error = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case PROVISION_CHECK:
      /* Only start destructive operations if they can be completed. */
      if (!validity_vendor_data_check_provisioning (self->vendor, &error))
        {
          fpi_ssm_mark_failed (ssm, error);
          return;
        }

      data->ic = validity_flash_ic_lookup (self->flash.jedec_id0, self->flash.jedec_id1,
                                           (guint32) self->flash.blocks * self->flash.blocksize);
      if (!data->ic)
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                                              "Unknown flash chip %02x:%02x "
                                                              "(%u bytes)",
                                                              self->flash.jedec_id0,
                                                              self->flash.jedec_id1,
                                                              (guint) self->flash.blocks *
                                                              self->flash.blocksize));
          return;
        }
      fp_dbg ("Flash chip: %s (%u bytes)", data->ic->name, data->ic->size);

      if (self->provision == PROVISION_WIPE_AND_PAIR)
        {
          fp_info ("Sensor is paired with another host, re-provisioning it");
          fpi_ssm_next_state (ssm);
        }
      else
        {
          fp_info ("Sensor is not provisioned, provisioning it");
          fpi_ssm_jump_to_state (ssm, PROVISION_UNLOCK);
        }
      break;

    case PROVISION_WIPE_UNLOCK:
      send_vendor_blob (self, ssm, VALIDITY_VENDOR_RESET, FALSE, "Factory reset unlock", NULL);
      break;

    case PROVISION_WIPE:
      {
        guint8 cmd[1 + 0x61] = { VALIDITY_CMD_FACTORY_WIPE };

        send_cmd (self, ssm, cmd, sizeof (cmd), FALSE, "Factory reset", NULL);
      }
      break;

    case PROVISION_WIPE_RESET:
      /* The sensor only accepts partitioning after a restart. */
      if (!usb_reset (self, &error))
        fpi_ssm_mark_failed (ssm, error);
      else
        fpi_ssm_next_state (ssm);
      break;

    case PROVISION_UNLOCK:
      send_vendor_blob (self, ssm, VALIDITY_VENDOR_RESET, FALSE, "Partitioning unlock", NULL);
      break;

    case PROVISION_PARTITION:
      {
        g_autoptr(GBytes) sig = NULL;
        g_autoptr(GBytes) cert = NULL;
        g_autoptr(GBytes) cmd = NULL;
        g_autoptr(GError) tls_error = NULL;
        const guint8 *ca;
        gsize ca_len;

        sig = validity_vendor_data_get (self->vendor, VALIDITY_VENDOR_PARTITION_SIG, &error);
        if (!sig)
          {
            fpi_ssm_mark_failed (ssm, error);
            return;
          }

        if (!validity_tls_pairing_begin (self->tls, &tls_error) ||
            !(cert = validity_tls_pairing_get_client_cert (self->tls, &tls_error)))
          {
            fpi_ssm_mark_failed (ssm, proto_error_new ("Pairing", tls_error));
            return;
          }

        ca = validity_tls_get_ca_blob (&ca_len);
        cmd = validity_cmd_partition_flash (data->ic, pairing_layout, G_N_ELEMENTS (pairing_layout),
                                            g_bytes_get_data (sig, NULL), g_bytes_get_size (sig),
                                            cert, ca, ca_len);
        send_cmd_bytes (self, ssm, cmd, FALSE, "Flash partitioning", provision_partition_done);
      }
      break;

    case PROVISION_ROM_INFO:
      {
        static const guint8 cmd[] = { VALIDITY_CMD_ROM_INFO };

        send_cmd (self, ssm, cmd, sizeof (cmd), FALSE, "ROM info", NULL);
      }
      break;

    case PROVISION_GET_ECDH:
      {
        static const guint8 cmd[] = { VALIDITY_CMD_GET_ECDH };

        send_cmd (self, ssm, cmd, sizeof (cmd), FALSE, "Sensor key read", provision_ecdh_done);
      }
      break;

    case PROVISION_COMMIT:
      send_cmd (self, ssm, cmd_cleanup, sizeof (cmd_cleanup), FALSE, "Flash commit",
                handler_cleanup);
      break;

    case PROVISION_PAIR_KEYS:
      {
        g_autoptr(GError) tls_error = NULL;

        if (!validity_tls_pairing_finish (self->tls, &tls_error))
          fpi_ssm_mark_failed (ssm, proto_error_new ("Pairing", tls_error));
        else
          fpi_ssm_next_state (ssm);
      }
      break;

    case PROVISION_HANDSHAKE:
      fpi_ssm_start_subsm (ssm, handshake_ssm_new (self));
      break;

    case PROVISION_ERASE:
      fpi_ssm_start_subsm (ssm, flash_erase_ssm_new (self, pairing_erase_order[data->erase_idx]));
      break;

    case PROVISION_ERASE_NEXT:
      if (++data->erase_idx < G_N_ELEMENTS (pairing_erase_order))
        fpi_ssm_jump_to_state (ssm, PROVISION_ERASE);
      else
        fpi_ssm_next_state (ssm);
      break;

    case PROVISION_WRITE_PAIRING:
      {
        g_autoptr(GError) tls_error = NULL;
        g_autoptr(GBytes) flash = validity_tls_build_flash (self->tls, &tls_error);

        if (!flash)
          {
            fpi_ssm_mark_failed (ssm, proto_error_new ("Pairing", tls_error));
            return;
          }
        fpi_ssm_start_subsm (ssm, flash_write_ssm_new (self, VALIDITY_PARTITION_TLS, 0, flash));
      }
      break;

    case PROVISION_FWEXT:
      fpi_ssm_start_subsm (ssm, fwext_ssm_new (self));
      break;

    case PROVISION_RESET:
      /* Restart the sensor so that it boots the new firmware extension. */
      fp_info ("Sensor provisioned, restarting it");
      if (!usb_reset (self, &error))
        fpi_ssm_mark_failed (ssm, error);
      else
        fpi_ssm_next_state (ssm);
      break;
    }
}

static FpiSsm *
provision_ssm_new (FpiDeviceValidity *self)
{
  FpiSsm *ssm = fpi_ssm_new (FP_DEVICE (self), provision_run_state, PROVISION_NUM_STATES);

  fpi_ssm_set_data (ssm, g_new0 (ProvisionData, 1), g_free);
  return ssm;
}

/* ---------------------------------------------------------------------- */
/* Calibration                                                            */
/* ---------------------------------------------------------------------- */

enum {
  CALIBRATE_CAPTURE,
  CALIBRATE_READ_FRAMES,
  CALIBRATE_CHECK_HEADER,
  CALIBRATE_CHECK_PAYLOAD,
  CALIBRATE_VERIFY,
  CALIBRATE_ERASE,
  CALIBRATE_WRITE,
  CALIBRATE_NUM_STATES,
};

typedef struct
{
  guint       iteration;
  GBytes     *clean_slate;
  GByteArray *flash;          /* data read back from the flash */
  guint8      header[VALIDITY_CLEAN_SLATE_HDR_SIZE];
  gboolean    header_blank;
} CalibrateData;

static void
calibrate_data_free (gpointer p)
{
  CalibrateData *data = p;

  g_clear_pointer (&data->clean_slate, g_bytes_unref);
  g_clear_pointer (&data->flash, g_byte_array_unref);
  g_free (data);
}

static void
calibrate_frames_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (dev);
  FpiSsm *ssm = transfer->ssm;
  CalibrateData *data = fpi_ssm_get_data (ssm);
  const ValiditySensorProfile *prof = self->sensor.profile;

  if (error)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  if (transfer->actual_length != transfer->length)
    fp_dbg ("Short calibration data: %" G_GSSIZE_FORMAT " of %" G_GSSIZE_FORMAT " bytes",
            transfer->actual_length, transfer->length);

  if (data->iteration < prof->calibration_iterations)
    {
      fp_dbg ("Calibration iteration %u", data->iteration);
      if (!validity_calibration_process (&self->sensor, transfer->buffer,
                                         transfer->actual_length, &error))
        {
          fpi_ssm_mark_failed (ssm, error);
          return;
        }
      data->iteration++;
      fpi_ssm_jump_to_state (ssm, CALIBRATE_CAPTURE);
      return;
    }

  /* Last round: the "clean slate" reference frame of the calibrated sensor */
  data->clean_slate = validity_calibration_build_clean_slate (&self->sensor, transfer->buffer,
                                                              transfer->actual_length, &error);
  if (!data->clean_slate)
    fpi_ssm_mark_failed (ssm, error);
  else
    fpi_ssm_next_state (ssm);
}

static void
calibrate_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (dev);
  CalibrateData *data = fpi_ssm_get_data (ssm);
  GError *error = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CALIBRATE_CAPTURE:
      {
        g_autoptr(GBytes) cmd = validity_build_capture_cmd (&self->sensor,
                                                            VALIDITY_CAPTURE_CALIBRATE, &error);

        if (!cmd)
          {
            fpi_ssm_mark_failed (ssm, error);
            return;
          }
        send_cmd_bytes (self, ssm, cmd, TRUE, "Calibration capture", NULL);
      }
      break;

    case CALIBRATE_READ_FRAMES:
      {
        FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);

        /* The sensor occasionally ends the stream early (seen right after
         * a firmware restart).  Only the second frame is used, and its
         * presence is checked when processing, so short data is fine. */
        transfer->ssm = ssm;
        fpi_usb_transfer_fill_bulk (transfer, EP_DATA_IN,
                                    validity_calibration_frame_bytes (&self->sensor));
        fpi_usb_transfer_submit (transfer, CMD_TIMEOUT_MS, NULL, calibrate_frames_cb, NULL);
      }
      break;

    case CALIBRATE_CHECK_HEADER:
      fpi_ssm_start_subsm (ssm, flash_read_ssm_new (self, VALIDITY_PARTITION_CALIBRATION, 0,
                                                    VALIDITY_CLEAN_SLATE_HDR_SIZE, data->flash));
      break;

    case CALIBRATE_CHECK_PAYLOAD:
      {
        guint16 payload_len;

        if (data->flash->len != VALIDITY_CLEAN_SLATE_HDR_SIZE)
          {
            fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                                "Short calibration flash read"));
            return;
          }

        memcpy (data->header, data->flash->data, sizeof (data->header));
        data->header_blank = TRUE;
        for (guint i = 0; i < sizeof (data->header); i++)
          data->header_blank &= data->header[i] == 0xff;

        /* A header describing anything but our own format (e.g. a
         * corrupted length) is treated like missing data and rewritten. */
        if (!validity_clean_slate_header_valid (data->header, sizeof (data->header),
                                                &payload_len) ||
            payload_len != validity_clean_slate_payload_size (&self->sensor))
          {
            fp_dbg ("No valid calibration data on the sensor flash");
            fpi_ssm_jump_to_state (ssm, CALIBRATE_ERASE);
            return;
          }

        fpi_ssm_start_subsm (ssm, flash_read_ssm_new (self, VALIDITY_PARTITION_CALIBRATION,
                                                      VALIDITY_CLEAN_SLATE_HDR_SIZE, payload_len,
                                                      data->flash));
      }
      break;

    case CALIBRATE_VERIFY:
      if (validity_clean_slate_payload_valid (data->header, data->flash->data, data->flash->len))
        {
          /* Calibration is reproducible to within a few LSB, so a valid
           * stored reference is kept to avoid needless flash wear. */
          fp_dbg ("Calibration data on the sensor flash is valid");
          fpi_ssm_mark_completed (ssm);
        }
      else
        {
          fp_dbg ("Calibration data on the sensor flash is corrupt");
          fpi_ssm_next_state (ssm);
        }
      break;

    case CALIBRATE_ERASE:
      if (data->header_blank)
        fpi_ssm_next_state (ssm);
      else
        fpi_ssm_start_subsm (ssm, flash_erase_ssm_new (self, VALIDITY_PARTITION_CALIBRATION));
      break;

    case CALIBRATE_WRITE:
      fp_info ("Storing calibration data on the sensor flash");
      fpi_ssm_start_subsm (ssm, flash_write_ssm_new (self, VALIDITY_PARTITION_CALIBRATION, 0,
                                                     data->clean_slate));
      break;
    }
}

static FpiSsm *
calibrate_ssm_new (FpiDeviceValidity *self)
{
  FpiSsm *ssm = fpi_ssm_new (FP_DEVICE (self), calibrate_run_state, CALIBRATE_NUM_STATES);
  CalibrateData *data = g_new0 (CalibrateData, 1);

  data->flash = g_byte_array_new ();
  fpi_ssm_set_data (ssm, data, calibrate_data_free);
  return ssm;
}

/* ---------------------------------------------------------------------- */
/* Open                                                                   */
/* ---------------------------------------------------------------------- */

enum {
  OPEN_ROM_INFO,
  OPEN_RESET_INFO,
  OPEN_FW_INFO_EARLY,
  OPEN_INIT_BLOB,
  OPEN_FLASH_INFO,
  OPEN_READ_PAIRING,
  OPEN_PROVISION,
  OPEN_HANDSHAKE,
  OPEN_FW_INFO,
  OPEN_FWEXT_UPLOAD,
  OPEN_RESTART,
  OPEN_IDENTIFY_SENSOR,
  OPEN_FACTORY_BITS,
  OPEN_CALIBRATE,
  OPEN_NUM_STATES,
};

static void
open_rom_info_done (FpiDeviceValidity *self, FpiSsm *ssm, const guint8 *rsp, gsize len)
{
  GError *error = NULL;

  if (!validity_parse_rom_info (rsp, len, &self->rom, &error))
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  fp_dbg ("ROM %u.%u build 0x%x, product 0x%02x, flags 0x%02x, state %u, patch 0x%04x",
          self->rom.major, self->rom.minor, self->rom.build, self->rom.product,
          self->rom.flags, self->rom.state, self->rom.patch_level);

  /* The vendor driver applies a persistent firmware patch to sensors with
   * an older patch level; that patch is not implemented here. */
  if (self->rom.patch_level != VALIDITY_ROM_PATCH_LEVEL)
    fp_warn ("Sensor ROM patch level 0x%04x differs from the tested 0x%04x",
             self->rom.patch_level, VALIDITY_ROM_PATCH_LEVEL);

  fpi_ssm_next_state (ssm);
}

static void
open_flash_info_done (FpiDeviceValidity *self, FpiSsm *ssm, const guint8 *rsp, gsize len)
{
  GError *error = NULL;

  if (!validity_parse_flash_info (rsp, len, &self->flash, &error))
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  fp_dbg ("Flash %02x:%02x, %u x %u bytes, %u partitions", self->flash.jedec_id0,
          self->flash.jedec_id1, self->flash.blocks, self->flash.blocksize,
          self->flash.n_partitions);

  if (self->flash.n_partitions == 0)
    {
      self->provision = PROVISION_PAIR;
      fpi_ssm_jump_to_state (ssm, OPEN_PROVISION);
      return;
    }

  fpi_ssm_next_state (ssm);
}

static void
open_read_pairing_done (FpiDeviceValidity *self, FpiSsm *ssm, const guint8 *rsp, gsize len)
{
  g_autoptr(GBytes) flash = NULL;
  g_autoptr(GError) tls_error = NULL;
  GError *error = NULL;

  /* Pairing data written by the vendor's SGX based driver can't be read. */
  if (validity_rsp_status (rsp, len) == VALIDITY_STATUS_FLASH_DENIED)
    {
      fp_dbg ("Pairing data is not accessible");
      self->provision = PROVISION_WIPE_AND_PAIR;
      fpi_ssm_next_state (ssm);
      return;
    }

  flash = validity_parse_flash_read (rsp, len, &error);
  if (!flash)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  if (!validity_tls_load_flash (self->tls, g_bytes_get_data (flash, NULL),
                                g_bytes_get_size (flash), &tls_error))
    {
      if (!g_error_matches (tls_error, VALIDITY_TLS_ERROR, VALIDITY_TLS_ERROR_FOREIGN_PAIRING))
        {
          fpi_ssm_mark_failed (ssm, proto_error_new ("Pairing data", tls_error));
          return;
        }

      fp_dbg ("%s", tls_error->message);
      self->provision = PROVISION_WIPE_AND_PAIR;
    }
  else if (!validity_tls_has_pairing (self->tls))
    {
      fp_dbg ("Pairing data is incomplete");
      self->provision = PROVISION_WIPE_AND_PAIR;
    }
  else
    {
      self->provision = PROVISION_NONE;
    }

  fpi_ssm_next_state (ssm);
}

static void
open_fw_info_done (FpiDeviceValidity *self, FpiSsm *ssm, const guint8 *rsp, gsize len)
{
  ValidityFwInfo info;
  GError *error = NULL;

  if (!validity_parse_fw_info (rsp, len, &info, &error))
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  if (!info.present)
    {
      fp_info ("Sensor has no firmware extension");
      fpi_ssm_next_state (ssm);
      return;
    }

  fp_dbg ("Firmware extension %u.%u, build time %u, %u modules", info.major, info.minor,
          info.buildtime, info.n_modules);
  fpi_ssm_jump_to_state (ssm, OPEN_IDENTIFY_SENSOR);
}

static void
open_identify_done (FpiDeviceValidity *self, FpiSsm *ssm, const guint8 *rsp, gsize len)
{
  GError *error = NULL;
  guint16 major, version;

  if (!validity_parse_sensor_id (rsp, len, &major, &version, &error))
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  self->sensor.profile = validity_sensor_profile_lookup (major, version, &self->rom);
  if (!self->sensor.profile || self->rom.product != 0x30)
    {
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                                          "Unsupported sensor %04x:%04x "
                                                          "(ROM %u.%u, product 0x%02x)",
                                                          major, version, self->rom.major,
                                                          self->rom.minor, self->rom.product));
      return;
    }

  fp_info ("Sensor: %s (type 0x%03x)", self->sensor.profile->name,
           self->sensor.profile->sensor_type);
  fpi_ssm_next_state (ssm);
}

static void
open_factory_bits_done (FpiDeviceValidity *self, FpiSsm *ssm, const guint8 *rsp, gsize len)
{
  const ValiditySensorProfile *profile = self->sensor.profile;

  g_autoptr(GBytes) entry = NULL;
  g_autoptr(GBytes) values = NULL;
  GError *error = NULL;

  entry = validity_parse_factory_bits (rsp, len, FACTORY_CALIB_SUBTAG, &error);
  if (!entry)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  if (g_bytes_get_size (entry) <= FACTORY_CALIB_SKIP)
    {
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                          "Short factory calibration entry"));
      return;
    }

  values = g_bytes_new_from_bytes (entry, FACTORY_CALIB_SKIP,
                                   g_bytes_get_size (entry) - FACTORY_CALIB_SKIP);
  if (!validity_sensor_init (&self->sensor, profile, values, &error))
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  fpi_ssm_next_state (ssm);
}

static void
open_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (dev);
  GError *error = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case OPEN_ROM_INFO:
      {
        static const guint8 cmd[] = { VALIDITY_CMD_ROM_INFO };

        send_cmd (self, ssm, cmd, sizeof (cmd), FALSE, "ROM info", open_rom_info_done);
      }
      break;

    case OPEN_RESET_INFO:
      {
        static const guint8 cmd[] = { VALIDITY_CMD_RESET_INFO };

        send_cmd (self, ssm, cmd, sizeof (cmd), FALSE, "Reset info", NULL);
      }
      break;

    case OPEN_FW_INFO_EARLY:
      {
        static const guint8 cmd[] = { VALIDITY_CMD_FW_INFO, VALIDITY_PARTITION_FWEXT };

        send_cmd (self, ssm, cmd, sizeof (cmd), FALSE, "Firmware info", handler_ignore_status);
      }
      break;

    case OPEN_INIT_BLOB:
      send_vendor_blob (self, ssm, VALIDITY_VENDOR_INIT, FALSE, "Sensor init", NULL);
      break;

    case OPEN_FLASH_INFO:
      {
        static const guint8 cmd[] = { VALIDITY_CMD_FLASH_INFO };

        send_cmd (self, ssm, cmd, sizeof (cmd), FALSE, "Flash info", open_flash_info_done);
      }
      break;

    case OPEN_READ_PAIRING:
      {
        g_autoptr(GBytes) cmd = validity_cmd_flash_read (VALIDITY_PARTITION_TLS, 0,
                                                         VALIDITY_TLS_FLASH_SIZE);

        send_cmd_bytes (self, ssm, cmd, FALSE, "Pairing data read", open_read_pairing_done);
      }
      break;

    case OPEN_PROVISION:
      if (self->provision == PROVISION_NONE)
        {
          fpi_ssm_next_state (ssm);
        }
      else if (self->open_restarts >= MAX_OPEN_RESTARTS)
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                              "Sensor provisioning did not succeed"));
        }
      else
        {
          self->open_restarts++;
          fpi_ssm_start_subsm (ssm, provision_ssm_new (self));
        }
      break;

    case OPEN_HANDSHAKE:
      if (self->provision != PROVISION_NONE)
        {
          /* Freshly provisioned and restarted: start over. */
          self->provision = PROVISION_NONE;
          fpi_ssm_jump_to_state (ssm, OPEN_ROM_INFO);
          return;
        }
      fpi_ssm_start_subsm (ssm, handshake_ssm_new (self));
      break;

    case OPEN_FW_INFO:
      {
        static const guint8 cmd[] = { VALIDITY_CMD_FW_INFO, VALIDITY_PARTITION_FWEXT };

        send_cmd (self, ssm, cmd, sizeof (cmd), TRUE, "Firmware info", open_fw_info_done);
      }
      break;

    case OPEN_FWEXT_UPLOAD:
      if (self->open_restarts >= MAX_OPEN_RESTARTS)
        {
          fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                              "Firmware upload did not succeed"));
          return;
        }
      self->open_restarts++;
      fpi_ssm_start_subsm (ssm, fwext_ssm_new (self));
      break;

    case OPEN_RESTART:
      if (!usb_reset (self, &error))
        {
          fpi_ssm_mark_failed (ssm, error);
          return;
        }
      fpi_ssm_jump_to_state (ssm, OPEN_ROM_INFO);
      break;

    case OPEN_IDENTIFY_SENSOR:
      {
        static const guint8 cmd[] = { VALIDITY_CMD_IDENTIFY_SENSOR };

        send_cmd (self, ssm, cmd, sizeof (cmd), TRUE, "Sensor identification",
                  open_identify_done);
      }
      break;

    case OPEN_FACTORY_BITS:
      {
        g_autoptr(GBytes) cmd = validity_cmd_factory_bits (FACTORY_BITS_TAG);

        send_cmd_bytes (self, ssm, cmd, TRUE, "Factory calibration read",
                        open_factory_bits_done);
      }
      break;

    case OPEN_CALIBRATE:
      fpi_ssm_start_subsm (ssm, calibrate_ssm_new (self));
      break;
    }
}

static void
open_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (dev);

  if (error)
    {
      g_usb_device_release_interface (fpi_device_get_usb_device (dev), 0, 0, NULL);
      validity_sensor_clear (&self->sensor);
      validity_tls_reset_session (self->tls);
    }
  else
    {
      fp_info ("Sensor ready");
    }

  fpi_image_device_open_complete (FP_IMAGE_DEVICE (dev), error);
}

static void
dev_open (FpImageDevice *img_dev)
{
  FpDevice *dev = FP_DEVICE (img_dev);
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (img_dev);
  GUsbDevice *usb_dev = fpi_device_get_usb_device (dev);
  const gchar *data_dir = NULL;
  GError *error = NULL;

  /* Emulation (umockdev tests, and recording them on real hardware) uses a
   * fixed host identity and deterministic randomness, so that the secure
   * channel traffic replays byte for byte.  The pairing it creates uses a
   * publicly known identity; opening the sensor normally replaces it. */
  self->test_mode = fpi_device_emulation_mode_enabled (dev);
  if (self->test_mode)
    {
      fp_dbg ("Emulation: using a fixed host identity and deterministic randomness");
      data_dir = g_getenv ("FP_VALIDITY_DATA_DIR");
    }

  g_clear_pointer (&self->tls, validity_tls_free);
  self->tls = validity_tls_new ();
  self->rng_counter = 0;
  if (self->test_mode)
    validity_tls_set_random_func (self->tls, test_random, self);

  g_clear_pointer (&self->vendor, validity_vendor_data_free);
  self->vendor = validity_vendor_data_new (g_usb_device_get_vid (usb_dev),
                                           g_usb_device_get_pid (usb_dev),
                                           data_dir, &error);
  if (!self->vendor || !setup_host_identity (self, &error))
    {
      fpi_image_device_open_complete (img_dev, error);
      return;
    }

  /* A reset clears any secure session left over by a previous user and
   * recovers the sensor from interrupted transfers. */
  if (!usb_reset (self, &error) ||
      !g_usb_device_claim_interface (usb_dev, 0, 0, &error))
    {
      fpi_image_device_open_complete (img_dev, error);
      return;
    }

  self->provision = PROVISION_NONE;
  self->open_restarts = 0;
  self->needs_reconnect = FALSE;
  fpi_ssm_start (fpi_ssm_new (dev, open_run_state, OPEN_NUM_STATES), open_complete);
}

static void
dev_close (FpImageDevice *img_dev)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (img_dev);
  GError *error = NULL;

  validity_sensor_clear (&self->sensor);
  g_clear_pointer (&self->tls, validity_tls_free);
  g_clear_pointer (&self->vendor, validity_vendor_data_free);

  g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (img_dev)), 0, 0, &error);
  fpi_image_device_close_complete (img_dev, error);
}

/* ---------------------------------------------------------------------- */
/* Capture                                                                */
/* ---------------------------------------------------------------------- */

static void start_capture (FpiDeviceValidity *self);
static void start_finger_off (FpiDeviceValidity *self);

static gboolean
check_deactivating (FpiDeviceValidity *self, FpiSsm *ssm)
{
  if (!self->deactivating)
    return FALSE;

  fpi_ssm_mark_failed (ssm, g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                                 "Deactivation requested"));
  return TRUE;
}

static void
capture_finished (FpiDeviceValidity *self, GError *error)
{
  FpImageDevice *img_dev = FP_IMAGE_DEVICE (self);

  self->capture_ssm = NULL;
  g_clear_object (&self->capture_cancel);

  if (self->deactivating)
    {
      if (error && !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        fp_dbg ("Ignoring error during deactivation: %s", error->message);
      g_clear_error (&error);
      self->deactivating = FALSE;
      fpi_image_device_deactivate_complete (img_dev, NULL);
      return;
    }

  if (error)
    {
      /* The sensor may have lost its secure session (e.g. it was power
       * cycled); re-establish it before the next scan. */
      self->needs_reconnect = TRUE;
      fpi_image_device_session_error (img_dev, error);
    }
}

/* --- Finger on: start program, wait for finger + scan, fetch image ------- */

enum {
  CAPTURE_START,
  CAPTURE_WAIT,
  CAPTURE_IMAGE,
  CAPTURE_STOP,          /* cleanup */
  CAPTURE_NUM_STATES,
};

static void
capture_int_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (dev);
  FpiSsm *ssm = transfer->ssm;
  const guint8 *pkt = transfer->buffer;

  if (error)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  if (transfer->actual_length < 3)
    {
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                          "Short interrupt packet"));
      return;
    }

  fp_dbg ("Event %02x %02x %02x", pkt[0], pkt[1], pkt[2]);

  switch (pkt[0])
    {
    case VALIDITY_INT_SCAN_STARTED:
      break;

    case VALIDITY_INT_FINGER_DOWN:
      if (!self->finger_present)
        {
          self->finger_present = TRUE;
          fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (self), TRUE);
        }
      break;

    case VALIDITY_INT_SCAN_PROGRESS:
      if (pkt[2] & VALIDITY_INT_SCAN_COMPLETE_MASK)
        {
          fpi_ssm_next_state (ssm);
          return;
        }
      break;

    default:
      fp_dbg ("Ignoring unknown event 0x%02x", pkt[0]);
    }

  /* Wait for the next event */
  fpi_ssm_jump_to_state (ssm, CAPTURE_WAIT);
}

static void
capture_image_done (FpiDeviceValidity *self, FpiSsm *ssm, const guint8 *rsp, gsize len)
{
  GError *error = NULL;

  g_clear_pointer (&self->image.pixels, g_free);
  if (!validity_parse_image (rsp, len, &self->image, &error))
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  /* Image preparation and the matching parameters assume this size */
  if (self->image.width != VALIDITY_IMAGE_SIZE || self->image.height != VALIDITY_IMAGE_SIZE)
    {
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                          "Unexpected image size %ux%u",
                                                          self->image.width,
                                                          self->image.height));
      return;
    }

  fpi_ssm_next_state (ssm);
}

static void
capture_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (dev);
  GError *error = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CAPTURE_START:
      {
        g_autoptr(GBytes) cmd = NULL;

        if (check_deactivating (self, ssm))
          return;

        /* Enroll and verify images must come from the same program: the
         * vendor "enroll" program uses different image reconstruction
         * settings, and such images match poorly against identify ones. */
        cmd = validity_build_capture_cmd (&self->sensor, VALIDITY_CAPTURE_IDENTIFY, &error);
        if (!cmd)
          {
            fpi_ssm_mark_failed (ssm, error);
            return;
          }
        send_cmd_bytes (self, ssm, cmd, TRUE, "Capture start", NULL);
      }
      break;

    case CAPTURE_WAIT:
      {
        FpiUsbTransfer *transfer;

        if (check_deactivating (self, ssm))
          return;

        transfer = fpi_usb_transfer_new (dev);
        transfer->ssm = ssm;
        fpi_usb_transfer_fill_interrupt (transfer, EP_INT_IN, INT_PKT_MAX);
        fpi_usb_transfer_submit (transfer, 0, self->capture_cancel, capture_int_cb, NULL);
      }
      break;

    case CAPTURE_IMAGE:
      {
        g_autoptr(GBytes) cmd = validity_cmd_get_data (IMAGE_MAX);

        send_cmd_bytes (self, ssm, cmd, TRUE, "Image read", capture_image_done);
      }
      break;

    case CAPTURE_STOP:
      {
        static const guint8 cmd[] = { VALIDITY_CMD_CAPTURE_STOP };

        send_cmd (self, ssm, cmd, sizeof (cmd), TRUE, "Capture stop", handler_ignore_status);
      }
      break;
    }
}

static void
capture_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (dev);
  FpImageDevice *img_dev = FP_IMAGE_DEVICE (dev);
  ValidityImage image = self->image;

  memset (&self->image, 0, sizeof (self->image));

  if (!error && !self->deactivating)
    {
      g_autofree guint8 *prepared = NULL;
      guint width, height;
      FpImage *img;

      prepared = validity_image_prepare (image.pixels, image.width, image.height,
                                         VALIDITY_IMAGE_SCALE, VALIDITY_IMAGE_PAD,
                                         &width, &height);
      explicit_bzero (image.pixels, (gsize) image.width * image.height);
      g_free (image.pixels);

      img = fp_image_new (width, height);
      memcpy (img->data, prepared, (gsize) width * height);
      explicit_bzero (prepared, (gsize) width * height);
      /* Drop minutiae on the perimeter of the print area */
      img->flags = FPI_IMAGE_PARTIAL;

      self->capture_ssm = NULL;
      g_clear_object (&self->capture_cancel);
      fp_dbg ("Image captured");
      fpi_image_device_image_captured (img_dev, img);
      return;
    }

  if (image.pixels)
    explicit_bzero (image.pixels, (gsize) image.width * image.height);
  g_free (image.pixels);
  capture_finished (self, error);
}

static void
start_capture (FpiDeviceValidity *self)
{
  g_assert (self->capture_ssm == NULL);

  self->finger_present = FALSE;
  self->capture_cancel = g_cancellable_new ();
  self->capture_ssm = fpi_ssm_new_full (FP_DEVICE (self), capture_run_state,
                                        CAPTURE_NUM_STATES, CAPTURE_STOP, "CAPTURE");
  fpi_ssm_start (self->capture_ssm, capture_complete);
}

/* --- Finger off: re-arm the capture program and watch for finger down --- */

/*
 * Finger detection is level triggered: a freshly armed capture program
 * reports "finger down" within a few ms while a finger rests on the sensor.
 * A detected scan must be allowed to complete and its image must be read:
 * aborting a scan in progress leaves the detector latched, after which
 * every new program reports a finger even when there is none.
 */
enum {
  FINGER_OFF_START,
  FINGER_OFF_WAIT,
  FINGER_OFF_DRAIN,
  FINGER_OFF_STOP,
  FINGER_OFF_DECIDE,
  FINGER_OFF_NUM_STATES,
};

#define FINGER_OFF_SCAN_TIMEOUT_MS 1000

typedef struct
{
  gint64   deadline;   /* monotonic time in us */
  gboolean present;
} FingerOffData;

static void
finger_off_int_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  FpiSsm *ssm = transfer->ssm;
  FingerOffData *data = fpi_ssm_get_data (ssm);
  const guint8 *pkt = transfer->buffer;

  /* No finger within the window, or a detected scan that did not finish
   * in time (the finger then counts as still present).  umockdev replays
   * the timed out, canceled transfer as an empty completion. */
  if (g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT) ||
      (!error && fpi_device_emulation_mode_enabled (dev) && transfer->actual_length == 0))
    {
      g_clear_error (&error);
      fpi_ssm_jump_to_state (ssm, FINGER_OFF_STOP);
      return;
    }

  if (error)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  if (transfer->actual_length < 3)
    {
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                          "Short interrupt packet"));
      return;
    }

  if (pkt[0] == VALIDITY_INT_FINGER_DOWN && !data->present)
    {
      data->present = TRUE;
      data->deadline = g_get_monotonic_time () + FINGER_OFF_SCAN_TIMEOUT_MS * 1000;
    }
  else if (pkt[0] == VALIDITY_INT_SCAN_PROGRESS && (pkt[2] & VALIDITY_INT_SCAN_COMPLETE_MASK))
    {
      fpi_ssm_jump_to_state (ssm, FINGER_OFF_DRAIN);
      return;
    }

  fpi_ssm_jump_to_state (ssm, FINGER_OFF_WAIT);
}

static void
finger_off_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (dev);
  FingerOffData *data = fpi_ssm_get_data (ssm);
  GError *error = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case FINGER_OFF_START:
      {
        g_autoptr(GBytes) cmd = NULL;

        if (check_deactivating (self, ssm))
          return;

        cmd = validity_build_capture_cmd (&self->sensor, VALIDITY_CAPTURE_IDENTIFY, &error);
        if (!cmd)
          {
            fpi_ssm_mark_failed (ssm, error);
            return;
          }
        data->present = FALSE;
        data->deadline = g_get_monotonic_time () + FINGER_OFF_WINDOW_MS * 1000;
        send_cmd_bytes (self, ssm, cmd, TRUE, "Finger detection start", NULL);
      }
      break;

    case FINGER_OFF_WAIT:
      {
        gint64 remaining = (data->deadline - g_get_monotonic_time ()) / 1000;
        FpiUsbTransfer *transfer;

        if (check_deactivating (self, ssm))
          return;

        if (remaining <= 0)
          {
            fpi_ssm_jump_to_state (ssm, FINGER_OFF_STOP);
            return;
          }

        transfer = fpi_usb_transfer_new (dev);
        transfer->ssm = ssm;
        fpi_usb_transfer_fill_interrupt (transfer, EP_INT_IN, INT_PKT_MAX);
        fpi_usb_transfer_submit (transfer, remaining, self->capture_cancel,
                                 finger_off_int_cb, NULL);
      }
      break;

    case FINGER_OFF_DRAIN:
      {
        g_autoptr(GBytes) cmd = validity_cmd_get_data (IMAGE_MAX);

        send_cmd_bytes (self, ssm, cmd, TRUE, "Image read", handler_ignore_status);
      }
      break;

    case FINGER_OFF_STOP:
      {
        static const guint8 cmd[] = { VALIDITY_CMD_CAPTURE_STOP };

        send_cmd (self, ssm, cmd, sizeof (cmd), TRUE, "Finger detection stop",
                  handler_ignore_status);
      }
      break;

    case FINGER_OFF_DECIDE:
      if (check_deactivating (self, ssm))
        return;

      if (data->present)
        fpi_ssm_jump_to_state_delayed (ssm, FINGER_OFF_START, FINGER_OFF_RETRY_MS);
      else
        fpi_ssm_next_state (ssm);
      break;
    }
}

static void
finger_off_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (dev);

  if (!error && !self->deactivating)
    {
      self->capture_ssm = NULL;
      g_clear_object (&self->capture_cancel);
      self->finger_present = FALSE;
      fp_dbg ("Finger removed");
      fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), FALSE);
      return;
    }

  capture_finished (self, error);
}

static void
start_finger_off (FpiDeviceValidity *self)
{
  FpiSsm *ssm;

  g_assert (self->capture_ssm == NULL);

  self->capture_cancel = g_cancellable_new ();
  ssm = fpi_ssm_new_full (FP_DEVICE (self), finger_off_run_state, FINGER_OFF_NUM_STATES,
                          FINGER_OFF_STOP, "FINGER_OFF");
  fpi_ssm_set_data (ssm, g_new0 (FingerOffData, 1), g_free);
  self->capture_ssm = ssm;
  fpi_ssm_start (ssm, finger_off_complete);
}

/* --- Reconnect: restart the sensor and re-establish the secure channel ---- */

enum {
  RECONNECT_RESET,
  RECONNECT_ROM_INFO,
  RECONNECT_INIT_BLOB,
  RECONNECT_HANDSHAKE,
  RECONNECT_NUM_STATES,
};

static void
reconnect_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (dev);
  GError *error = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case RECONNECT_RESET:
      fp_info ("Re-establishing the secure session with the sensor");
      if (!usb_reset (self, &error))
        fpi_ssm_mark_failed (ssm, error);
      else
        fpi_ssm_next_state (ssm);
      break;

    case RECONNECT_ROM_INFO:
      {
        static const guint8 cmd[] = { VALIDITY_CMD_ROM_INFO };

        send_cmd (self, ssm, cmd, sizeof (cmd), FALSE, "ROM info", open_rom_info_done);
      }
      break;

    case RECONNECT_INIT_BLOB:
      send_vendor_blob (self, ssm, VALIDITY_VENDOR_INIT, FALSE, "Sensor init", NULL);
      break;

    case RECONNECT_HANDSHAKE:
      fpi_ssm_start_subsm (ssm, handshake_ssm_new (self));
      break;
    }
}

static void
reconnect_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (dev);

  if (!error)
    self->needs_reconnect = FALSE;

  fpi_image_device_activate_complete (FP_IMAGE_DEVICE (dev), error);
}

/* --- Image device glue ---------------------------------------------------- */

static void
dev_activate (FpImageDevice *img_dev)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (img_dev);

  self->deactivating = FALSE;

  if (self->needs_reconnect)
    {
      fpi_ssm_start (fpi_ssm_new (FP_DEVICE (img_dev), reconnect_run_state, RECONNECT_NUM_STATES),
                     reconnect_complete);
      return;
    }

  fpi_image_device_activate_complete (img_dev, NULL);
}

static void
dev_change_state (FpImageDevice *img_dev, FpiImageDeviceState state)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (img_dev);

  switch (state)
    {
    case FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON:
      start_capture (self);
      break;

    case FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_OFF:
      start_finger_off (self);
      break;

    case FPI_IMAGE_DEVICE_STATE_INACTIVE:
    case FPI_IMAGE_DEVICE_STATE_ACTIVATING:
    case FPI_IMAGE_DEVICE_STATE_DEACTIVATING:
    case FPI_IMAGE_DEVICE_STATE_IDLE:
    case FPI_IMAGE_DEVICE_STATE_CAPTURE:
      break;
    }
}

static void
dev_deactivate (FpImageDevice *img_dev)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (img_dev);

  if (!self->capture_ssm)
    {
      fpi_image_device_deactivate_complete (img_dev, NULL);
      return;
    }

  self->deactivating = TRUE;
  g_cancellable_cancel (self->capture_cancel);
}

/* ---------------------------------------------------------------------- */
/* Class                                                                  */
/* ---------------------------------------------------------------------- */

static const FpIdEntry id_table[] = {
  { .vid = 0x06cb, .pid = 0x00a2 },
  { .vid = 0,      .pid = 0 },
};

static void
fpi_device_validity_init (FpiDeviceValidity *self)
{
}

static void
fpi_device_validity_finalize (GObject *object)
{
  FpiDeviceValidity *self = FPI_DEVICE_VALIDITY (object);

  validity_sensor_clear (&self->sensor);
  g_clear_pointer (&self->tls, validity_tls_free);
  g_clear_pointer (&self->vendor, validity_vendor_data_free);
  g_clear_pointer (&self->image.pixels, g_free);
  g_clear_object (&self->capture_cancel);

  G_OBJECT_CLASS (fpi_device_validity_parent_class)->finalize (object);
}

static void
fpi_device_validity_class_init (FpiDeviceValidityClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  FpImageDeviceClass *img_class = FP_IMAGE_DEVICE_CLASS (klass);

  object_class->finalize = fpi_device_validity_finalize;

  dev_class->id = "validity";
  dev_class->full_name = "Synaptics Metallica match-on-host sensor (VSI)";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = VALIDITY_ENROLL_STAGES;

  img_class->img_open = dev_open;
  img_class->img_close = dev_close;
  img_class->activate = dev_activate;
  img_class->change_state = dev_change_state;
  img_class->deactivate = dev_deactivate;

  img_class->img_width = VALIDITY_IMAGE_SIZE * VALIDITY_IMAGE_SCALE + 2 * VALIDITY_IMAGE_PAD;
  img_class->img_height = VALIDITY_IMAGE_SIZE * VALIDITY_IMAGE_SCALE + 2 * VALIDITY_IMAGE_PAD;
  img_class->bz3_threshold = VALIDITY_BZ3_THRESHOLD;
}
