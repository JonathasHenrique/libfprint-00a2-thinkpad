#!/usr/bin/env python3
#
# Extract the vendor data needed by the libfprint "validity" driver from the
# vendor's Windows driver package.
#
# Copyright (C) 2026 Aurel Farkasovsky
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# The Synaptics 06cb:00a2 sensor only accepts certain commands together with
# vendor-signed blobs, and it runs a vendor-signed firmware extension.  These
# are not redistributable, so this script takes them from Lenovo's driver
# package (r0yfp10w.exe, Synaptics driver 5.2.326.26).  Every input and output
# is verified against a pinned SHA-256 digest.
#
# Requires: innoextract

"""Extract the vendor data of the libfprint "validity" driver (Synaptics
06cb:00a2) from Lenovo's driver package r0yfp10w.exe, verify it and install
it into the driver's data directory."""

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request

INSTALLER_URL = 'https://download.lenovo.com/pccbbs/mobiles/r0yfp10w.exe'
INSTALLER_SHA256 = '760c405f4f173abdf196cf1a3011f7147dea88c2177855f768efdeea254866bf'

DLL_NAME = 'synaWudfBioUsb.dll'
DLL_SHA256 = '16f066d11a83b45d6d052042949a3d2ba8916d5afe35b96365facf7971a44d56'
FWEXT_NAME = '6_07f_lenovo_sm_qm.xpfwext'

DEVICE_DIR = '06cb-00a2'

# (output file, source, file offset in the DLL, length, prefix, SHA-256)
# Command blobs are stored without their 0x06 opcode in the DLL.
OUTPUTS = [
    ('init.bin', DLL_NAME, 0x16f240, 0x244, b'\x06',
     '0f3128a1c93b49f0a5162bbad26b22ae02f539ab0668678ea090449922e39674'),
    ('reset.bin', DLL_NAME, 0x16f490, 0x2ec4, b'\x06',
     '1a43ff9949f64f71e9b62003015b6101a3d36a8442e52fd0d58cb12964b0e706'),
    ('db-write-enable.bin', DLL_NAME, 0x172360, 0xa84, b'\x06',
     'cd3fe4e0b3be7af277dceb040bddf53bf001e0dcfffa912c9cd67b2b9c34e371'),
    ('partition-signature.bin', DLL_NAME, 0x1b4560, 0x100, b'',
     '8389426fc0cfa3d75cf79ee3d93ba21e43e2a8b606202f084d55446bc846bbdb'),
    (FWEXT_NAME, FWEXT_NAME, 0, None, b'',
     'ad14dddb5914cad8fa9f6a2a29120c152476bdac10c735beadbc15e9c2e05ba6'),
]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def fail(msg):
    print('error: ' + msg, file=sys.stderr)
    sys.exit(1)


def get_installer(path, workdir):
    if path:
        with open(path, 'rb') as f:
            data = f.read()
    else:
        print('Downloading %s' % INSTALLER_URL)
        with urllib.request.urlopen(INSTALLER_URL, timeout=120) as r:
            data = r.read()
        path = os.path.join(workdir, os.path.basename(INSTALLER_URL))
        with open(path, 'wb') as f:
            f.write(data)

    if sha256(data) != INSTALLER_SHA256:
        fail('%s is not the expected driver package (SHA-256 %s)' % (path, sha256(data)))
    return path


def find_file(root, name):
    for dirpath, _, files in os.walk(root):
        if name in files:
            return os.path.join(dirpath, name)
    fail('%s not found in the driver package' % name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--installer', help='local copy of r0yfp10w.exe (downloaded otherwise)')
    parser.add_argument('--destdir', default='/usr/share/libfprint-2/validity',
                        help='vendor data directory (default: %(default)s)')
    args = parser.parse_args()

    if not shutil.which('innoextract'):
        fail('innoextract is required')

    with tempfile.TemporaryDirectory() as workdir:
        installer = get_installer(args.installer, workdir)
        extract_dir = os.path.join(workdir, 'extracted')
        subprocess.run(['innoextract', '--silent', '--output-dir', extract_dir, installer],
                       check=True)

        sources = {}
        for name, digest in ((DLL_NAME, DLL_SHA256), (FWEXT_NAME, None)):
            with open(find_file(extract_dir, name), 'rb') as f:
                sources[name] = f.read()
            if digest and sha256(sources[name]) != digest:
                fail('unexpected %s (SHA-256 %s)' % (name, sha256(sources[name])))

        outputs = {}
        for out, src, offset, length, prefix, digest in OUTPUTS:
            data = sources[src]
            data = prefix + (data[offset:offset + length] if length is not None else data)
            if sha256(data) != digest:
                fail('extracted %s does not match (SHA-256 %s)' % (out, sha256(data)))
            outputs[out] = data

    dest = os.path.join(args.destdir, DEVICE_DIR)
    os.makedirs(dest, exist_ok=True)
    for name, data in outputs.items():
        path = os.path.join(dest, name)
        tmp = path + '.tmp'
        with open(tmp, 'wb') as f:
            f.write(data)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
        print('Installed %s' % path)


if __name__ == '__main__':
    main()
