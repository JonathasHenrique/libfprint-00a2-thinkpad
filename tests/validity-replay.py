#!/usr/bin/env python3
#
# Runs the umockdev replay test of the "validity" driver.
#
# The driver sends a vendor-signed init blob on every open. The blob is not
# redistributable, so the recording in tests/validity contains a placeholder
# of the same length instead. This script copies the test data into a
# temporary directory, puts the blob from the installed (or extracted) vendor
# data in place of the placeholder and runs the test there. The test is
# skipped if the vendor data is not available.
#
# After re-recording the test, run
#   validity-replay.py --strip tests/validity/custom.pcapng <vendor data dir>
# to replace the blob in the new recording with the placeholder.

import os
import shutil
import subprocess
import sys
import tempfile

PLACEHOLDER = (b'VALIDITY INIT BLOB PLACEHOLDER ' * 40)[:581]
SKIP = 77


def read_init_blob(data_dir):
    path = os.path.join(data_dir, '06cb-00a2', 'init.bin')
    with open(path, 'rb') as f:
        blob = f.read()
    if len(blob) != len(PLACEHOLDER):
        sys.exit('%s has an unexpected size' % path)
    return blob


def strip(pcap, data_dir):
    init_blob = read_init_blob(data_dir)
    with open(pcap, 'rb') as f:
        recording = f.read()
    if recording.count(init_blob) != 1:
        sys.exit('%s does not contain the init blob exactly once' % pcap)
    with open(pcap, 'wb') as f:
        f.write(recording.replace(init_blob, PLACEHOLDER))


if sys.argv[1] == '--strip':
    strip(*sys.argv[2:4])
    sys.exit(0)

umockdev_test, test_dir, default_data_dir = sys.argv[1:4]

data_dir = os.environ.get('FP_VALIDITY_DATA_DIR', default_data_dir)
try:
    init_blob = read_init_blob(data_dir)
except FileNotFoundError:
    print('No vendor data in %s, skipping test. Run '
          'scripts/validity-extract-vendor-data.py or set FP_VALIDITY_DATA_DIR.' % data_dir)
    sys.exit(SKIP)

with tempfile.TemporaryDirectory(prefix='libfprint-validity-replay-') as tmpdir:
    ddir = os.path.join(tmpdir, 'validity')
    shutil.copytree(test_dir, ddir)

    pcap = os.path.join(ddir, 'custom.pcapng')
    with open(pcap, 'rb') as f:
        recording = f.read()
    if recording.count(PLACEHOLDER) != 1:
        sys.exit('%s does not contain the init blob placeholder' % pcap)
    with open(pcap, 'wb') as f:
        f.write(recording.replace(PLACEHOLDER, init_blob))

    env = dict(os.environ, FP_VALIDITY_DATA_DIR=data_dir)
    sys.exit(subprocess.call([sys.executable, umockdev_test, ddir, '--test', 'custom'],
                             env=env))
