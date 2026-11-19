#!/usr/bin/env python3

import sys
import traceback
import gi

gi.require_version('FPrint', '2.0')
from gi.repository import FPrint, GLib

# Exit with error on any exception, included those happening in async callbacks
sys.excepthook = lambda *args: (traceback.print_exception(*args), sys.exit(1))

# Run through tests/validity-replay.py, which provides the vendor init blob.
# In emulation mode the driver uses a fixed host identity and deterministic
# randomness, so the secure channel traffic replays byte for byte.

c = FPrint.Context()
c.enumerate()
devices = c.get_devices()

d = devices[0]
del devices

assert d.get_driver() == "validity"
assert d.has_feature(FPrint.DeviceFeature.CAPTURE)
assert d.has_feature(FPrint.DeviceFeature.VERIFY)
assert d.has_feature(FPrint.DeviceFeature.IDENTIFY)
assert not d.has_feature(FPrint.DeviceFeature.STORAGE)
assert d.get_nr_enroll_stages() == 15

d.open_sync()

print("Capturing image, place finger on the sensor")
img = d.capture_sync(True)
print("Image captured")

# 112x112 sensor image, upscaled 2x and padded by 16 pixels on each side
assert img.get_width() == 256
assert img.get_height() == 256
data = img.get_data()
assert len(data) == 256 * 256
assert max(data) - min(data) > 64, "image has no contrast"

d.close_sync()
del d
del c
