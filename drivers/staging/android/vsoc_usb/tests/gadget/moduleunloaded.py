# Preliminary tests after the gadget controller is unloaded.
#
# Licensed under the terms of the GNU GPL 2.
#
# Copyright (C) 2017 Google, Inc.
#

import kmod
import os
import sys
import unittest

#
# TODO(romitd):
# Cleanup the USB configuration, configfs entries.
#
class TestModuleLoading(unittest.TestCase):
    def setUp(self):
        self.km = kmod.Kmod()

    #
    # There are few different ways to do this.
    # One could look into /sys/module/vsoc_usb_gadget
    # Here I have chosen to look into /sys/devices/...
    #
    def test_isModuleUnLoaded(self):
        notFound = True
        for module in self.km.loaded():
            if module.name == TestModuleLoading.name:
                notFound = False
        self.assertEqual(notFound, True)

    def test_PlatformDeviceUnRegistered(self):
        self.assertEqual(os.path.isdir('/sys/devices/platform/vsoc_usb_udc.0'), False)

    def test_PlatformDriverUnRegistered(self):
        self.assertEqual(os.path.isdir('/sys/bus/platform/drivers/vsoc_usb_udc'), False)

    def tearDown(self):
        pass

if __name__ == '__main__':
    TestModuleLoading.name = "vsoc_usb_gadget"
    unittest.main()
