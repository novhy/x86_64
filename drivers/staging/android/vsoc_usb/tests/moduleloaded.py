# preliminary tests after gadget controller is loaded.
# Licensed under the terms of the GNU GPL 2.
#
# Copyright (C) 2017 Google, Inc.
#

import kmod
import os
import sys
import unittest

#
# We need libcomposite, configfs, udc_core kernel modules.
# The setup script will modprobe libcomposite and that will indirectly satisfy
# the other module dependencies.
#

class TestModuleLoading(unittest.TestCase):
    def setUp(self):
        self.km = kmod.Kmod()

    #
    # There are few different ways to do this.
    # One could look into /sys/module/vsoc_usb_gadget
    # Here I have chosen to look into /sys/devices/...
    #
    def test_isModuleLoaded(self):
        found = False
        for module in self.km.loaded():
            if module.name == TestModuleLoading.name:
                found = True
        self.assertEqual(found, True)

    def test_libcomposite_loaded(self):
        self.assertEqual(os.path.isdir('/sys/kernel/config/usb_gadget'), True)

    def test_PlatformDeviceRegistered(self):
        self.assertEqual(os.path.isdir('/sys/devices/platform/vsoc_usb_udc.0'), True)

    def test_PlatformDriverRegistered(self):
        self.assertEqual(os.path.isdir('/sys/bus/platform/drivers/vsoc_usb_udc'), True)

    def test_UDCRegistered(self):
       self.assertEqual(os.path.isdir('/sys/devices/platform/vsoc_usb_udc.0/udc'), True)

    def test_VSOC_Is_GadgetDevice(self):
       self.assertEqual(os.path.isdir('/sys/devices/platform/vsoc_usb_udc.0/udc/vsoc_usb_udc.0'), True)

    def test_gadgetRegistered(self):
       self.assertEqual(os.path.isdir('/sys/devices/platform/vsoc_usb_udc.0/gadget'), True)
       self.assertEqual(os.path.exists('/sys/devices/platform/vsoc_usb_udc.0/gadget/function'), True)

    def tearDown(self):
        pass

if __name__ == '__main__':
    TestModuleLoading.name = "vsoc_usb_gadget"
    unittest.main()
