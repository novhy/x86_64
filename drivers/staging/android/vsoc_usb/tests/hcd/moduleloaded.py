# preliminary tests after host controller is loaded.
# Licensed under the terms of the GNU GPL 2.
#
# Copyright (C) 2017 Google, Inc.
#

import kmod
import os
import sys
import unittest

class TestModuleLoading(unittest.TestCase):
    def setUp(self):
        self.km = kmod.Kmod()

    def test_isModuleLoaded(self):
        found = False
        for module in self.km.loaded():
            if module.name == TestModuleLoading.name:
                found = True
        self.assertEqual(found, True)

    def test_PlatformDeviceRegistered(self):
        self.assertEqual(os.path.isdir('/sys/devices/platform/vsoc_usb_hcd.0'), True)

    def test_PlatformDriverRegistered(self):
        self.assertEqual(os.path.isdir('/sys/bus/platform/drivers/vsoc_usb_hcd'), True)

    # Root hub should be at bus 0 and has only a single port
    def test_RootHubStarted(self):
       self.assertEqual(os.path.isdir('/sys/bus/usb/devices/1-0:1.0'), True)

    def tearDown(self):
        pass

if __name__ == '__main__':
    TestModuleLoading.name = "vsoc_usb_hcd"
    unittest.main()
