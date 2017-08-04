#
# This tests if a function(gadget driver) has bound to the gadget controller
# driver.
#
# Licensed under the terms of the GNU GPL 2.
#
# Copyright (C) 2017 Google, Inc.
#

import os
import sys
import unittest

class GadgetControllerDriver(unittest.TestCase):
    def setUp(self):
        pass

    def test_GadetDriverAttached(self):
        f = open('/sys/devices/platform/vsoc_usb_udc.0/gadget/function')
        content = f.read()
        self.assertEqual(content.startswith('g1'), True)
        f.close()

    def tearDown(self):
        pass

if __name__ == '__main__':
    unittest.main()
