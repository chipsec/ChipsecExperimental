# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# Contact information:
# chipsec@intel.com

"""
Abstracts support for various OS/environments, wrapper around platform specific code that invokes kernel driver
"""

import importlib
import platform
import os
import sys
import traceback

from chipsec.file import get_main_dir
from chipsec.logger import logger
from chipsec.helper.basehelper import Helper


# OS Helper
#
# Abstracts support for various OS/environments, wrapper around platform specific code that invokes kernel driver
class OsHelper:
    def __init__(self):
        self.helper = Helper()
        self.avail_helpers = {}
        self.loadHelpers()
        self.filecmds = None

    def getBaseHelper(self):
        return Helper()

    def loadHelpers(self):
        helper_dir = os.path.join(get_main_dir(), "chipsec", "helper")
        helpers = [os.path.basename(f) for f in os.scandir(helper_dir)
                   if f.is_dir() and not os.path.basename(f).startswith("__")]

        for helper in helpers:
            try:
                helper_path = 'chipsec.helper.{}.{}helper'.format(helper, helper)
                hlpr = importlib.import_module(helper_path)
                self.avail_helpers["{}helper".format(helper)] = hlpr
            except ImportError as msg:
                logger().log_debug("unable to load {} {}".format(helper_path, msg))

    def getHelper(self, name):
        ret = None
        if name in self.avail_helpers:
            ret = self.avail_helpers[name].get_helper()
        return ret

    def getAvailableHelpers(self):
        return self.avail_helpers.keys()

    def getDefaultHelper(self):
        ret = None
        if self.is_linux():
            ret = self.getHelper('linuxhelper')
            if ret is None:
                ret = self.getHelper('linuxnativehelper')
        if self.is_windows():
            ret = self.getHelper('windowshelper')
            if ret is None:
                ret = self.getHelper('windowsnativehelper')
        if ret is None:
            ret = self.getBaseHelper()
        return ret

    def is_dal(self):
        return ('itpii' in sys.modules)

    def is_efi(self):
        return platform.system().lower().startswith('efi') or platform.system().lower().startswith('uefi')

    def is_linux(self):
        return platform.system().lower() == 'linux'

    def is_windows(self):
        return platform.system().lower() == 'windows'


_helper = None


def helper():
    global _helper
    if _helper is None:
        try:
            _helper = OsHelper()
        except BaseException as msg:
            logger().log_debug(str(msg))
            logger().log_debug(traceback.format_exc())
            raise
    return _helper
