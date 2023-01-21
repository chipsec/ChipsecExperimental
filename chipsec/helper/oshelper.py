# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# Contact information:
# chipsec@intel.com
#

"""
Abstracts support for various OS/environments, wrapper around platform specific code that invokes kernel driver
"""

import os
import re
import errno
import traceback
import sys
from ctypes import Array
from typing import Tuple, List, Optional

import chipsec.file
from chipsec.logger import logger
from chipsec.exceptions import UnimplementedAPIError, OsHelperError

import importlib
import platform
from chipsec.file import get_main_dir
from chipsec.helper.basehelper import Helper


ZIP_HELPER_RE = re.compile("^chipsec\/helper\/\w+\/\w+\.pyc$", re.IGNORECASE)


def f_mod_zip(x: str):
    return (x.find('__init__') == -1 and ZIP_HELPER_RE.match(x))


def map_modname_zip(x: str) -> str:
    return (x.rpartition('.')[0]).replace('/', '.')


def get_tools_path() -> str:
    return os.path.normpath(os.path.join(chipsec.file.get_main_dir(), chipsec.file.TOOLS_DIR))


# OS Helper
#
# Abstracts support for various OS/environments, wrapper around platform specific code that invokes kernel driver


class OsHelper:
    def __init__(self):
        self.helper = Helper()
        self.avail_helpers = {}
        self.loadHelpers()
        self.filecmds = None
        self.getDefaultHelper()
        if (not self.helper):
            import platform
            os_system = platform.system()
            raise OsHelperError("Could not load any helpers for '{}' environment (unsupported environment?)".format(os_system), errno.ENODEV)
        else:
            if sys.version[0] == "2":
                logger().log_warning("*****************************************************************************")
                logger().log_warning("* !! Python 2 is deprecated and not supported. Please update to Python 3 !! *")
                logger().log_warning("* !!                           Exiting CHIPSEC                           !! *")
                logger().log_warning("*****************************************************************************")
                sys.exit(0)
            self.os_system = self.helper.os_system
            self.os_release = self.helper.os_release
            self.os_version = self.helper.os_version
            self.os_machine = self.helper.os_machine

    def loadHelpers(self) -> None:
        helper_dir = os.path.join(get_main_dir(), "chipsec", "helper")
        helpers = [os.path.basename(f) for f in os.scandir(helper_dir)
                   if f.is_dir() and not os.path.basename(f).startswith("__")]

        for helper in helpers:
            helper_path = ''
            try:
                helper_path = f'chipsec.helper.{helper}.{helper}helper'
                hlpr = importlib.import_module(helper_path)
                self.avail_helpers["{}helper".format(helper)] = hlpr
            except ImportError as msg:
                logger().log_debug(f'unable to load {helper_path} {msg}')

    def getHelper(self, name):
        ret = None
        if name in self.avail_helpers:
            ret = self.avail_helpers[name].get_helper()
        return ret

    def getAvailableHelpers(self):
        return self.avail_helpers.keys()

    def getBaseHelper(self):
        return Helper()

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

    def is_dal(self) -> bool:
        return 'itpii' in sys.modules

    def is_efi(self) -> bool:
        return platform.system().lower().startswith('efi') or platform.system().lower().startswith('uefi')

    def is_linux(self) -> bool:
        return 'linux' == platform.system().lower()

    def is_windows(self) -> bool:
        return 'windows' == platform.system().lower()

    def is_win8_or_greater(self) -> bool:
        win8_or_greater = self.is_windows() and (self.os_release.startswith('8') or ('2008Server' in self.os_release) or ('2012Server' in self.os_release))
        return win8_or_greater

    def is_macos(self) -> bool:
        return 'darwin' == platform.system().lower()


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
