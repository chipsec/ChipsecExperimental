# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2020, Intel Corporation
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
Checks for BIOS Interface Lock including Top Swap Mode

References:
    - `BIOS Boot Hijacking and VMware Vulnerabilities Digging <http://powerofcommunity.net/poc2007/sunbing.pdf>`_ by Bing Sun

Usage:
    ``chipsec_main -m common.bios_ts``

Examples:
    >>> chipsec_main.py -m common.bios_ts

Registers used:
    - BiosInterfaceLockDown (control)
    - TopSwapStatus (control)
    - TopSwap (control)

"""

from chipsec.module_common import BaseModule, ModuleResult, MTAG_BIOS
TAGS = [MTAG_BIOS]


class bios_ts(BaseModule):
    def __init__(self):
        super(bios_ts, self).__init__()

    def is_supported(self):
        if self.cs.Cfg.is_control_defined('BiosInterfaceLockDown'):
            return True
        self.logger.log_important('BiosInterfaceLockDown control not defined for platform.  Skipping module.')
        self.res = ModuleResult.NOTAPPLICABLE
        return False

    def check_bios_iface_lock(self):
        bild = self.cs.get_control('BiosInterfaceLockDown', with_print=self.logger.VERBOSE)

        if self.cs.Cfg.is_control_defined('TopSwapStatus'):
            _ = self.cs.get_control('TopSwapStatus', with_print=self.logger.VERBOSE)

        if self.cs.Cfg.is_control_defined('TopSwap'):
            _ = self.cs.get_control('TopSwap', with_print=self.logger.VERBOSE)

        if self.cs.is_any_value(bild, 0):
            res = ModuleResult.FAILED
            self.logger.log_failed("BIOS Interface is not locked (including Top Swap Mode)")
        else:
            res = ModuleResult.PASSED
            self.logger.log_passed("BIOS Interface is locked (including Top Swap Mode)")
        return res

    def run(self, module_argv):
        self.logger.start_test("BIOS Interface Lock (including Top Swap Mode)")
        return self.check_bios_iface_lock()
