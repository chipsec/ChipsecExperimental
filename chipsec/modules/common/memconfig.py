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
This module verifies memory map secure configuration,
that memory map registers are correctly configured and locked down.

Usage:
  ``chipsec_main -m common.memconfig``

Example:
    >>> chipsec_main.py -m common.memconfig

.. note::
    - This module will only run on Core (client) platforms.
"""

from chipsec.module_common import BaseModule, ModuleResult, MTAG_HWCONFIG

_MODULE_NAME = 'memconfig'

TAGS = [MTAG_HWCONFIG]


memmap_registers = {
  "8086.HOSTCTL.GGC": 'GGCLOCK',
  "8086.HOSTCTL.PAVPC": 'PAVPLCK',
  "8086.HOSTCTL.DPR": 'LOCK',
  "8086.HOSTCTL.MESEG_MASK": 'MELCK',
  "8086.HOSTCTL.REMAPBASE": 'LOCK',
  "8086.HOSTCTL.REMAPLIMIT": 'LOCK',
  "8086.HOSTCTL.TOM": 'LOCK',
  "8086.HOSTCTL.TOUUD": 'LOCK',
  "8086.HOSTCTL.BDSM": 'LOCK',
  "8086.HOSTCTL.BGSM": 'LOCK',
  "8086.HOSTCTL.TSEGMB": 'LOCK',
  "8086.HOSTCTL.TOLUD": 'LOCK'
}

memmap_registers_dev0bars = [
  "8086.HOSTCTL.PXPEPBAR",
  "8086.HOSTCTL.MCHBAR",
  "8086.HOSTCTL.PCIEXBAR",
  "8086.HOSTCTL.DMIBAR",
]


class memconfig(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.cs.set_scope({
            "MSR_BIOS_DONE": "8086.MSR.MSR_BIOS_DONE",
        })

    def is_supported(self):
        if self.cs.is_core():
            return True
        else:
            self.logger.log_important("Not a 'Core' (Desktop) platform.  Skipping test.")
        self.res = ModuleResult.NOTAPPLICABLE
        return False

    def check_memmap_locks(self):

        # Determine if IA_UNTRUSTED can be used to lock the system.
        ia_untrusted = None
        if self.cs.Cfg.is_register_defined('MSR_BIOS_DONE') and self.cs.Cfg.register_has_field('MSR_BIOS_DONE', 'IA_UNTRUSTED'):
            ia_untrusted = self.cs.read_register_field('MSR_BIOS_DONE', 'IA_UNTRUSTED')

        regs = sorted(memmap_registers.keys())
        all_locked = True

        self.logger.log('[*]')
        if ia_untrusted is not None:
            self.logger.log('[*] Checking legacy register lock state:')
        else:
            self.logger.log('[*] Checking register lock state:')
        for r in regs:
            if not self.cs.Cfg.is_register_defined(r) or not self.cs.Cfg.register_has_field(r, memmap_registers[r]):
                self.logger.log_important('Skipping Validation: Register {} or field {} was not defined for this platform.'.format(r, memmap_registers[r]))
                continue
            d = self.cs.Cfg.get_register_def(r)['desc']
            v = self.cs.read_register(r)
            mask = self.cs.get_register_field_mask(r, memmap_registers[r], True)
            if self.logger.VERBOSE:
                for regdata in v:
                    self.cs.print_register(r, regdata)
            if self.cs.is_all_value(v, mask & 0xFFFFFFFF, mask):
                self.logger.log_good("{:20} = - LOCKED   - {}".format(r, d))
            else:
                all_locked = False
                self.logger.log_bad("{:20} = - UNLOCKED - {}".format(r, d))

        if ia_untrusted is not None:
            self.logger.log('[*]')
            self.logger.log('[*] Checking if IA Untrusted mode is used to lock registers')
            if self.cs.is_all_value(ia_untrusted, 1):
                self.logger.log_good('IA Untrusted mode set')
                all_locked = True
            else:
                self.logger.log_bad('IA Untrusted mode not set')

        self.logger.log('[*]')
        if all_locked:
            res = ModuleResult.PASSED
            self.logger.log_passed("All memory map registers seem to be locked down")
        else:
            res = ModuleResult.FAILED
            self.logger.log_failed("Not all memory map registers are locked down")

        return res

    def run(self, module_argv):
        self.logger.start_test("Host Bridge Memory Map Locks")

        self.res = self.check_memmap_locks()
        return self.res
