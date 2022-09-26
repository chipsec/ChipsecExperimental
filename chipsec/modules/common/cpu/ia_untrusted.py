# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2018-2021, Intel Corporation
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
IA Untrusted checks
"""

from chipsec.module_common import BaseModule, ModuleResult, MTAG_HWCONFIG

TAGS = [MTAG_HWCONFIG]


class ia_untrusted(BaseModule):
    def __init__(self):
        super(ia_untrusted, self).__init__()
        self.cs.set_scope({
            "MSR_BIOS_DONE": "8086.MSR.MSR_BIOS_DONE",
        })

    def is_supported(self):
        if self.cs.Cfg.is_register_defined('MSR_BIOS_DONE') and \
           self.cs.Cfg.register_has_field('MSR_BIOS_DONE', 'IA_UNTRUSTED'):
            return True
        self.res = ModuleResult.NOTAPPLICABLE
        return False

    def check_untrusted(self):
        self.logger.log('[*] Check that untrusted mode has been set.')
        res = ModuleResult.PASSED
        bd = self.cs.read_register('MSR_BIOS_DONE')

        for regdata in bd:
            if self.logger.VERBOSE:
                self.cs.print_register('MSR_BIOS_DONE', regdata)
            if regdata.instance == 0:
                if self.cs.Cfg.register_has_field('MSR_BIOS_DONE', 'SoC_BIOS_DONE'):
                    soc = self.cs.get_register_field('MSR_BIOS_DONE', regdata.value, 'SoC_BIOS_DONE')
                    if soc == 0:
                        res = ModuleResult.FAILED
                        self.logger.log_bad('SoC_BIOS_DONE not set.')
                    else:
                        self.logger.log_good('SoC_BIOS_DONE set.')
                    self.logger.log('')

            ia_untrusted = self.cs.get_register_field('MSR_BIOS_DONE', regdata.value, "IA_UNTRUSTED")
            if ia_untrusted == 0:
                res = ModuleResult.FAILED
                self.logger.log_bad('IA_UNTRUSTED not set on thread {:d}.'.format(regdata.instance))
            else:
                self.logger.log_good('IA_UNTRUSTED set on thread {:d}.'.format(regdata.instance))
        return res

    def run(self, module_argv):
        self.logger.start_test('IA_UNTRUSTED Check')
        self.res = self.check_untrusted()
        self.logger.log("")
        if self.res == ModuleResult.PASSED:
            self.logger.log_passed("IA_UNTRUSTED set on all threads")
        elif self.res == ModuleResult.FAILED:
            self.logger.log_failed("IA_UNTRUSTED not set on all threads")
        return self.res
