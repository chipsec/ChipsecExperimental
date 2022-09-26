# -*- coding: utf-8 -*-
# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2021, SentinelOne
# Copyright (c) 2021, Intel
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

"""
SMM_Code_Chk_En (SMM Call-Out) Protection check

SMM_Code_Chk_En is a bit found in the SMM_FEATURE_CONTROL register.
Once set to '1', any CPU that attempts to execute SMM code not within the ranges defined by the SMRR will assert an unrecoverable MCE.
As such, enabling and locking this bit is an important step in mitigating SMM call-out vulnerabilities.
This CHIPSEC module simply reads the register and checks that SMM_Code_Chk_En is set and locked.

Reference:
    - Intel 64 and IA-32 Architectures Software Developer Manual (SDM)
        - https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html

Usage:
    ``chipsec_main -m common.smm_code_chk``

Examples:
    >>> chipsec_main.py -m common.smm_code_chk

Registers used:
    - SMM_FEATURE_CONTROL.LOCK
    - SMM_FEATURE_CONTROL.SMM_Code_Chk_En

.. note::
    - SMM_FEATURE_CONTROL may not be defined or readable on all platforms.

"""
from chipsec.exceptions import HWAccessViolationError
from chipsec.module_common import BaseModule, ModuleResult, MTAG_BIOS, MTAG_SMM

TAGS = [MTAG_BIOS, MTAG_SMM]


class smm_code_chk(BaseModule):

    def __init__(self):
        super(smm_code_chk, self).__init__()
        self.cs.set_scope({
            "SMM_FEATURE_CONTROL": "8086.MSR.SMM_FEATURE_CONTROL",
        })

    def is_supported(self):
        if not self.cs.Cfg.is_register_defined('SMM_FEATURE_CONTROL'):
            # The SMM_FEATURE_CONTROL register is available starting from:
            # * 4th Generation Intel® Core™ Processors (Haswell microarchitecture)
            # * Atom Processors Based on the Goldmont Microarchitecture
            self.logger.log_important('Register SMM_FEATURE_CONTROL not defined for platform.  Skipping module.')
            self.res = ModuleResult.NOTAPPLICABLE
            return False

        # The Intel SDM states that SMM_FEATURE_CONTROL can only be accessed while the CPU executes in SMM.
        # However, in reality many users report that there is no problem reading this register from outside of SMM.
        # Just to be on the safe side of things, we'll verify we can read this register successfully before moving on.
        try:
            self.cs.read_register('SMM_FEATURE_CONTROL')
        except HWAccessViolationError:
            self.logger.log_important('SMM_FEATURE_CONTROL is unreadable.  Skipping module.')
            self.res = ModuleResult.NOTAPPLICABLE
            return False
        else:
            return True

    def check_SMM_Code_Chk_En(self):
        regval = self.cs.read_register('SMM_FEATURE_CONTROL')
        if self.logger.VERBOSE:
            for reg in regval:
                self.cs.print_register('SMM_FEATURE_CONTROL', reg)

        lockmask = self.cs.get_register_field_mask('SMM_FEATURE_CONTROL', 'LOCK', True)
        code_chk_en_mask = self.cs.get_register_field_mask('SMM_FEATURE_CONTROL', 'SMM_CODE_CHK_EN', True)

        if self.cs.is_all_value(regval, 0xFFFFFFFF & code_chk_en_mask, code_chk_en_mask):
            if self.cs.is_all_value(regval, 0xFFFFFFFF & lockmask, lockmask):
                res = ModuleResult.PASSED
                self.logger.log_passed("SMM_Code_Chk_En is enabled and locked down")
            else:
                res = ModuleResult.FAILED
                self.logger.log_failed("SMM_Code_Chk_En is enabled but not locked down")
        else:
            # MSR_SMM_MCA_CAP (the register that reports enhanced SMM capabilities) can only be read from SMM.
            # Thus, there is no way to tell whether the the CPU doesn't support SMM_Code_Chk_En in the first place,
            # or the CPU supports SMM_Code_Chk_En but the BIOS forgot to enable it.
            #
            # In either case, there is nothing that prevents SMM code from executing instructions outside the ranges defined by the SMRRs,
            # so we should at least issue a warning regarding that.
            res = ModuleResult.WARNING
            self.logger.log_warning("""[*] SMM_Code_Chk_En is not enabled.
This can happen either because this feature is not supported by the CPU or because the BIOS forgot to enable it.
Please consult the Intel SDM to determine whether or not your CPU supports SMM_Code_Chk_En.""")

        return res

    def run(self, module_argv):
        self.logger.start_test("SMM_Code_Chk_En (SMM Call-Out) Protection")
        self.res = self.check_SMM_Code_Chk_En()
        return self.res
