# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2018, Eclypsium, Inc.
# Copyright (c) 2018-2021, Intel Corporation

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.


"""
This module checks if the system has debug features turned on,
specifically the Direct Connect Interface (DCI).

This module checks the following bits:
1. HDCIEN bit in the DCI Control Register
2. Debug enable bit in the IA32_DEBUG_INTERFACE MSR
3. Debug lock bit in the IA32_DEBUG_INTERFACE MSR
4. Debug occurred bit in the IA32_DEBUG_INTERFACE MSR

The module returns the following results:
FAILED : Any one of the debug features is enabled or unlocked.
PASSED : All debug feature are diabled and locked.

Hardware registers used:
IA32_DEBUG_INTERFACE[DEBUGENABLE]
IA32_DEBUG_INTERFACE[DEBUGELOCK]
IA32_DEBUG_INTERFACE[DEBUGEOCCURED]
P2SB_DCI.DCI_CONTROL_REG[HDCIEN]

"""

from chipsec.module_common import BaseModule, ModuleResult
from chipsec.defines import BIT11
_MODULE_NAME = 'debugenabled'


########################################################################################################
#
# Main module functionality
#
########################################################################################################
class debugenabled(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.cs.set_scope({
            "ECTRL": "8086.DCI.ECTRL",
            "IA32_DEBUG_INTERFACE": "8086.MSR.IA32_DEBUG_INTERFACE"
        })

    def is_supported(self):
        # Use CPUID Function 1 to determine if the IA32_DEBUG_INTERFACE MSR is supported.
        # See IA32 SDM CPUID Instruction for details.  (SDBG ECX bit 11)
        (eax, ebx, ecx, edx) = self.cs.cpu.cpuid(1, 0)
        supported = (ecx & BIT11) != 0
        if not supported:
            self.res = ModuleResult.NOTAPPLICABLE
            self.logger.log_skipped('CPU Debug features are not supported on this platform')
        return supported

    def check_dci(self):
        if not self.cs.Cfg.is_register_defined('ECTRL'):
            return
        self.logger.log('\n[*] Checking DCI register status')
        ectrl = self.cs.read_register("ECTRL")
        if self.logger.VERBOSE:
            for regdata in ectrl:
                self.cs.print_register("ECTRL", regdata.value, regdata.instance)
        hdcien_mask = self.cs.get_register_field_mask('ECTRL', 'ENABLE', True)
        if self.cs.is_all_value(ectrl, ectrl[0].value, hdcien_mask):
            self.logger.log_good('CPU debug enable is set consitently')
        if self.cs.is_any_value(ectrl, 0xFFFFFFFF & hdcien_mask, hdcien_mask):
            self.update_res(ModuleResult.FAILED)
            self.logger.log_bad('DCI Debug is enabled')
        else:
            self.logger.log_good('DCI Debug is disabled')
        
    def check_cpu_debug_enable(self):
        self.logger.log('\n[*] Checking IA32_DEBUG_INTERFACE msr status')
        #res = ModuleResult.PASSED
        dbg_data = self.cs.read_register('IA32_DEBUG_INTERFACE')
        if self.logger.VERBOSE:
            for regdata in dbg_data:
                self.cs.print_register("IA32_DEBUG_INTERFACE", regdata)
        enable_mask = self.cs.get_register_field_mask('IA32_DEBUG_INTERFACE', 'ENABLE', True)
        lock_mask = self.cs.get_register_field_mask('IA32_DEBUG_INTERFACE', 'LOCK', True)
        occured_mask = self.cs.get_register_field_mask('IA32_DEBUG_INTERFACE', 'DEBUG_OCCURRED', True)
        if self.cs.is_all_value(dbg_data, dbg_data[0].value, enable_mask):
            self.logger.log_good('CPU debug enable is set consitently')
        if self.cs.is_any_value(dbg_data, 0xFFFFFFFF & enable_mask, enable_mask):
            self.update_res(ModuleResult.FAILED)
            self.logger.log_bad("CPU debug enable requested by software.")
        if self.cs.is_all_value(dbg_data, dbg_data[0].value, lock_mask):
            self.logger.log_good('CPU debug lock is set consitently')
        if self.cs.is_any_value(dbg_data, 0, lock_mask):
            self.update_res(ModuleResult.FAILED)
            self.logger.log_bad("CPU debug interface is not locked.")
        if self.cs.is_all_value(dbg_data, dbg_data[0].value, enable_mask):
            self.logger.log_good('CPU debug enable is set consitently')
        if self.cs.is_any_value(dbg_data, 0xFFFFFFFF & occured_mask, occured_mask):
            self.update_res(ModuleResult.FAILED)
            self.logger.log_bad("Debug Occurred bit set in IA32_DEBUG_INTERFACE MSR")
        if self.res ==  ModuleResult.PASSED:
            self.logger.log_good("CPU debug interface state is correct.")

    def run(self, module_argv):
        self.logger.start_test('Debug features test')

        self.check_cpu_debug_enable()

        if self.cs.Cfg.is_register_defined("ECTRL"):
            dci_test_fail = self.check_dci()

        self.logger.log("\n[*] Module Result")
        if self.res == ModuleResult.FAILED:
            self.logger.log_failed('One or more of the debug checks have failed and a debug feature is enabled')
            self.res = ModuleResult.FAILED
        elif self.res == ModuleResult.WARNING:
            self.logger.log_warning('An unexpected debug state was discovered on this platform')
            self.res = ModuleResult.WARNING
        else:
            self.logger.log_passed('All checks have successfully passed')

        return self.res
