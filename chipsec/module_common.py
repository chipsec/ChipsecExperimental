# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2022, Intel Corporation
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
Common include file for modules
"""

import chipsec.chipset
from enum import Enum
from chipsec.defines import bit, is_set
import chipsec.logger
logger = chipsec.logger.logger()
using_return_codes = False


class ModuleResult:
    # -------------------------------------------------------
    # Legacy results
    # -------------------------------------------------------
    FAILED = 0
    PASSED = 1
    WARNING = 2
    SKIPPED = 3
    DEPRECATED = 4
    INFORMATION = 5
    NOTAPPLICABLE = 6
    ERROR = -1
    # -------------------------------------------------------
    class status(Enum):
        SUCCESS = [0x00000000, "Test module completed successfully"]
        LOCKS = [bit(63), "Locks are not set"] 
        MITIGATION = [bit(62), "Does not support mitigation"]
        CONFIGURATION = [bit(61), "Configuration not set"] 
        PROTECTION = [bit(60), "Protection not supported/enabled"]
        ACCESS_RW = [bit(59), ""]
        DEVICE_DISABLED = [bit(58), ""]
        FEATURE_DISABLED = [bit(57), ""]
        UNSUPPORTED_FEATURE = [bit(56), ""] 
        DEBUG_FEATURE = [bit(55), "A debug feature is enabled or an unexpected debug state was discovered on this platform"]
        NOT_APPLICABLE = [bit(54), "Skipping module since it is not supported"]
        ALL_FFS = [bit(53), "Read returned all 0xFFs"]
        INFORMATION = [bit(52), ""]
        VERIFY = [bit(51), "Manual verification/further testing recommended"]
        INVALID = [0xFFFFFFFFFFFFFFFF, ""]
    
    def __init__(self, id = 0, url = ""):
        self._id = id
        self._url = url
        self._result = self.status.INVALID.value[0]
        self._message = ""
        self.logger = logger

    def setStatusBit(self, s):
        if self._result == self.status.INVALID.value[0]:
            self._result = s.value[0]
            self._message = s.value[1]
        elif is_set(self._result, s.value[0]) is not True:
            self._result ^= s.value[0]
            self._message += ' / ' + s.value[1]

    def buildRC(self):
        returnCode = self._result
        #returnCode = self._result "0x{:08X}{:07X}0".format(typeCode[self._type],self._id)
        
        # Log message
        # If passed only log RC and message
        if self._result == self.status.SUCCESS.value[0]:
            self.logger.log_good(f"RC 0x{returnCode:016x}: {self._message}")
        # Else log RC, message and next steps
        else:
            self.logger.log_important(f"RC 0x{returnCode:016x}: {self._message}")
            self.logger.log_important(f"For next steps: {self._url}")
        
        return returnCode

    def getModuleResultName(self, result):
        if result == self.status.SUCCESS.value[0]:
            return "passed"
        return "failed"

# -------------------------------------------------------
# Legacy results
# -------------------------------------------------------
result_priority = {
    ModuleResult.PASSED: 0,
    ModuleResult.NOTAPPLICABLE: 0,
    ModuleResult.DEPRECATED: 0,
    ModuleResult.SKIPPED: 0,
    ModuleResult.INFORMATION: 1,
    ModuleResult.WARNING: 2,
    ModuleResult.FAILED: 3,
    ModuleResult.ERROR: 4
}

ModuleResultName = {
    ModuleResult.FAILED: "Failed",
    ModuleResult.PASSED: "Passed",
    ModuleResult.WARNING: "Warning",
    ModuleResult.SKIPPED: "Skipped",
    ModuleResult.DEPRECATED: "Deprecated",
    ModuleResult.INFORMATION: "Information",
    ModuleResult.ERROR: "Error",
    ModuleResult.NOTAPPLICABLE: "NotApplicable"
}

def getModuleResultName(res):
    return ModuleResultName[res] if res in ModuleResultName else ModuleResultName[ModuleResult.ERROR]
# -------------------------------------------------------

class BaseModule:
    def __init__(self):
        self.cs = chipsec.chipset.cs()
        self.logger = logger
        # -------------------------------------------------------
        # Legacy results
        # -------------------------------------------------------
        self.res = ModuleResult.PASSED
        # -------------------------------------------------------

    def is_supported(self):
        """
        This method should be overwritten by the module returning True or False
        depending whether or not this module is supported in the currently running
        platform.
        To access the currently running platform use
        """
        return True

    # -------------------------------------------------------
    # Legacy results
    # -------------------------------------------------------
    def update_res(self, value):
        if value not in result_priority:
            self.logger.log_verbose(f'Attempting to set invalid result status: {value}')
            return
        cur_priority = result_priority[self.res]
        new_priority = result_priority[value]
        if new_priority >= cur_priority:
            self.res = value

    def display_res_check(self, pass_msg, error_msg):
        if self.res == ModuleResult.PASSED:
            self.logger.log_passed(pass_msg)
        elif self.res == ModuleResult.FAILED:
            self.logger.log_failed(error_msg)
        elif self.res == ModuleResult.WARNING:
            self.logger.log_warning(error_msg)
        elif self.res == ModuleResult.INFORMATION:
            self.logger.log_information(error_msg)
    # -------------------------------------------------------

    def run(self, module_argv):
        raise NotImplementedError('Sub-class should overwrite the run() method')


MTAG_BIOS = "BIOS"
MTAG_SMM = "SMM"
MTAG_SECUREBOOT = "SECUREBOOT"
MTAG_HWCONFIG = "HWCONFIG"
MTAG_CPU = "CPU"


# ! [Available Tags]
MTAG_METAS = {
    MTAG_BIOS: "System Firmware (BIOS/UEFI) Modules",
    MTAG_SMM: "System Management Mode (SMM) Modules",
    MTAG_SECUREBOOT: "Secure Boot Modules",
    MTAG_HWCONFIG: "Hardware Configuration Modules",
    MTAG_CPU: "CPU Modules",
}
# ! [Available Tags]
MODULE_TAGS = dict([(_tag, []) for _tag in MTAG_METAS])

#
# Common module command line options
#
OPT_MODIFY = 'modify'
