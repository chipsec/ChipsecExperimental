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
# Authors:
#  Yuriy Bulygin
#  Erik Bjorge


"""
SPI Flash Region Access Control

Checks SPI Flash Region Access Permissions programmed in the Flash Descriptor

Usage:
    ``chipsec_main -m common.spi_access``

Examples:
    >>> chipsec_main.py -m common.spi_access

Registers used:
    - HSFS.FDV
    - FRAP.BRWA

"""

from chipsec.module_common import BaseModule, ModuleResult, MTAG_BIOS
from chipsec.hal.spi import SPI, GBE, PLATFORM_DATA, ME, FLASH_DESCRIPTOR

TAGS = [MTAG_BIOS]


class spi_access(BaseModule):

    def __init__(self):
        super(spi_access, self).__init__()
        self.spi = SPI(self.cs)
        self.cs.set_scope({
            "HSFS": "8086.SPI.HSFS",
            "FRAP": "8086.SPI.FRAP",
        })

    def is_supported(self):
        return True

    ##
    # Displays the SPI Regions Access Permissions
    def check_flash_access_permissions(self):
        frapData = self.cs.read_register('FRAP')
        for frap in frapData:
            if self.logger.VERBOSE:
                self.cs.print_register('FRAP', frap)
            fdv = self.cs.read_register_field('HSFS', 'FDV', instance=frap.instance)[0].value == 1
            brwa = self.cs.get_register_field('FRAP', frap.value, 'BRWA')

            # Informational
            # State of Flash Descriptor Valid bit
            if not fdv:
                self.logger.log("[*] Flash Descriptor Valid bit is not set")

            # CPU/Software access to Platform Data region (platform specific)
            if brwa & (1 << PLATFORM_DATA):
                self.logger.log("[*] Software has write access to Platform Data region in SPI flash (it's platform specific)")

            # Warnings
            # CPU/Software access to GBe region
            if brwa & (1 << GBE):
                self.update_res(ModuleResult.WARNING)
                self.logger.log_warning("Software has write access to GBe region in SPI flash")

            # Failures
            # CPU/Software access to Flash Descriptor region (Read Only)
            if brwa & (1 << FLASH_DESCRIPTOR):
                self.update_res(ModuleResult.FAILED)
                self.logger.log_bad("Software has write access to SPI flash descriptor")

            # CPU/Software access to Intel ME region (Read Only)
            if brwa & (1 << ME):
                self.update_res(ModuleResult.FAILED)
                self.logger.log_bad("Software has write access to Management Engine (ME) region in SPI flash")

            if fdv:
                if ModuleResult.PASSED == self.res:
                    self.logger.log_good("SPI Flash Region Access Permissions in flash descriptor look ok")
                elif ModuleResult.FAILED == self.res:
                    self.logger.log_bad("SPI Flash Region Access Permissions are not programmed securely in flash descriptor")
                    self.logger.log_important('System may be using alternative protection by including descriptor region in SPI Protected Range Registers')
                elif ModuleResult.WARNING == self.res:
                    self.logger.log_warning("Certain SPI flash regions are writeable by software")
            else:
                self.update_res(ModuleResult.WARNING)
                self.logger.log_warning("Either flash descriptor is not valid or not present on this system")

    def run(self, module_argv):
        self.logger.start_test("SPI Flash Region Access Control")
        self.spi.display_SPI_Ranges_Access_Permissions()
        self.check_flash_access_permissions()
        return self.res
