# CHIPSEC: Platform Security Assessment Framework

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

from chipsec.helper.basehelper import Helper


class MockHelper(Helper):
    """Default test helper that emulates a Broadwell architecture.

    See datasheet for registers definition.
    http://www.intel.com/content/www/us/en/chipsets/9-series-chipset-pch-datasheet.html
    """

    def __init__(self):
        super(MockHelper, self).__init__()
        self.os_system = "test_helper"
        self.os_release = "0"
        self.os_version = "0"
        self.os_machine = "test"
        self.driver_loaded = True
        self.name = "MockHelper"

    def create(self):
        return True

    def delete(self, start_driver):
        return True

    def start(self):
        return True

    def stop(self, start_driver):
        return True

    # This will be used to probe the device, fake a Broadwell CPU
    def read_pci_reg(self, bus, device, function, address, size):
        if (bus, device, function) == (0, 0, 0):
            if size == 1:
                return 0x86
            elif size == 2:
                return 0x8086
            elif size == 4:
                return 0x9A128086
        elif (bus, device, function) == (0, 0x1f, 0):
            if size == 1:
                return 0x86
            elif size == 2:
                return 0x8086
            elif size == 4:
                return 0xA0828086
        else:
            return 0xFFFFFFFF

    def read_physical_mem(self, phys_address, length):
        return self.read_phys_mem(phys_address >> 32, phys_address & 0xFFFFFFFF, length)

    def get_threads_count(self):
        return 2

    def cpuid(self, eax, ecx):
        return 0x406F1, 0, 0, 0


def get_helper():
    return MockHelper()
