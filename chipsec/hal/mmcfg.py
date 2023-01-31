# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2022, Intel Corporation

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
Access to MMIO (Memory Mapped IO) BARs and Memory-Mapped PCI Configuration Space (MMCFG)

usage:
    Access Memory Mapped Config Space:

    >>> get_MMCFG_base_address(cs)
    >>> read_mmcfg_reg(cs, 0, 0, 0, 0x10, 4)
    >>> read_mmcfg_reg(cs, 0, 0, 0, 0x10, 4, 0xFFFFFFFF)
"""

from chipsec.exceptions import CSReadError
from chipsec.hal import hal_base

PCI_PCIEXBAR_REG_LENGTH_256MB = 0x0
PCI_PCIEXBAR_REG_LENGTH_128MB = 0x1
PCI_PCIEXBAR_REG_LENGTH_64MB = 0x2
PCI_PCIEXBAR_REG_LENGTH_512MB = 0x3
PCI_PCIEXBAR_REG_LENGTH_1024MB = 0x4
PCI_PCIEXBAR_REG_LENGTH_2048MB = 0x5
PCI_PCIEXBAR_REG_LENGTH_4096MB = 0x6
PCI_PCIEBAR_REG_MASK = 0x7FFC000000


class MMCFG(hal_base.HALBase):

    def __init__(self, cs):
        super(MMCFG, self).__init__(cs)

    ##################################################################################
    # Access to Memory Mapped PCIe Configuration Space
    ##################################################################################

    def get_MMCFG_base_address(self):
        (bar_base, bar_size) = self.get_MMIO_BAR_base_address('MMCFG')
        if self.cs.register_has_field("PCI0.0.0_PCIEXBAR", "LENGTH") and not self.cs.is_server():
            len = self.cs.read_register_field("PCI0.0.0_PCIEXBAR", "LENGTH")
            if len == PCI_PCIEXBAR_REG_LENGTH_256MB:
                bar_base &= (PCI_PCIEBAR_REG_MASK << 2)
            elif len == PCI_PCIEXBAR_REG_LENGTH_128MB:
                bar_base &= (PCI_PCIEBAR_REG_MASK << 1)
            if len == PCI_PCIEXBAR_REG_LENGTH_64MB:
                bar_base &= (PCI_PCIEBAR_REG_MASK << 0)
            if len == PCI_PCIEXBAR_REG_LENGTH_512MB:
                bar_base &= (PCI_PCIEBAR_REG_MASK << 3)
            if len == PCI_PCIEXBAR_REG_LENGTH_1024MB:
                bar_base &= (PCI_PCIEBAR_REG_MASK << 4)
            if len == PCI_PCIEXBAR_REG_LENGTH_2048MB:
                bar_base &= (PCI_PCIEBAR_REG_MASK << 5)
            if len == PCI_PCIEXBAR_REG_LENGTH_4096MB:
                bar_base &= (PCI_PCIEBAR_REG_MASK << 6)
        if self.cs.register_has_field("MmioCfgBaseAddr", "BusRange"):
            num_buses = self.cs.read_register_field("MmioCfgBaseAddr", "BusRange")
            if num_buses <= 8:
                bar_size = 2**20 * 2**num_buses
            else:
                if self.logger.HAL:
                    self.logger.log('[mmcfg] Unexpected MmioCfgBaseAddr bus range: 0x{:01X}'.format(num_buses))
        if self.logger.HAL:
            self.logger.log('[mmcfg] Memory Mapped CFG Base: 0x{:016X}'.format(bar_base))
        return bar_base, bar_size

    def read_mmcfg_reg(self, bus, dev, fun, off, size):
        pciexbar, pciexbar_sz = self.get_MMCFG_base_address()
        pciexbar_off = (bus * 32 * 8 + dev * 8 + fun) * 0x1000 + off
        value = self.read_MMIO_reg(pciexbar, pciexbar_off, size, pciexbar_sz)
        if self.logger.HAL:
            self.logger.log("[mmcfg] reading {:02d}:{:02d}.{:d} + 0x{:02X} (MMCFG + 0x{:08X}): 0x{:08X}".format(bus, dev, fun, off, pciexbar_off, value))
        if 1 == size:
            return (value & 0xFF)
        elif 2 == size:
            return (value & 0xFFFF)
        return value

    def write_mmcfg_reg(self, bus, dev, fun, off, size, value):
        pciexbar, pciexbar_sz = self.get_MMCFG_base_address()
        pciexbar_off = (bus * 32 * 8 + dev * 8 + fun) * 0x1000 + off
        if size == 1:
            mask = 0xFF
        elif size == 2:
            mask = 0xFFFF
        else:
            mask = 0xFFFFFFFF
        self.write_MMIO_reg(pciexbar, pciexbar_off, (value & mask), size, pciexbar_sz)
        if self.logger.HAL:
            self.logger.log("[mmcfg] writing {:02d}:{:02d}.{:d} + 0x{:02X} (MMCFG + 0x{:08X}): 0x{:08X}".format(bus, dev, fun, off, pciexbar_off, value))
        return True