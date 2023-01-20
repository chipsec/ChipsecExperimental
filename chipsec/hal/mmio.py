# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2022, Intel Corporation

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
    >>> read_MMIO_reg(cs, bar_base, 0x0, 4)
    >>> write_MMIO_reg(cs, bar_base, 0x0, 0xFFFFFFFF, 4)
    >>> read_MMIO(cs, bar_base, 0x1000)
    >>> dump_MMIO(cs, bar_base, 0x1000)
    Access MMIO by BAR name:
    >>> read_MMIO_BAR_reg(cs, 'MCHBAR', 0x0, 4)
    >>> write_MMIO_BAR_reg(cs, 'MCHBAR', 0x0, 0xFFFFFFFF, 4)
    >>> get_MMIO_BAR_base_address(cs, 'MCHBAR')
    >>> is_MMIO_BAR_enabled(cs, 'MCHBAR')
    >>> is_MMIO_BAR_programmed(cs, 'MCHBAR')
    >>> dump_MMIO_BAR(cs, 'MCHBAR')
    >>> list_MMIO_BARs(cs)
"""

from chipsec.hal import hal_base
from chipsec.exceptions import CSReadError
import struct

DEFAULT_MMIO_BAR_SIZE = 0x1000


class MMIO(hal_base.HALBase):

    def __init__(self, cs):
        super(MMIO, self).__init__(cs)

    ###########################################################################
    # Access to MMIO BAR defined by configuration files (chipsec/cfg/*.py)
    ###########################################################################

    #
    # Read MMIO register as an offset off of MMIO range base address
    #
    def read_MMIO_reg(self, bar_base, offset, size=4, bar_size=None):
        if size > 8:
            self.logger.log_hal("MMIO read cannot exceed 8")
        reg_value = self.helper.read_mmio_reg(bar_base, size, offset, bar_size)
        self.logger.log_hal('[mmio] 0x{:08X} + 0x{:08X} = 0x{:08X}'.format(bar_base, offset, reg_value))
        return reg_value

    def read_MMIO_reg_byte(self, bar_base, offset):
        reg_value = self.read_MMIO_reg(bar_base, offset, 1)
        self.logger.log_hal('[mmio] 0x{:08X} + 0x{:08X} = 0x{:08X}'.format(bar_base, offset, reg_value))
        return reg_value

    def read_MMIO_reg_word(self, bar_base, offset):
        reg_value = self.read_MMIO_reg(bar_base, offset, 2)
        self.logger.log_hal('[mmio] 0x{:08X} + 0x{:08X} = 0x{:08X}'.format(bar_base, offset, reg_value))
        return reg_value

    def read_MMIO_reg_dword(self, bar_base, offset):
        reg_value = self.read_MMIO_reg(bar_base, offset, 4)
        self.logger.log_hal('[mmio] 0x{:08X} + 0x{:08X} = 0x{:08X}'.format(bar_base, offset, reg_value))
        return reg_value

    #
    # Write MMIO register as an offset off of MMIO range base address
    #
    def write_MMIO_reg(self, bar_base, offset, value, size=4, bar_size=None):
        self.logger.log_hal('[mmio] write 0x{:08X} + 0x{:08X} = 0x{:08X}'.format(bar_base, offset, value))
        self.helper.write_mmio_reg(bar_base, size, value, offset, bar_size)

    def write_MMIO_reg_byte(self, bar_base, offset, value):
        self.logger.log_hal('[mmio] write 0x{:08X} + 0x{:08X} = 0x{:08X}'.format(bar_base, offset, value))
        self.write_MMIO_reg(bar_base, offset, value, 1)

    def write_MMIO_reg_word(self, bar_base, offset, value):
        self.logger.log_hal('[mmio] write 0x{:08X} + 0x{:08X} = 0x{:08X}'.format(bar_base, offset, value))
        self.write_MMIO_reg(bar_base, offset, value, 2)

    def write_MMIO_reg_dword(self, bar_base, offset, value):
        self.logger.log_hal('[mmio] write 0x{:08X} + 0x{:08X} = 0x{:08X}'.format(bar_base, offset, value))
        self.write_MMIO_reg(bar_base, offset, value, 4)

    #
    # Dump MMIO range
    #
    def dump_MMIO(self, bar_base, size):
        ret = b''
        self.logger.log("[mmio] MMIO register range [0x{:016X}:0x{:016X}+{:08X}]:".format(bar_base, bar_base, size))
        size -= size % 4
        for offset in range(0, size, 4):
            value = self.read_MMIO_reg(bar_base, offset)
            self.logger.log('+{:08X}: {:08X}'.format(offset, value))
            ret += struct.pack('I', value)
        return ret

    ###############################################################################
    # Access to MMIO BAR defined by XML configuration files (chipsec/cfg/*.xml)
    ###############################################################################

    #
    # Check if MMIO BAR with bar_name has been defined in XML config
    # Use this function to fall-back to hardcoded config in case XML config is not available
    #
    def is_MMIO_BAR_defined(self, bar_name):
        is_bar_defined = False
        try:
            _bar = self.cs.Cfg.get_mmio_def(bar_name)
            if _bar is not None:
                if 'register' in _bar:
                    is_bar_defined = self.cs.Cfg.is_register_defined(_bar['register'])
        except KeyError:
            pass

        if not is_bar_defined:
            self.logger.log_hal("'{}' MMIO BAR definition not found/correct in XML config".format(bar_name))
        return is_bar_defined

    #
    # Get base address of MMIO range by MMIO BAR name
    #
    def get_MMIO_BAR_base_address(self, bar_name, bus):
        bar = self.cs.Cfg.get_mmio_def(bar_name)
        if not bar:
            raise CSReadError("{} is not defined, check scoping and configuration".format(bar_name))
        base = 0
        reg_mask = 0xFFFF
        limit = 0
        size = 0

        if 'register' in bar and bus is not None:
            preserve = True
            bar_reg = bar['register']
            if 'reg_align' in bar:
                preserve = False
            if 'base_field' in bar:
                base_field = bar['base_field']
                try:
                    base = self.cs.read_register_field(bar_reg, base_field, preserve, bus)[0].value
                except CSReadError:
                    self.logger.log_hal('[mmio] Unable to determine MMIO Base register.  Using Base = 0x0')
                try:
                    reg_mask = self.cs.get_register_field_mask(bar_reg, base_field, preserve)
                except CSReadError:
                    self.logger.log_hal('[mmio] Unable to determine MMIO Mask register.  Using Mask = 0xFFFF')
            if not preserve:
                base <<= bar['reg_align']
                reg_mask <<= bar['reg_align']
        if 'registerh' in bar and bus is not None:
            preserve = True
            bar_reg = bar['registerh']
            if 'regh_align' in bar:
                preserve = False
            if 'baseh_field' in bar:
                base_field = bar['baseh_field']
                try:
                    baseh = self.cs.read_register_field(bar_reg, base_field, preserve, bus)[0].value
                except CSReadError:
                    self.logger.log_hal('[mmio] Unable to determine MMIO Base registerh.  Using Base = 0x0')
                    baseh = 0
                try:
                    reg_maskh = self.cs.get_register_field_mask(bar_reg, base_field, preserve)
                except CSReadError:
                    self.logger.log_hal('[mmio] Unable to determine MMIO Mask registerh.  Using Mask = 0xFFFF')
                    reg_maskh = 0xFFFF
            if not preserve:
                baseh <<= bar['reg_align']
                reg_maskh <<= bar['reg_align']
            base += baseh
            reg_mask += reg_maskh
        if 'registertype' in bar and bar['registertype'] == 'dynamic':
            try:
                dynbase = self.read_MMIO_reg(base, 0)
            except CSReadError:
                self.logger.log_hal('[mmio] Unable to determine MMIO Base.  Using Base = 0x0')
                dynbase = 0x0
            base = dynbase
        if 'mmio_base' in bar:
            mmiobar = bar['mmio_base']
            mmioaddr, _ = self.get_MMIO_BAR_base_address(mmiobar, bus)
            if 'mmio_align' in bar:
                mmioaddr <<= bar['mmio_align']
            base += mmioaddr

        if 'limit_register' in bar and 'limit_field' in bar and 'limit_align' in bar:
            limit_field = bar['limit_field']
            limit_bar = bar['limit_register']
            limit = self.cs.read_register_field(limit_bar, limit_field, instance=bus)[0].value
            if 'limit_align' in bar:
                limit_align = bar['limit_align']
                limit <<= limit_align

        if 'fixed_address' in bar and (base == reg_mask or base == 0):
            base = bar['fixed_address']
            self.logger.log_hal('[mmio] Using fixed address for {}: 0x{:016X}'.format(bar_name, base))
        if 'size' in bar:
            size = bar['size']
        elif limit:
            if 'mmio_align' in bar:
                limit += ((0x1 << bar['mmio_align']) - 1)
            limit += mmioaddr
            size = limit - base
        if size == 0:
            size = DEFAULT_MMIO_BAR_SIZE
        self.logger.log_hal('[mmio] {}: 0x{:016X} (size = 0x{:X})'.format(bar_name, base, size))
        if base == 0:
            self.logger.log_hal('[mmio] Base address was determined to be 0.')
            raise CSReadError('[mmio] Base address was determined to be 0')
        return base, size

    def get_MMIO_BAR_from_bdf(self, b, d, f, off, size=4):
        if 8 == size:
            base_lo = self.cs.pci.read_dword(b, d, f, off)
            base_hi = self.cs.pci.read_dword(b, d, f, off + 4)
            base = (base_hi << 32) | base_lo
        else:
            base = self.cs.pci.read_dword(b, d, f, off)
        return base

    #
    # Check if MMIO range is enabled by MMIO BAR name
    #
    def is_MMIO_BAR_enabled(self, bar_name, bus=None):
        if not self.is_MMIO_BAR_defined(bar_name):
            return False
        bar = self.cs.Cfg.get_mmio_def(bar_name)
        is_enabled = True
        if 'register' in bar:
            if 'enable_field' in bar:
                bar_en_field = bar['enable_field']
                bar_reg = bar['register']
                is_enabled = (1 == self.cs.read_register_field(bar_reg, bar_en_field, instance=bus)[0].value)
        return is_enabled

    #
    # Check if MMIO range is valid by MMIO BAR name
    #
    def is_MMIO_BAR_valid(self, bar_name, bus=None):
        if not self.is_MMIO_BAR_defined(bar_name):
            return False
        bar = self.cs.Cfg.get_mmio_def(bar_name)
        is_valid = True
        if 'register' in bar:
            if 'valid' in bar:
                bar_en_field = bar['valid']
                bar_reg = bar['register']
                is_valid = (1 == self.cs.read_register_field(bar_reg, bar_en_field, instance=bus)[0].value)
        return is_valid

    #
    # Check if MMIO range is programmed by MMIO BAR name
    #
    def is_MMIO_BAR_programmed(self, bar_name, bus):
        bar = self.cs.Cfg.MMIO_BARS[bar_name]

        if 'register' in bar:
            bar_reg = bar['register']
            if 'base_field' in bar:
                base_field = bar['base_field']
                base = self.cs.read_register_field(bar_reg, base_field, preserve_field_position=True, instance=bus)[0].value
            else:
                base = self.cs.read_register(bar_reg, bus)[0].value
        return (0 != base)

    def list_MMIO_BARs(self):
        self.logger.log('')
        self.logger.log('---------------------------------------------------------------------------------------------------------')
        self.logger.log(' {:35} | {:3} | {:16} | {:8} | {:3} | {:5} | {}'.format('MMIO Range', 'BUS', 'Base', 'Size', 'En?', 'Valid', 'Description'))
        self.logger.log('---------------------------------------------------------------------------------------------------------')
        for vid in self.cs.Cfg.MMIO_BARS:
            for dev in self.cs.Cfg.MMIO_BARS[vid]:
                for bar_name in self.cs.Cfg.MMIO_BARS[vid][dev]:
                    _bar_name = "{}.{}.{}".format(vid, dev, bar_name)
                    if not self.is_MMIO_BAR_defined(_bar_name):
                        continue
                    _bar = self.cs.Cfg.MMIO_BARS[vid][dev][bar_name]
                    bus_data = self.cs.Cfg.get_device_bus("{}.{}".format(vid, dev))
                    if not bus_data:
                        # need to check for fixed address
                        bus_data = [None]
                    for bus in bus_data:
                        try:
                            (_base, _size) = self.get_MMIO_BAR_base_address(_bar_name, bus)
                        except Exception as e:
                            self.logger.log_hal("Unable to find MMIO BAR {}: {}".format(_bar, e))
                            continue
                        _en = self.is_MMIO_BAR_enabled(_bar_name)
                        _valid = self.is_MMIO_BAR_valid(_bar_name)

                        self.logger.log(' {:35} | {:02X}  | {:016X} | {:08X} |  {:d}  |   {:d}   | {}'.format(
                            _bar_name, bus or 0, _base, _size, _en, _valid, _bar['desc']))
