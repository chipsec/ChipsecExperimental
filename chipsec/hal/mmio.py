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
        self.cached_bar_addresses = {}
        self.cache_bar_addresses_resolution = False

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
    # Read MMIO registers as offsets off of MMIO range base address
    #
    def read_MMIO(self, bar_base, size):
        regs = []
        size -= size % 4
        for offset in range(0, size, 4):
            regs.append(self.read_MMIO_reg(bar_base, offset))
        return regs

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
            _bar = self.cs.Cfg.MMIO_BARS[bar_name]
            if _bar is not None:
                if 'register' in _bar:
                    is_bar_defined = self.cs.is_register_defined(_bar['register'])
                elif ('bus' in _bar) and ('dev' in _bar) and ('fun' in _bar) and ('reg' in _bar):
                    # old definition
                    is_bar_defined = True
        except KeyError:
            pass

        if not is_bar_defined:
            self.logger.log_hal("'{}' MMIO BAR definition not found/correct in XML config".format(bar_name))
        return is_bar_defined

    #
    # Enable caching of BAR addresses
    #
    def enable_cache_address_resolution(self, enable):
        if enable:
            self.cache_bar_addresses_resolution = True
        else:
            self.cache_bar_addresses_resolution = False
            self.flush_bar_address_cache()

    def flush_bar_address_cache(self):
        self.cached_bar_addresses = {}

    #
    # Get base address of MMIO range by MMIO BAR name
    #
    def get_MMIO_BAR_base_address(self, bar_name, bus=None):
        if self.cache_bar_addresses_resolution and (bar_name, bus) in self.cached_bar_addresses:
            return self.cached_bar_addresses[(bar_name, bus)]
        bar = self.cs.Cfg.MMIO_BARS[bar_name]
        if bar is None or bar == {}:
            return -1, -1
        _bus = bus

        if 'register' in bar:
            preserve = True
            bar_reg = bar['register']
            if _bus is None:
                _buses = self.cs.get_register_bus(bar_reg)
                _bus = _buses[0] if _buses else None
            if 'align_bits' in bar:
                preserve = False
            if 'base_field' in bar:
                base_field = bar['base_field']
                try:
                    base = self.cs.read_register_field(bar_reg, base_field, preserve, bus=_bus)
                except CSReadError:
                    if self.logger.HAL:
                        self.logger.log('[mmio] Unable to determine MMIO Base.  Using Base = 0x0')
                    base = 0
                try:
                    reg_mask = self.cs.get_register_field_mask(bar_reg, base_field, preserve)
                except CSReadError:
                    if self.logger.HAL:
                        self.logger.log('[mmio] Unable to determine MMIO Mask.  Using Mask = 0xFFFF')
                    reg_mask = 0xFFFF
            else:
                base = self.cs.read_register(bar_reg, bus=_bus)
                reg_mask = self.cs.get_register_field_mask(bar_reg, preserve_field_position=preserve)
            if 'limit_field' in bar:
                limit_field = bar['limit_field']
                limit = self.cs.read_register_field(bar_reg, limit_field, bus=_bus)
        else:
            # this method is not preferred (less flexible)
            if _bus is not None:
                b = _bus
            else:
                b = int(bar['bus'], 16)
            d = int(bar['dev'], 16)
            f = int(bar['fun'], 16)
            r = int(bar['reg'], 16)
            width = int(bar['width'], 16)
            reg_mask = (1 << (width * 8)) - 1
            if 8 == width:
                base_lo = self.cs.pci.read_dword(b, d, f, r)
                base_hi = self.cs.pci.read_dword(b, d, f, r + 4)
                base = (base_hi << 32) | base_lo
            else:
                base = self.cs.pci.read_dword(b, d, f, r)

        if 'fixed_address' in bar and (base == reg_mask or base == 0):
            base = int(bar['fixed_address'], 16)
            if self.logger.HAL:
                self.logger.log('[mmio] Using fixed address for {}: 0x{:016X}'.format(bar_name, base))
        if 'mask' in bar:
            base &= int(bar['mask'], 16)
        if 'offset' in bar:
            base = base + int(bar['offset'], 16)
        if 'align_bits' in bar:
            _buses = self.cs.get_register_bus(bar['base_reg'])
            _bus = _buses[0] if _buses else None
            start = self.cs.read_register_field(bar['base_reg'], bar['base_addr'], bus=_bus)
            start <<= int(bar['base_align'])
            base <<= int(bar['align_bits'])
            limit <<= int(bar['align_bits'])
            base += start
            limit += ((0x1 << int(bar['align_bits'])) - 1)
            limit += start
            size = limit - base
        else:
            size = int(bar['size'], 16) if ('size' in bar) else DEFAULT_MMIO_BAR_SIZE

        if self.logger.HAL:
            self.logger.log('[mmio] {}: 0x{:016X} (size = 0x{:X})'.format(bar_name, base, size))
        if base == 0:
            if self.logger.HAL:
                self.logger.log('[mmio] Base address was determined to be 0.')
            raise CSReadError('[mmio] Base address was determined to be 0')

        if self.cache_bar_addresses_resolution:
            self.cached_bar_addresses[(bar_name, bus)] = (base, size)
        return base, size

    #
    # Check if MMIO range is enabled by MMIO BAR name
    #
    def is_MMIO_BAR_enabled(self, bar_name, bus=None):
        if not self.is_MMIO_BAR_defined(bar_name):
            return False
        bar = self.cs.Cfg.MMIO_BARS[bar_name]
        is_enabled = True
        if 'register' in bar:
            bar_reg = bar['register']
            if 'enable_field' in bar:
                bar_en_field = bar['enable_field']
                is_enabled = (1 == self.cs.read_register_field(bar_reg, bar_en_field, bus=bus))
        else:
            # this method is not preferred (less flexible)
            if bus is not None:
                b = bus
            else:
                b = int(bar['bus'], 16)
            d = int(bar['dev'], 16)
            f = int(bar['fun'], 16)
            r = int(bar['reg'], 16)
            width = int(bar['width'], 16)
            if not self.cs.pci.is_enabled(b, d, f):
                return False
            if 8 == width:
                base_lo = self.cs.pci.read_dword(b, d, f, r)
                base_hi = self.cs.pci.read_dword(b, d, f, r + 4)
                base = (base_hi << 32) | base_lo
            else:
                base = self.cs.pci.read_dword(b, d, f, r)

            if 'enable_bit' in bar:
                en_mask = 1 << int(bar['enable_bit'])
                is_enabled = (0 != base & en_mask)

        return is_enabled

    #
    # Check if MMIO range is programmed by MMIO BAR name
    #
    def is_MMIO_BAR_programmed(self, bar_name):
        bar = self.cs.Cfg.MMIO_BARS[bar_name]

        if 'register' in bar:
            bar_reg = bar['register']
            if 'base_field' in bar:
                base_field = bar['base_field']
                base = self.cs.read_register_field(bar_reg, base_field, preserve_field_position=True)
            else:
                base = self.cs.read_register(bar_reg)
        else:
            # this method is not preferred (less flexible)
            b = int(bar['bus'], 16)
            d = int(bar['dev'], 16)
            f = int(bar['fun'], 16)
            r = int(bar['reg'], 16)
            width = int(bar['width'], 16)
            if 8 == width:
                base_lo = self.cs.pci.read_dword(b, d, f, r)
                base_hi = self.cs.pci.read_dword(b, d, f, r + 4)
                base = (base_hi << 32) | base_lo
            else:
                base = self.cs.pci.read_dword(b, d, f, r)

        #if 'mask' in bar: base &= int(bar['mask'],16)
        return (0 != base)

    #
    # Read MMIO register from MMIO range defined by MMIO BAR name
    #
    def read_MMIO_BAR_reg(self, bar_name, offset, size=4, bus=None):
        (bar_base, bar_size) = self.get_MMIO_BAR_base_address(bar_name, bus)
        # @TODO: check offset exceeds BAR size
        return self.read_MMIO_reg(bar_base, offset, size, bar_size)

    #
    # Write MMIO register from MMIO range defined by MMIO BAR name
    #
    def write_MMIO_BAR_reg(self, bar_name, offset, value, size=4, bus=None):
        (bar_base, bar_size) = self.get_MMIO_BAR_base_address(bar_name, bus)
        # @TODO: check offset exceeds BAR size
        return self.write_MMIO_reg(bar_base, offset, value, size, bar_size)

    def read_MMIO_BAR(self, bar_name, bus=None):
        (bar_base, bar_size) = self.get_MMIO_BAR_base_address(bar_name, bus)
        return self.read_MMIO(bar_base, bar_size)

    #
    # Dump MMIO range by MMIO BAR name
    #
    def dump_MMIO_BAR(self, bar_name):
        (bar_base, bar_size) = self.get_MMIO_BAR_base_address(bar_name)
        self.dump_MMIO(bar_base, bar_size)

    def list_MMIO_BARs(self):
        self.logger.log('')
        self.logger.log('--------------------------------------------------------------------------------------')
        self.logger.log(' MMIO Range   | BUS | BAR Register   | Base             | Size     | En? | Description')
        self.logger.log('--------------------------------------------------------------------------------------')
        for _bar_name in self.cs.Cfg.MMIO_BARS:
            if not self.is_MMIO_BAR_defined(_bar_name):
                continue
            _bar = self.cs.Cfg.MMIO_BARS[_bar_name]
            bus_data = []
            if 'register' in _bar:
                bus_data = self.cs.get_register_bus(_bar['register'])
                if not bus_data:
                    if 'bus' in self.cs.get_register_def(_bar['register']):
                        bus_data = [int(self.cs.get_register_def(_bar['register'])['bus'], 16)]
            elif 'bus' in _bar:
                bus_data = [int(_bar['bus'], 16)]
            else:
                continue
            for bus in bus_data:
                try:
                    (_base, _size) = self.get_MMIO_BAR_base_address(_bar_name, bus)
                except:
                    if self.logger.HAL:
                        self.logger.log("Unable to find MMIO BAR {}".format(_bar))
                    continue
                _en = self.is_MMIO_BAR_enabled(_bar_name)

                if 'register' in _bar:
                    _s = _bar['register']
                    if 'offset' in _bar:
                        _s += (' + 0x{:X}'.format(int(_bar['offset'], 16)))
                else:
                    _s = '{:02X}:{:02X}.{:01X} + {}'.format(int(_bar['bus'], 16), int(_bar['dev'], 16), int(_bar['fun'], 16), _bar['reg'])

                self.logger.log(' {:12} |  {:02X} | {:14} | {:016X} | {:08X} | {:d}   | {}'.format(_bar_name, bus or 0, _s, _base, _size, _en, _bar['desc']))
