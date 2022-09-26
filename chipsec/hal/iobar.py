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
I/O BAR access (dump, read/write)

usage:
    >>> get_IO_BAR_base_address(bar_name)
    >>> read_IO_BAR_reg(bar_name, offset, size)
    >>> write_IO_BAR_reg(bar_name, offset, size, value)
"""

from chipsec.hal import hal_base
from chipsec.exceptions import IOBARNotFoundError, CSReadError

DEFAULT_IO_BAR_SIZE = 0x100


class IOBAR(hal_base.HALBase):

    def __init__(self, cs):
        super(IOBAR, self).__init__(cs)

    #
    # Check if I/O BAR with bar_name has been defined in XML config
    # Use this function to fall-back to hardcoded config in case XML config is not available
    #
    def is_IO_BAR_defined(self, bar_name):
        is_bar_defined = False
        try:
            _bar = self.cs.Cfg.get_io_def(bar_name)
            if _bar is not None:
                if 'register' in _bar:
                    is_bar_defined = self.cs.Cfg.is_register_defined(_bar['register'])
        except KeyError:
            pass
        if not is_bar_defined:
            self.logger.log_hal("'{}' IO BAR definition not found/correct in XML config".format(bar_name))
        return is_bar_defined

    #
    # Get base address of I/O range by IO BAR name
    #
    def get_IO_BAR_base_address(self, bar_name, bus):
        bar = self.cs.Cfg.get_io_def(bar_name)
        if bar is None or bar == {}:
            raise IOBARNotFoundError('IOBARNotFound: {}'.format(bar_name))
        base = 0
        empty_base = 0

        if 'register' in bar and bus is not None:
            bar_reg = bar['register']
            if 'base_field' in bar:
                base_field = bar['base_field']
                try:
                    base = self.cs.read_register_field(bar_reg, base_field, True, bus)[0].value
                except Exception:
                    pass
                try:
                    empty_base = self.cs.get_register_field_mask(bar_reg, base_field, preserve_field_position=True)
                except Exception:
                    pass
            else:
                try:
                    base = self.cs.read_register(bar_reg, bus)[0].value
                except Exception:
                    pass
                try:
                    empty_base = self.cs.get_register_field_mask(bar_reg, preserve_field_position=True)
                except Exception:
                    pass

        if 'fixed_address' in bar and (base == empty_base or base == 0):
            base = bar['fixed_address']
            self.logger.log_hal('[iobar] Using fixed address for {}: 0x{:016X}'.format(bar_name, base))

        if 'mask' in bar:
            base = base & bar['mask']
        if 'offset' in bar:
            base = base + bar['offset']
        size = bar['size'] if ('size' in bar) else DEFAULT_IO_BAR_SIZE
        self.logger.log_hal('[iobar] {}: 0x{:04X} (size = 0x{:X})'.format(bar_name, base, size))
        if base == 0:
            raise CSReadError("IOBAR ({}) base address is 0".format(bar_name))
        return base, size

    #
    # Check if I/O range is enabled by BAR name
    #
    def is_IO_BAR_enabled(self, bar_name, bus):
        if not self.is_IO_BAR_defined(bar_name):
            return False
        bar = self.cs.Cfg.get_io_def(bar_name)
        is_enabled = True
        if 'register' in bar:
            bar_reg = bar['register']
            if 'enable_field' in bar:
                bar_en_field = bar['enable_field']
                is_enabled = (1 == self.cs.read_register_field(bar_reg, bar_en_field, instance=bus)[0].value)
        return is_enabled

    def list_IO_BARs(self):
        self.logger.log('')
        self.logger.log('------------------------------------------------------------------------------------------------')
        self.logger.log(' I/O Range    | BUS |       BAR Register       | Base             | Size     | En? | Description')
        self.logger.log('------------------------------------------------------------------------------------------------')
        for vid in self.cs.Cfg.IO_BARS:
            for dev in self.cs.Cfg.IO_BARS[vid]:
                for _bar_name in self.cs.Cfg.IO_BARS[vid][dev]:
                    bar_name = "{}.{}.{}".format(vid, dev, _bar_name)
                    if not self.is_IO_BAR_defined(bar_name):
                        continue
                    _bar = self.cs.Cfg.IO_BARS[vid][dev][_bar_name]
                    bus_data = self.cs.Cfg.get_device_bus("{}.{}".format(vid, dev))
                    for bus in bus_data:
                        try:
                            (_base, _size) = self.get_IO_BAR_base_address(bar_name, bus)
                        except CSReadError:
                            self.logger.log_hal("Unable to find IO BAR {}".format(_bar_name))
                            continue
                        _en = self.is_IO_BAR_enabled(bar_name, bus)

                        if 'register' in _bar:
                            _s = _bar['register']
                            if 'offset' in _bar:
                                _s += (' + 0x{:X}'.format(_bar['offset']))
                        self.logger.log(' {:12} |  {:02X} | {:24} | {:016X} | {:08X} | {:d}   | {}'.format(
                            _bar_name, bus, _s, _base, _size, _en, _bar['desc']))
