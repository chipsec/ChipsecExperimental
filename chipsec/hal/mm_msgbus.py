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
Access to message bus (IOSF sideband) interface registers on Intel SoCs

References:

usage:
    >>> reg_read(port, register)
    >>> reg_write(port, register, data)
"""

from chipsec.hal import hal_base
from chipsec.exceptions import RegisterNotFoundError


class MMMsgBus(hal_base.HALBase):

    def __init__(self, cs):
        super(MMMsgBus, self).__init__(cs)
        self.p2sbHide = None

    def __hide_p2sb(self, hide):
        if not self.p2sbHide:
            if self.cs.Cfg.register_has_field("8086.P2SBC.P2SBC", "HIDE"):
                self.p2sbHide = {'reg': '8086.P2SBC.P2SBC', 'field': 'HIDE'}
            elif self.cs.Cfg.register_has_field("P2SB_HIDE", "HIDE"):
                self.p2sbHide = {'reg': '8086.P2SBC.P2SB_HIDE', 'field': 'HIDE'}
            else:
                raise RegisterNotFoundError('RegisterNotFound: P2SBC')

        hidden = not self.cs.is_device_enabled('8086.P2SBC', 0)

        if hide:
            self.cs.write_register_field(self.p2sbHide['reg'], self.p2sbHide['field'], 1)
        else:
            self.cs.write_register_field(self.p2sbHide['reg'], self.p2sbHide['field'], 0)
        return hidden

    def reg_read(self, port, register):
        was_hidden = False
        if self.cs.Cfg.is_register_defined('8086.P2SBC.P2SBC'):
            was_hidden = self.__hide_p2sb(False)
        mmio_addr = self.cs.mmio.get_MMIO_BAR_base_address('8086.P2SBC.SBREGBAR', 0)[0]
        reg_val = self.cs.mmio.read_MMIO_reg_dword(mmio_addr, ((port & 0xFF) << 16) | (register & 0xFFFF))
        if self.cs.Cfg.is_register_defined('8086.P2SBC.P2SBC') and was_hidden:
            self.__hide_p2sb(True)
        return reg_val

    def reg_write(self, port, register, data):
        was_hidden = False
        if self.cs.Cfg.is_register_defined('8086.P2SBC.P2SBC'):
            was_hidden = self.__hide_p2sb(False)
        mmio_addr = self.cs.mmio.get_MMIO_BAR_base_address('8086.P2SBC.SBREGBAR', 0)[0]
        reg_val = self.cs.mmio.write_MMIO_reg_dword(mmio_addr, ((port & 0xFF) << 16) | (register & 0xFFFF), data)
        if self.cs.Cfg.is_register_defined('8086.P2SBC.P2SBC') and was_hidden:
            self.__hide_p2sb(True)
        return reg_val
