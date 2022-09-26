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
Access to Port I/O

usage:
    >>> read_port_byte(0x61)
    >>> read_port_word(0x61)
    >>> read_port_dword(0x61)
    >>> write_port_byte(0x71, 0)
    >>> write_port_word(0x71, 0)
    >>> write_port_dword(0x71, 0)
"""

from chipsec.hal.hal_base import HALBase
from chipsec.logger import logger


class PortIO(HALBase):

    def __init__(self, cs):
        super(PortIO, self).__init__(cs)

    def read_port(self, io_port, size):
        value = self.helper.read_io_port(io_port, size)
        logger().log_hal("[io] IN 0x{:04X}: value = 0x{:08X}, size = 0x{:02X}".format(io_port, value, size))
        return value

    def write_port(self, io_port, value, size):
        logger().log_hal("[io] OUT 0x{:04X}: value = 0x{:08X}, size = 0x{:02X}".format(io_port, value, size))
        status = self.helper.write_io_port(io_port, value, size)
        return status

    def read_port_dword(self, io_port):
        value = self.read_port(io_port, 4)
        logger().log_hal("[io] reading dword from I/O port 0x{:04X} -> 0x{:08X}".format(io_port, value))
        return value

    def read_port_word(self, io_port):
        value = self.read_port(io_port, 2)
        logger().log_hal("[io] reading word from I/O port 0x{:04X} -> 0x{:04X}".format(io_port, value))
        return value

    def read_port_byte(self, io_port):
        value = self.read_port(io_port, 1)
        logger().log_hal("[io] reading byte from I/O port 0x{:04X} -> 0x{:02X}".format(io_port, value))
        return value

    def write_port_byte(self, io_port, value):
        logger().log_hal("[io] writing byte to I/O port 0x{:04X} <- 0x{:02X}".format(io_port, value))
        self.write_port(io_port, value, 1)
        return

    def write_port_word(self, io_port, value):
        logger().log_hal("[io] writing word to I/O port 0x{:04X} <- 0x{:04X}".format(io_port, value))
        self.write_port(io_port, value, 2)
        return

    def write_port_dword(self, io_port, value):
        logger().log_hal("[io] writing dword to I/O port 0x{:04X} <- 0x{:08X}".format(io_port, value))
        self.write_port(io_port, value, 4)
        return

    #
    # Dump I/O range
    #
    def dump_IO(self, range_base, range_size, size=1):
        n = range_size // size
        res = []
        for i in range(n):
            reg = self.read_port(range_base + i * size, size)
            for shift in range(0, size * 8, 8):
                res.append((reg >> shift) & 0xFF)
        return res

