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
Access to physical memory

usage:
    >>> read_physical_mem( 0xf0000, 0x100 )
    >>> write_physical_mem( 0xf0000, 0x100, buffer )
    >>> write_physical_mem_dowrd( 0xf0000, 0xdeadbeef )
    >>> read_physical_mem_dowrd( 0xfed40000 )
"""

import struct

from chipsec.hal.hal_base import HALBase
from chipsec.lib.display_format import print_buffer


class Memory(HALBase):
    def __init__(self, cs):
        super(Memory, self).__init__(cs)

    ####################################################################################
    #
    # Physical memory API using 64b Physical Address
    # (Same functions as below just using 64b PA instead of High and Low 32b parts of PA)
    #
    ####################################################################################

    # Reading physical memory

    def read_physical_mem(self, phys_address, length):
        self.logger.log_hal("[mem] 0x{:016X}".format(phys_address))
        buf = self.helper.read_phys_mem(phys_address, length)
        return buf

    def read_physical_mem_qword(self, phys_address):
        out_buf = self.read_physical_mem(phys_address, 8)
        value = struct.unpack('=Q', out_buf)[0]
        self.logger.log_hal('[mem] qword at PA = 0x{:016X}: 0x{:016X}'.format(phys_address, value))
        return value

    def read_physical_mem_dword(self, phys_address):
        out_buf = self.read_physical_mem(phys_address, 4)
        value = struct.unpack('=I', out_buf)[0]
        self.logger.log_hal('[mem] dword at PA = 0x{:016X}: 0x{:08X}'.format(phys_address, value))
        return value

    def read_physical_mem_word(self, phys_address):
        out_buf = self.read_physical_mem(phys_address, 2)
        value = struct.unpack('=H', out_buf)[0]
        self.logger.log_hal('[mem] word at PA = 0x{:016X}: 0x{:04X}'.format(phys_address, value))
        return value

    def read_physical_mem_byte(self, phys_address):
        out_buf = self.read_physical_mem(phys_address, 1)
        value = struct.unpack('=B', out_buf)[0]
        self.logger.log_hal('[mem] byte at PA = 0x{:016X}: 0x{:02X}'.format(phys_address, value))
        return value

    # Writing physical memory

    def write_physical_mem(self, phys_address, length, buf):
        self.logger.log_hal('[mem] buffer len = 0x{:X} to PA = 0x{:016X}'.format(length, phys_address))
        if self.logger.HAL:
            print_buffer(buf)
        return self.helper.write_phys_mem(phys_address, length, buf)

    def write_physical_mem_qword(self, phys_address, qword_value):
        self.logger.log_hal('[mem] qword to PA = 0x{:016X} <- 0x{:10X}'.format(phys_address, qword_value))
        return self.write_physical_mem(phys_address, 4, struct.pack('Q', qword_value))

    def write_physical_mem_dword(self, phys_address, dword_value):
        self.logger.log_hal('[mem] dword to PA = 0x{:016X} <- 0x{:08X}'.format(phys_address, dword_value))
        return self.write_physical_mem(phys_address, 4, struct.pack('I', dword_value))

    def write_physical_mem_word(self, phys_address, word_value):
        self.logger.log_hal('[mem] word to PA = 0x{:016X} <- 0x{:04X}'.format(phys_address, word_value))
        return self.write_physical_mem(phys_address, 2, struct.pack('H', word_value))

    def write_physical_mem_byte(self, phys_address, byte_value):
        self.logger.log_hal('[mem] byte to PA = 0x{:016X} <- 0x{:02X}'.format(phys_address, byte_value))
        return self.write_physical_mem(phys_address, 1, struct.pack('B', byte_value))

    def va2pa(self, va):
        (pa, error_code) = self.helper.va2pa(va)
        self.logger.log_hal('[mem] VA (0x{:016X}) -> PA (0x{:016X})'.format(va, pa))
        if error_code:
            self.logger.log_hal('[mem] Looks like VA (0x{:016X}) not mapped'.format(va))
            return
        return pa

    def alloc_physical_mem(self, length, max_phys_address=0xFFFFFFFFFFFFFFFF):
        (va, pa) = self.helper.alloc_physical_mem(length, max_phys_address)
        self.logger.log_hal('[mem] Allocated: PA = 0x{:016X}, VA = 0x{:016X}'.format(pa, va))
        return (va, pa)

    # Free physical memory buffer

    def free_physical_mem(self, pa):
        ret = self.helper.free_physical_mem(pa)
        self.logger.log_hal('[mem] Deallocated : PA = 0x{:016X}'.format(pa))
        return True if ret == 1 else False

    def set_mem_bit(self, addr, bit):
        addr += bit >> 3
        byte = self.read_physical_mem_byte(addr)
        self.write_physical_mem_byte(addr, (byte | (0x1 << (bit & 0x7))))
        return byte
