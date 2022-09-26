# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation

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
The mem command provides direct access to read and write physical memory.

>>> chipsec_util mem <op> <physical_address> <length> [value|buffer_file]
>>> <physical_address> : 64-bit physical address
>>> <op>               : read|readval|write|writeval|allocate|pagedump|search
>>> <length>           : byte|word|dword or length of the buffer from <buffer_file>
>>> <value>            : byte, word or dword value to be written to memory at <physical_address>
>>> <buffer_file>      : file with the contents to be written to memory at <physical_address>

Examples:

>>> chipsec_util mem <op>     <physical_address> <length> [value|file]
>>> chipsec_util mem readval  0xFED40000         dword
>>> chipsec_util mem read     0x41E              0x20     buffer.bin
>>> chipsec_util mem writeval 0xA0000            dword    0x9090CCCC
>>> chipsec_util mem write    0x100000000        0x1000   buffer.bin
>>> chipsec_util mem write    0x100000000        0x10     000102030405060708090A0B0C0D0E0F
>>> chipsec_util mem allocate                    0x1000
>>> chipsec_util mem pagedump 0xFED00000         0x100000
>>> chipsec_util mem search   0xF0000            0x10000  _SM_
"""

from argparse import ArgumentParser
import os

from chipsec.command import BaseCommand, toLoad
from chipsec.defines import ALIGNED_4KB, BOUNDARY_4KB
from chipsec.file import read_file, write_file, get_main_dir
from chipsec.lib.display_format import print_buffer_bytes


# Physical Memory
class MemCommand(BaseCommand):

    def requires_driver(self):
        parser = ArgumentParser(prog='chipsec_util mem', usage=__doc__)
        subparsers = parser.add_subparsers()

        parser_read = subparsers.add_parser('read')
        parser_read.add_argument('phys_address', type=lambda x: int(x, 16), help='64-bit physical address (hex)')
        parser_read.add_argument('buffer_length', type=lambda x: int(x, 16), default=0x100, nargs='?',
                                 help='Length of buffer (hex)')
        parser_read.add_argument('file_name', type=str, default='', nargs='?', help='Buffer file name')
        parser_read.set_defaults(func=self.mem_read)

        parser_readval = subparsers.add_parser('readval')
        parser_readval.add_argument('phys_address', type=lambda x: int(x, 16), help='64-bit physical address (hex)')
        parser_readval.add_argument('width', type=lambda x: int(x, 16), choices=[1, 2, 4, 8],
                                    help='Width value [1, 2, 4, 8] (hex)')
        parser_readval.set_defaults(func=self.mem_readval)

        parser_write = subparsers.add_parser('write')
        parser_write.add_argument('phys_address', type=lambda x: int(x, 16), help='64-bit physical address (hex)')
        parser_write.add_argument('buffer_length', type=lambda x: int(x, 16), help='Length of buffer (hex)')
        parser_write.add_argument('buffer_data', type=str, help='Buffer data or file name')
        parser_write.set_defaults(func=self.mem_write)

        parser_writeval = subparsers.add_parser('writeval')
        parser_writeval.add_argument('phys_address', type=lambda x: int(x, 16), help='64-bit physical address (hex)')
        parser_writeval.add_argument('width', type=lambda x: int(x, 16), choices=[1, 2, 4, 8],
                                     help='Width value [1, 2, 4, 8] (hex)')
        parser_writeval.add_argument('write_data', type=lambda x: int(x, 16), help='Data to write')
        parser_writeval.set_defaults(func=self.mem_writeval)

        parser_allocate = subparsers.add_parser('allocate')
        parser_allocate.add_argument('allocate_length', type=lambda x: int(x, 16), help='Length to allocate (hex)')
        parser_allocate.set_defaults(func=self.mem_allocate)

        parser_pagedump = subparsers.add_parser('pagedump')
        parser_pagedump.add_argument('start_address', type=lambda x: int(x, 16), help='64-bit physical address (hex)')
        parser_pagedump.add_argument('length', type=lambda x: int(x, 16), nargs='?',
                                     default=BOUNDARY_4KB, help='Length to allocate (hex)')
        parser_pagedump.add_argument('to_file', type=bool, nargs='?', default=False, help="filename")
        parser_pagedump.set_defaults(func=self.mem_pagedump)

        parser_search = subparsers.add_parser('search')
        parser_search.add_argument('phys_address', type=lambda x: int(x, 16), help='64-bit physical address (hex)')
        parser_search.add_argument('length', type=lambda x: int(x, 16), help='Length to search (hex)')
        parser_search.add_argument('value', type=lambda x: x.encode('latin-1'), help='Value to search for')
        parser_search.set_defaults(func=self.mem_search)

        parser.parse_args(self.argv, namespace=self)

        return toLoad.Driver

    def mem_allocate(self):
        (va, pa) = self.cs.mem.alloc_physical_mem(self.allocate_length)
        self.logger.log('[CHIPSEC] Allocated {:X} bytes of physical memory: VA = 0x{:016X}, PA = 0x{:016X}'.format(
            self.allocate_length, va, pa))

    def mem_search(self):
        buffer = self.cs.mem.read_physical_mem(self.phys_address, self.length)
        offset = buffer.find(self.value)
        self.logger.log('[CHIPSEC] Search buffer from memory: PA = 0x{:016X}, len = 0x{:X}'.format(
            self.phys_address, self.length))

        if offset != -1:
            self.logger.log(
                'target address= 0x{:X}..'.format(self.phys_address + offset))
        else:
            self.logger.log('can not find the target in the searched range..')

    def mem_pagedump(self):
        head_len = self.start_address & ALIGNED_4KB
        tail_len = (self.start_address + self.length) & ALIGNED_4KB
        pa = self.start_address - head_len + ALIGNED_4KB + 1
        end = self.start_address + self.length - tail_len
        if self.to_file:
            fname = os.path.join(get_main_dir(), "m{:016X}.bin".format(self.start_address))
        else:
            fname = os.devnull
        with open(fname, 'wb') as f:
            # read leading bytes to the next boundary
            if (head_len > 0):
                buffer = self.cs.mem.read_physical_mem(self.start_address, ALIGNED_4KB + 1 - head_len)
                f.write(buffer)
                if not self.to_file:
                    print_buffer_bytes(buffer)

            for addr in range(pa, end, ALIGNED_4KB + 1):
                buffer = self.cs.mem.read_physical_mem(addr, ALIGNED_4KB + 1)
                f.write(buffer)
                if not self.to_file:
                    print_buffer_bytes(buffer)

            # read trailing bytes
            if (tail_len > 0):
                buffer = self.cs.mem.read_physical_mem(end, tail_len)
                f.write(buffer)
                if not self.to_file:
                    print_buffer_bytes(buffer)

    def mem_read(self):
        self.logger.log('[CHIPSEC] Reading buffer from memory: PA = 0x{:016X}, len = 0x{:X}..'.format(
            self.phys_address, self.buffer_length))
        buffer = self.cs.mem.read_physical_mem(self.phys_address, self.buffer_length)
        if self.file_name:
            write_file(self.file_name, buffer)
            self.logger.log("[CHIPSEC] Written 0x{:X} bytes to '{}'".format(len(buffer), self.file_name))
        else:
            print_buffer_bytes(buffer)

    def mem_readval(self):
        self.logger.log('[CHIPSEC] Reading {:X}-byte value from PA 0x{:016X}..'.format(self.width, self.phys_address))
        if 0x1 == self.width:
            value = self.cs.mem.read_physical_mem_byte(self.phys_address)
        elif 0x2 == self.width:
            value = self.cs.mem.read_physical_mem_word(self.phys_address)
        elif 0x4 == self.width:
            value = self.cs.mem.read_physical_mem_dword(self.phys_address)
        elif 0x8 == self.width:
            value = self.cs.mem.read_physical_mem_qword(self.phys_address)
        self.logger.log('[CHIPSEC] Value = 0x{:X}'.format(value))

    def mem_write(self):
        if not os.path.exists(self.buffer_data):
            try:
                buffer = bytearray.fromhex(self.buffer_data)
            except ValueError:
                self.logger.error("Incorrect <value> specified: '{}'".format(self.buffer_data))
                return
            self.logger.log("[CHIPSEC] Read 0x{:X} hex bytes from command-line: '{}'".format(len(buffer), self.buffer_data))
        else:
            buffer = read_file(self.buffer_data)
            self.logger.log("[CHIPSEC] Read 0x{:X} bytes from file '{}'".format(len(buffer), self.buffer_data))

        if len(buffer) < self.buffer_length:
            self.logger.error("Number of bytes read (0x{:X}) is less than the specified <length> (0x{:X})".format(
                len(buffer), self.buffer_length))
            return

        self.logger.log('[CHIPSEC] writing buffer to memory: PA = 0x{:016X}, len = 0x{:X}..'.format(
            self.phys_address, self.buffer_length))
        self.cs.mem.write_physical_mem(self.phys_address, self.buffer_length, buffer)

    def mem_writeval(self):
        self.logger.log('[CHIPSEC] Writing {:X}-byte value 0x{:X} to PA 0x{:016X}..'.format(
            self.width, self.write_data, self.phys_address))
        if 0x1 == self.width:
            self.cs.mem.write_physical_mem_byte(self.phys_address, self.write_data)
        elif 0x2 == self.width:
            self.cs.mem.write_physical_mem_word(self.phys_address, self.write_data)
        elif 0x4 == self.width:
            self.cs.mem.write_physical_mem_dword(self.phys_address, self.write_data)


commands = {'mem': MemCommand}
