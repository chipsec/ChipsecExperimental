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


"""
The vmem command provides direct access to read and write virtual memory.

>>> chipsec_util vmem <op> <virtual_address> <length> [value|buffer_file]
>>>
>>> <physical_address> : 64-bit physical address
>>> <op>               : read|readval|write|writeval|allocate|pagedump|search|getphys
>>> <length>           : byte|word|dword or length of the buffer from <buffer_file>
>>> <value>            : byte, word or dword value to be written to memory at <physical_address>
>>> <buffer_file>      : file with the contents to be written to memory at <physical_address>

Examples:

>>> chipsec_util vmem <op>     <virtual_address>  <length> [value|file]
>>> chipsec_util vmem readval  0xFED40000         dword
>>> chipsec_util vmem read     0x41E              0x20     buffer.bin
>>> chipsec_util vmem writeval 0xA0000            dword    0x9090CCCC
>>> chipsec_util vmem write    0x100000000        0x1000   buffer.bin
>>> chipsec_util vmem write    0x100000000        0x10     000102030405060708090A0B0C0D0E0F
>>> chipsec_util vmem allocate                    0x1000
>>> chipsec_util vmem search   0xF0000            0x10000  _SM_
>>> chipsec_util vmem getphys  0xFED00000
"""

from argparse import ArgumentParser
import os

from chipsec.command import BaseCommand, toLoad
from chipsec.hal.virtmem import VirtMemory
from chipsec.lib.display_format import print_buffer_bytes
from chipsec.file import write_file, read_file


# Virtual Memory
class VMemCommand(BaseCommand):

    def requires_driver(self):
        parser = ArgumentParser(usage=__doc__)
        subparsers = parser.add_subparsers()

        parser_read = subparsers.add_parser('read')
        parser_read.add_argument('virt_address', type=lambda x: int(x, 16), help='64-bit virtual address (hex)')
        parser_read.add_argument('buffer_length', type=lambda x: int(x, 16), default=0x100, nargs='?',
                                 help='Length of buffer (hex)')
        parser_read.add_argument('file_name', type=str, default='', nargs='?', help='Buffer file name')
        parser_read.set_defaults(func=self.vmem_read)

        parser_readval = subparsers.add_parser('readval')
        parser_readval.add_argument('virt_address', type=lambda x: int(x, 16), help='64-bit virtual address (hex)')
        parser_readval.add_argument('width', type=lambda x: int(x, 16), choices=[1, 2, 4, 8],
                                    help='Width value [1, 2, 4, 8] (hex)')
        parser_readval.set_defaults(func=self.vmem_readval)

        parser_write = subparsers.add_parser('write')
        parser_write.add_argument('virt_address', type=lambda x: int(x, 16), help='Address (hex)')
        parser_write.add_argument('buffer_length', type=lambda x: int(x, 16), help='Length of buffer (hex)')
        parser_write.add_argument('buffer_data', type=str, help='Buffer data or file name')
        parser_write.set_defaults(func=self.vmem_write)

        parser_writeval = subparsers.add_parser('writeval')
        parser_writeval.add_argument('virt_address', type=lambda x: int(x, 16), help='Address (hex)')
        parser_writeval.add_argument('width', type=lambda x: int(x, 16), choices=[1, 2, 4, 8],
                                     help='Width value [1, 2, 4, 8] (hex)')
        parser_writeval.add_argument('write_data', type=lambda x: int(x, 16), help='Data to write')
        parser_writeval.set_defaults(func=self.vmem_writeval)

        parser_allocate = subparsers.add_parser('allocate')
        parser_allocate.add_argument('size', type=lambda x: int(x, 16), help='Size of memory to allocate (hex)')
        parser_allocate.set_defaults(func=self.vmem_allocate)

        parser_search = subparsers.add_parser('search')
        parser_search.add_argument('virt_address', type=lambda x: int(x, 16), help='Address (hex)')
        parser_search.add_argument('length', type=lambda x: int(x, 16), help='Length to search (hex)')
        parser_search.add_argument('value', type=lambda x: x.encode('latin-1'), help='Value to search for')
        parser_search.set_defaults(func=self.vmem_search)

        parser_getphys = subparsers.add_parser('getphys')
        parser_getphys.add_argument('virt_address', type=lambda x: int(x, 16), help='Address (hex)')
        parser_getphys.set_defaults(func=self.vmem_getphys)
        parser.parse_args(self.argv, namespace=self)

        return toLoad.Driver

    def vmem_read(self):
        self.logger.log('[CHIPSEC] Reading buffer from memory: VA = 0x{:016X}, len = 0x{:X}.'.format(self.virt_address, self.buffer_length))
        try:
            buffer = self._vmem.read_virtual_mem(self.virt_address, self.buffer_length)
        except (TypeError, OSError):
            self.logger.log_error('Error mapping VA to PA.')
            return

        if self.file_name:
            write_file(self.file_name, buffer)
            self.logger.log("[CHIPSEC] Written 0x{:X} bytes to '{}'".format(len(buffer), self.file_name))
        else:
            print_buffer_bytes(buffer)

    def vmem_readval(self):
        self.logger.log('[CHIPSEC] Reading {:X}-byte value from VA 0x{:016X}.'.format(self.width, self.virt_address))
        try:
            if 0x1 == self.width:
                value = self._vmem.read_virtual_mem_byte(self.virt_address)
            elif 0x2 == self.width:
                value = self._vmem.read_virtual_mem_word(self.virt_address)
            elif 0x4 == self.width:
                value = self._vmem.read_virtual_mem_dword(self.virt_address)
            elif 0x8 == self.width:
                value = self._vmem.read_virtual_mem_qword(self.virt_address)
        except (TypeError, OSError):
            self.logger.error('Error mapping VA to PA.')
            return
        self.logger.log('[CHIPSEC] value = 0x{:X}'.format(value))

    def vmem_write(self):
        if not os.path.exists(self.buffer_data):
            try:
                buffer = bytearray.fromhex(self.buffer_data)
            except ValueError as e:
                self.logger.log_error("Incorrect <value> specified: '{}'".format(self.buffer_data))
                self.logger.log_error(str(e))
                return
            self.logger.log("[CHIPSEC] Read 0x{:X} hex bytes from command-line: {}'".format(len(buffer), self.buffer_data))
        else:
            buffer = read_file(self.buffer_data)
            self.logger.log("[CHIPSEC] Read 0x{:X} bytes from file '{}'".format(len(buffer), self.buffer_data))

        if len(buffer) < self.buffer_length:
            self.logger.error("Number of bytes read (0x{:X}) is less than the specified <length> (0x{:X})".format(len(buffer), self.size))
            return

        self.logger.log('[CHIPSEC] Writing buffer to memory: VA = 0x{:016X}, len = 0x{:X}.'.format(self.virt_address, self.buffer_length))
        self._vmem.write_virtual_mem(self.virt_address, self.buffer_length, buffer)

    def vmem_writeval(self):
        self.logger.log('[CHIPSEC] Writing {:X}-byte value 0x{:X} to VA 0x{:016X}..'.format(
            self.width, self.write_data, self.virt_address))
        try:
            if 0x1 == self.width:
                self._vmem.write_virtual_mem_byte(self.virt_address, self.write_data)
            elif 0x2 == self.width:
                self._vmem.write_virtual_mem_word(self.virt_address, self.write_data)
            elif 0x4 == self.width:
                self._vmem.write_virtual_mem_dword(self.virt_address, self.write_data)
        except (TypeError, OSError):
            self.logger.error('Error mapping VA to PA.')

    def vmem_search(self):
        try:
            buffer = self._vmem.read_virtual_mem(self.virt_address, self.length)
        except (TypeError, OSError):
            self.logger.error('Error mapping VA to PA.')
            return

        offset = buffer.find(self.value)

        self.logger.log("[CHIPSEC] Search buffer for '{}':".format(self.value))
        self.logger.log('          VA = 0x{:016X}, len = 0x{:X}'.format(self.virt_address, self.length))
        if offset != -1:
            self.logger.log('[CHIPSEC] Target address = 0x{:X}.'.format(self.virt_address + offset))
        else:
            self.logger.log('[CHIPSEC] Could not find the target in the searched range.')

    def vmem_allocate(self):
        try:
            (va, pa) = self._vmem.alloc_virtual_mem(self.size)
        except (TypeError, OSError):
            self.logger.error('Error mapping VA to PA.')
            return
        self.logger.log('[CHIPSEC] Allocated {:X} bytes of virtual memory:'.format(self.size))
        self.logger.log('          VA = 0x{:016X}'.format(va))
        self.logger.log('          PA = 0x{:016X}'.format(pa))

    def vmem_getphys(self):
        try:
            pa = self._vmem.va2pa(self.virt_address)
        except (TypeError, OSError):
            self.logger.error('Error mapping VA to PA.')
            return
        if pa is not None:
            self.logger.log('[CHIPSEC] Virtual memory:')
            self.logger.log('          VA = 0x{:016X}'.format(self.virt_address))
            self.logger.log('          PA = 0x{:016X}'.format(pa))

    def run(self):
        self._vmem = VirtMemory(self.cs)
        self.func()


commands = {'vmem': VMemCommand}
