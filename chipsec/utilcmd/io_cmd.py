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
The io command allows direct access to read and write I/O port space.

>>> chipsec_util io list
>>> chipsec_util io dump <IO_BAR_name> [offset] [length]
>>> chipsec_util io dump-abs <io_port> [offset] [length]
>>> chipsec_util io read  <IO_BAR_name> <offset> <width>
>>> chipsec_util io read-abs  <io_port> <width>
>>> chipsec_util io write <IO_BAR_name> <offset> <width> <value>
>>> chipsec_util io write-abs <io_port> <width> <value>


Examples:

>>> chipsec_util io list
>>> chipsec_util io dump TCOBASE
>>> chipsec_util io dump-abs 0x400
>>> chipsec_util io read SMB_BASE 0x0 0x4
>>> chipsec_util io read-abs 0x61 1
>>> chipsec_util io write SMB_BASE 0x0 1 0x0
>>> chipsec_util io write-abs 0x430 1 0x0
"""

from argparse import ArgumentParser
from chipsec.command import BaseCommand, toLoad
from chipsec.lib.display_format import pretty_print_hex_buffer


class PortIOCommand(BaseCommand):

    def requires_driver(self):
        parser = ArgumentParser(prog='chipsec_util io', usage=__doc__)
        subparsers = parser.add_subparsers()

        # list
        parser_dump = subparsers.add_parser('list')
        parser_dump.set_defaults(func=self.io_list)

        # dump
        parser_dump = subparsers.add_parser('dump')
        parser_dump.add_argument('bar_name', type=str, help='MMIO BAR to dump')
        parser_dump.add_argument('offset', type=lambda x: int(x, 16), nargs='?', default=0,
                                 help='Offset in BAR to start dump')
        parser_dump.add_argument('length', type=lambda x: int(x, 16), nargs='?', default=None,
                                 help='Length of the region to dump')
        parser_dump.set_defaults(func=self.dump_bar)

        # dump-abs
        parser_dump_abs = subparsers.add_parser('dump-abs')
        parser_dump_abs.add_argument('base', type=lambda x: int(x, 16), help='MMIO region base address')
        parser_dump_abs.add_argument('offset', type=lambda x: int(x, 16), nargs='?', default=0,
                                     help='Offset in BAR to start dump')
        parser_dump_abs.add_argument('length', type=lambda x: int(x, 16), nargs='?', default=None,
                                     help='Length of the region to dump')
        parser_dump_abs.set_defaults(func=self.dump_bar_abs)

        # read
        parser_read = subparsers.add_parser('read')
        parser_read.add_argument('bar_name', type=str, help='IO BAR to read')
        parser_read.add_argument('offset', type=lambda x: int(x, 16), help='Offset value (hex)')
        parser_read.add_argument('width', type=lambda x: int(x, 16), choices=[1, 2, 4, 8],
                                 help='Width value [1, 2, 4, 8] (hex)')
        parser_read.add_argument('bus', type=lambda x: int(x, 16), help='bus value')
        parser_read.set_defaults(func=self.io_read_bar)

        # read-abs
        parser_r = subparsers.add_parser('read-abs')
        parser_r.add_argument('_port', metavar='port', type=lambda x: int(x, 0), help="io port")
        parser_r.add_argument('_width', metavar='width', type=int, choices=[0x1, 0x2, 0x4], help="width")
        parser_r.set_defaults(func=self.io_read_abs)

        # write
        parser_write = subparsers.add_parser('write')
        parser_write.add_argument('bar_name', type=str, help='IO BAR to write')
        parser_write.add_argument('offset', type=lambda x: int(x, 16), help='Offset value (hex)')
        parser_write.add_argument('width', type=lambda x: int(x, 16), choices=[1, 2, 4, 8],
                                  help='Width value [1, 2, 4, 8] (hex)')
        parser_write.add_argument('value', type=lambda x: int(x, 16), help='Value to write (hex)')
        parser_write.add_argument('bus', type=lambda x: int(x, 16), nargs='?', default=None, help='bus value')
        parser_write.set_defaults(func=self.io_write_bar)

        # write-abs
        parser_w = subparsers.add_parser('write-abs')
        parser_w.add_argument('_port', metavar='port', type=lambda x: int(x, 0), help="io port")
        parser_w.add_argument('_width', metavar='width', type=int, choices=[0x1, 0x2, 0x4], help="width")
        parser_w.add_argument('_value', metavar='value', type=lambda x: int(x, 0), help="value")
        parser_w.set_defaults(func=self.io_write_abs)

        parser.parse_args(self.argv, namespace=self)

        if self.func in [self.io_write_abs, self.io_read_abs, self.dump_bar_abs]:
            return toLoad.Driver
        return toLoad.All

    def io_list(self):
        self.cs.iobar.list_IO_BARs()

    def dump_bar(self):
        self.logger.log("[CHIPSEC] Dumping {} IO space..".format(self.bar_name.upper()))
        bus_data = self.cs.Cfg.get_device_bus(self.bar_name.upper())
        self.logger.log("[CHIPSEC] Found {:d} bus entries".format(len(bus_data)))
        for bus in bus_data:
            self.logger.log("[CHIPSEC] Dumping bus 0x{:X}".format(bus))
            (bar_base, bar_size) = self.cs.iobar.get_IO_BAR_base_address(self.bar_name.upper(), bus)
            if self.length is not None:
                bar_size = self.length
            else:
                bar_size -= self.offset
            bar_base += self.offset
            io_space = self.cs.io.dump_IO(bar_base, bar_size)
            pretty_print_hex_buffer(io_space)

    def dump_bar_abs(self):
        tmp_base = self.base + self.offset
        if self.length is None:
            tmp_length = 0x20
        else:
            tmp_length = self.length
        self.logger.log("[CHIPSEC] Dumping MMIO space 0x{:08X} to 0x{:08X}".format(tmp_base, tmp_base + tmp_length))
        io_space = self.cs.io.dump_IO(tmp_base, tmp_length)
        pretty_print_hex_buffer(io_space)

    def io_read_bar(self):
        bar = self.bar_name.upper()
        bar_base, bar_size = self.cs.iobar.get_IO_BAR_base_address(bar, self.bus)
        if self.offset + self.width > bar_size:
            self.logger.log_warning("[CHIPSEC] Write larger than bar size")
        bar_base += self.offset
        reg = self.cs.io.read_port(bar_base, self.width)
        self.logger.log("[CHIPSEC] Read {} + 0x{:X}: 0x{:0{width}X}".format(bar, self.offset, reg, width=self.width * 2))

    def io_read_abs(self):
        value = self.cs.io.read_port(self._port, self.width)
        self.logger.log("[CHIPSEC] IN 0x{:04X} -> 0x{:08X} (size = 0x{:02X})".format(self._port, value, self._width))
        return

    def io_write_bar(self):
        bar = self.bar_name.upper()
        bar_base, bar_size = self.cs.iobar.get_IO_BAR_base_address(bar, self.bus)
        if self.offset + self.width > bar_size:
            self.logger.log_warning("[CHIPSEC] Read larger than bar size")
        bar_base += self.offset
        self.cs.io.write_port(bar_base, self._value, self._width)
        self.logger.log(
            "[CHIPSEC] Write {} <- 0x{:08X} (size = 0x{:02X})".format(bar, self._value, self._width))
        return

    def io_write_abs(self):
        self.cs.io.write_port(self._port, self._value, self._width)
        self.logger.log(
            "[CHIPSEC] OUT 0x{:04X} <- 0x{:08X} (size = 0x{:02X})".format(self._port, self._value, self._width))
        return


commands = {'io': PortIOCommand}
