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
The mmcfg command allows direct access to memory mapped config space.

>>> chipsec_util mmcfg base
>>> chipsec_util mmcfg read <bus> <device> <function> <offset> <width>
>>> chipsec_util mmcfg write <bus> <device> <function> <offset> <width> [value]


Examples:

>>> chipsec_util mmcfg base
>>> chipsec_util mmcfg read 0 0 0 0x200 4
>>> chipsec_util mmcfg write 0 0 0 0x200 1 0x1A
"""

from chipsec.command import BaseCommand, toLoad
from argparse import ArgumentParser


# Access to Memory Mapped PCIe Configuration Space (MMCFG)
class MMCfgCommand(BaseCommand):

    def requires_driver(self):
        parser = ArgumentParser(prog='chipsec_util mmcfg', usage=__doc__)
        subparsers = parser.add_subparsers()

        parser_base = subparsers.add_parser('base')
        parser_base.set_defaults(func=self.base)
        parser_base.add_argument('bus', type=lambda x: int(x, 16), nargs='?', default=0, help='Bus (hex)')

        parser_read = subparsers.add_parser('read')
        parser_read.set_defaults(func=self.read)
        parser_read.add_argument('bus', type=lambda x: int(x, 16), help='Bus (hex)')
        parser_read.add_argument('device', type=lambda x: int(x, 16), help='Device (hex)')
        parser_read.add_argument('function', type=lambda x: int(x, 16), help='Function (hex)')
        parser_read.add_argument('offset', type=lambda x: int(x, 16), help='Offset (hex)')
        parser_read.add_argument('width', type=int, choices=[1, 2, 4], help='Width')

        parser_write = subparsers.add_parser('write')
        parser_write.set_defaults(func=self.write)
        parser_write.add_argument('bus', type=lambda x: int(x, 16), help='Bus (hex)')
        parser_write.add_argument('device', type=lambda x: int(x, 16), help='Device (hex)')
        parser_write.add_argument('function', type=lambda x: int(x, 16), help='Function (hex)')
        parser_write.add_argument('offset', type=lambda x: int(x, 16), help='Offset (hex)')
        parser_write.add_argument('width', type=int, choices=[1, 2, 4], help='Width')
        parser_write.add_argument('value', type=lambda x: int(x, 16), help='Value to write (hex)')

        parser.parse_args(self.argv, namespace=self)

        return toLoad.All

    def base(self):
        pciexbar, pciexbar_sz = self.cs.mmcfg.get_MMCFG_base_address(self.bus)
        self.logger.log("[CHIPSEC] Memory Mapped Config Base: 0x{:016X}".format(pciexbar))
        self.logger.log("[CHIPSEC] Memory Mapped Config Size: 0x{:016X}".format(pciexbar_sz))

    def read(self):
        data = self.cs.mmcfg.read_mmcfg_reg(self.bus, self.device, self.function, self.offset, self.width)
        self.logger.log("[CHIPSEC] Reading MMCFG register ({:02d}:{:02d}.{:d} + 0x{:02X}): 0x{:X}".format(
            self.bus, self.device, self.function, self.offset, data))

    def write(self):
        self.cs.mmcfg.write_mmcfg_reg(self.bus, self.device, self.function, self.offset, self.width, self.value)
        self.logger.log("[CHIPSEC] Writing MMCFG register ({:02d}:{:02d}.{:d} + 0x{:02X}): 0x{:X}".format(
            self.bus, self.device, self.function, self.offset, self.value))


commands = {'mmcfg': MMCfgCommand}
