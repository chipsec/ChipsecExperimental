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
>>> chipsec_util mm_msgbus read  <port> <register>
>>> chipsec_util mm_msgbus write <port> <register> <value>
>>>
>>> <port>    : message bus port of the target unit
>>> <register>: message bus register/offset in the target unit port
>>> <value>   : value to be written to the message bus register/offset

Examples:

>>> chipsec_util mm_msgbus read  0xc3 0x3400
>>> chipsec_util mm_msgbus write 0x3 0x27 0xE0000001
"""

from argparse import ArgumentParser
from chipsec.command import BaseCommand, toLoad


# Message Bus
class MMMsgBusCommand(BaseCommand):

    def requires_driver(self):
        parser = ArgumentParser(prog='chipsec_util msgbus', usage=__doc__)
        subparsers = parser.add_subparsers()

        parser_mmread = subparsers.add_parser('read')
        parser_mmread.add_argument('port', type=lambda x: int(x, 16), help='Port (hex)')
        parser_mmread.add_argument('reg', type=lambda x: int(x, 16), help='Register (hex)')
        parser_mmread.set_defaults(func=self.msgbus_mm_read)

        parser_mmwrite = subparsers.add_parser('write')
        parser_mmwrite.add_argument('port', type=lambda x: int(x, 16), help='Port (hex)')
        parser_mmwrite.add_argument('reg', type=lambda x: int(x, 16), help='Register (hex)')
        parser_mmwrite.add_argument('val', type=lambda x: int(x, 16), help='Value (hex)')
        parser_mmwrite.set_defaults(func=self.msgbus_mm_write)

        parser.parse_args(self.argv, namespace=self)

        return toLoad.Driver

    def msgbus_mm_read(self):
        self.logger.log("[CHIPSEC] MMIO msgbus read: port 0x{:02X} + 0x{:08X}".format(self.port, self.reg))
        try:
            ret = self.cs.mm_msgbus.reg_read(self.port, self.reg)
        except Exception:
            self.logger.log_error("Unable to read memory region")
            ret = None
        if ret is not None:
            self.logger.log("[CHIPSEC] Result: 0x{:08X}".format(ret))
        return ret

    def msgbus_mm_write(self):
        self.logger.log("[CHIPSEC] MMIO msgbus write: port 0x{:02X} + 0x{:08X} < 0x{:08X}".format(self.port, self.reg, self.val))
        return self.cs.mm_msgbus.reg_write(self.port, self.reg, self.val)


commands = {'mm_msgbus': MMMsgBusCommand}
