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
The uefi command provides access to UEFI variables, both on the live system and in a SPI flash image file.

>>> chipsec_util uefi types
>>> chipsec_util uefi decode --fwtype <rom_file> [filetypes]

Examples:

>>> chipsec_util uefi types
>>> chipsec_util uefi decode uefi.rom
>>> chipsec_util uefi decode uefi.rom FV_MM
"""

import os
from argparse import ArgumentParser

from chipsec.command import BaseCommand, toLoad
from chipsec.lib.spi_uefi import decode_uefi_region
from chipsec.lib.uefi_fv import FILE_TYPE_NAMES


# Unified Extensible Firmware Interface (UEFI)
class UEFICommand(BaseCommand):

    def requires_driver(self):
        parser = ArgumentParser(prog='chipsec_util uefi', usage=__doc__)
        subparsers = parser.add_subparsers()

        # decode command args
        parser_decode = subparsers.add_parser('decode')
        parser_decode.add_argument('filename', type=str, help='bios image to decompress')
        parser_decode.add_argument('--fwtype', dest='fwtype', type=str, nargs='?', default=None)
        parser_decode.add_argument('filetypes', type=str, nargs='*', default=[], help=FILE_TYPE_NAMES.values())
        parser_decode.set_defaults(func=self.decode)

        parser.parse_args(self.argv, namespace=self)

        # No driver for decode functionality
        if 'decode' in self.argv:
            return toLoad.Nil
        return toLoad.All

    def decode(self):
        if not os.path.exists(self.filename):
            self.logger.error("Could not find file '{}'".format(self.filename))
            return

        self.logger.log("[CHIPSEC] Parsing EFI volumes from '{}'..".format(self.filename))
        _orig_logname = self.logger.LOG_FILE_NAME
        self.logger.set_log_file(self.filename + '.UEFI.lst')
        cur_dir = self.cs.helper.getcwd()
        ftypes = []
        inv_filetypes = {v: k for k, v in FILE_TYPE_NAMES.items()}
        if self.filetypes:
            for mtype in self.filetypes:
                if mtype in inv_filetypes:
                    if inv_filetypes[mtype] not in ftypes:
                        ftypes.append(inv_filetypes[mtype])
                    break
        decode_uefi_region(cur_dir, self.filename, self.fwtype, ftypes)
        self.logger.set_log_file(_orig_logname)


commands = {'uefi': UEFICommand}
