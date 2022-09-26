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

>>> chipsec_util uefi_var list
>>> chipsec_util uefi_var find <name>|<GUID>
>>> chipsec_util uefi_var read|write|delete <name> <GUID> <efi_variable_file>
>>> chipsec_util uefi_var next <name> <GUID>

Examples:

>>> chipsec_util uefi_var list
>>> chipsec_util uefi_var find PK
>>> chipsec_util uefi_var read db D719B2CB-3D3A-4596-A3BC-DAD00E67656F db.bin
>>> chipsec_util uefi_var write db D719B2CB-3D3A-4596-A3BC-DAD00E67656F db.bin
>>> chipsec_util uefi_var delete db D719B2CB-3D3A-4596-A3BC-DAD00E67656F
>>> chipsec_util uefi_var next
"""

import os
from argparse import ArgumentParser
from uuid import UUID

from chipsec.command import BaseCommand
from chipsec.file import write_file
from chipsec.lib.uefi_common import EFI_STATUS_DICT
from chipsec.lib.uefi_variables import decode_EFI_variables, get_attr_string
from chipsec.hal.uefi import UEFI


# Unified Extensible Firmware Interface (UEFI)
class UEFIVARCommand(BaseCommand):

    def requires_driver(self):
        parser = ArgumentParser(usage=__doc__)
        subparsers = parser.add_subparsers()

        # var-read command args
        parser_var_read = subparsers.add_parser('read')
        parser_var_read.add_argument('name', type=str, help='name of variable to read')
        parser_var_read.add_argument('guid', type=lambda x: UUID(x), help='guid of variable to read')
        parser_var_read.add_argument('filename', type=str, nargs='?', default=None, help='output file to store read variable contents to')
        parser_var_read.set_defaults(func=self.var_read)

        # var-write command args
        parser_var_write = subparsers.add_parser('write')
        parser_var_write.add_argument('name', type=str, help='name of variable to write')
        parser_var_write.add_argument('guid', type=lambda x: UUID(x), help='guid of variable to write')
        parser_var_write.add_argument('filename', type=str, help='input file containing data to write to variable')
        parser_var_write.set_defaults(func=self.var_write)

        # var-delete command args
        parser_var_delete = subparsers.add_parser('delete')
        parser_var_delete.add_argument('name', type=str, help='name of variable to delete')
        parser_var_delete.add_argument('guid', type=lambda x: UUID(x), help='guid of variable to delete')
        parser_var_delete.set_defaults(func=self.var_delete)

        # var-list command args
        parser_var_list = subparsers.add_parser('list')
        parser_var_list.set_defaults(func=self.var_list)

        # var-find command args
        parser_var_find = subparsers.add_parser('find')
        parser_var_find.add_argument('name_guid', type=str, help='name or guid of variable to find')
        parser_var_find.set_defaults(func=self.var_find)

        # next command args
        parser_var_next = subparsers.add_parser('next')
        parser_var_next.add_argument('name', type=str, nargs='?', default=None, help='name of variable to read')
        parser_var_next.add_argument('guid', type=lambda x: UUID(x), nargs='?', default=None, help='guid of variable to read')
        parser_var_next.set_defaults(func=self.var_next)

        parser.parse_args(self.argv, namespace=self)

        return True

    def var_read(self):
        self.logger.log("[CHIPSEC] Reading EFI variable Name='{}' GUID={{{}}} to '{}' via Variable API..".format(self.name, self.guid, self.filename if self.filename is not None else "std_output"))
        var = self._uefi.get_EFI_variable(self.name, self.guid, self.filename)
        if self.filename is None:
            self.logger.log(var.data)

    def var_write(self):
        self.logger.log("[CHIPSEC] writing EFI variable Name='{}' GUID={{{}}} from '{}' via Variable API..".format(self.name, self.guid, self.filename))
        status = self._uefi.set_EFI_variable_from_file(self.name, self.guid, self.filename)
        self.logger.log("[CHIPSEC] status: {}".format(EFI_STATUS_DICT[status]))
        if status == 0:
            self.logger.log("[CHIPSEC] writing EFI variable was successful")
        else:
            self.logger.log_error("writing EFI variable failed")

    def var_delete(self):
        self.logger.log("[CHIPSEC] Deleting EFI variable Name='{}' GUID={{{}}} via Variable API..".format(self.name, self.guid))
        status = self._uefi.delete_EFI_variable(self.name, self.guid)
        self.logger.log("Returned {}".format(EFI_STATUS_DICT[status]))
        if status == 0:
            self.logger.log("[CHIPSEC] deleting EFI variable was successful")
        else:
            self.logger.log_error("deleting EFI variable failed")

    def var_list(self):
        self.logger.log("[CHIPSEC] Enumerating all EFI variables via OS specific EFI Variable API..")
        efi_vars = self._uefi.list_EFI_variables()
        if efi_vars is None:
            self.logger.log("[CHIPSEC] Could not enumerate EFI Variables (Legacy OS?). Exit..")
            return
        self.logger.log("[CHIPSEC] Decoding EFI Variables..")
        _orig_logname = self.logger.LOG_FILE_NAME
        self.logger.set_log_file('efi_variables.lst')
        nvram_pth = 'efi_variables.dir'
        if not os.path.exists(nvram_pth):
            os.makedirs(nvram_pth)
        decode_EFI_variables(efi_vars, nvram_pth)
        self.logger.set_log_file(_orig_logname)
        self.logger.log("[CHIPSEC] Variables are in efi_variables.lst log and efi_variables.dir directory")

    def var_find(self):
        _vars = self._uefi.list_EFI_variables()
        if _vars is None:
            self.logger.log_warning('Could not enumerate UEFI variables (non-UEFI OS?)')
            return
        is_guid = 0
        try:
            _input_var = str(UUID(self.name_guid))
            is_guid = 1
        except ValueError:
            _input_var = self.name_guid

        if is_guid:
            self.logger.log("[*] Searching for UEFI variable with GUID {{{}}}..".format(_input_var))
            for name in _vars:
                n = 0
                for var_info in _vars[name]:
                    if _input_var == var_info.guid:
                        var_fname = '{}_{}_{}_{:d}.bin'.format(name, var_info.guid, get_attr_string(var_info.attrs).strip(), n)
                        self.logger.log("Found UEFI variable {}:{}. Dumped to '{}'".format(var_info.guid, name, var_fname))
                        write_file(var_fname, var_info.data)
                    n += 1
        else:
            self.logger.log("[*] Searching for UEFI variable with name {}..".format(_input_var))
            name = _input_var
            if name in _vars.keys():
                n = 0
                for var_info in _vars[name]:
                    var_fname = '{}_{}_{}_{:d}.bin'.format(name, var_info.guid, get_attr_string(var_info.attrs).strip(), n)
                    self.logger.log_good("Found UEFI variable {}:{}. Dumped to '{}'".format(var_info.guid, name, var_fname))
                    write_file(var_fname, var_info.data)
                    n += 1

    def var_next(self):
        self.logger.log("[CHIPSEC] Reading Next EFI variable from Name='{}' GUID={{{}}} via Variable API..".format(self.name, self.guid))
        var, guid = self._uefi.get_next_variable(self.name, self.guid)
        self.logger.log("Next variable {} with GUID {}".format(var, guid))

    def run(self):
        self._uefi = UEFI(self.cs)
        self.func()


commands = {'uefi_var': UEFIVARCommand}
