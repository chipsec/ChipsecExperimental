# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2022, Intel Corporation
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
#

"""
Main UEFI component using platform specific and common UEFI functionality
"""

import struct
from chipsec.defines import stringtobytes
from chipsec.file import read_file, write_file
from chipsec.hal.hal_base import HALBase
from chipsec.lib.display_format import print_buffer_bytes
from chipsec.lib.uefi_common import FWType, fw_types, EFI_REVISIONS, EFI_VENDOR_TABLE_FORMAT, EFI_TABLES
from chipsec.lib.uefi_common import EFI_VENDOR_TABLE, EFI_VENDOR_TABLE_SIZE, EFI_CONFIGURATION_TABLE
from chipsec.lib.uefi_common import EFI_TABLE_HEADER_SIZE, EFI_TABLE_HEADER, EFI_TABLE_HEADER_FMT
from chipsec.lib.uefi_common import MAX_EFI_TABLE_SIZE, EFI_SYSTEM_TABLE_SIGNATURE, EFI_RUNTIME_SERVICES_SIGNATURE
from chipsec.lib.uefi_common import EFI_BOOT_SERVICES_SIGNATURE, EFI_DXE_SERVICES_TABLE_SIGNATURE
from chipsec.lib.uefi_variables import EFI_VAR_DICT, find_EFI_variable_store
from chipsec.exceptions import OsHelperError


class UEFI(HALBase):
    def __init__(self, cs):
        super(UEFI, self).__init__(cs)
        self._FWType = FWType.EFI_FW_TYPE_UEFI

    ######################################################################
    # FWType defines platform/BIOS dependent formats like
    # format of EFI NVRAM, format of FV, etc.
    #
    # FWType chooses an element from the EFI_VAR_DICT Dictionary
    #
    # Default current platform type is EFI_FW_TYPE_UEFI
    ######################################################################

    def set_FWType(self, efi_nvram_format):
        if efi_nvram_format in fw_types:
            self._FWType = efi_nvram_format

    ######################################################################
    # EFI NVRAM Parsing Functions
    ######################################################################

    def dump_EFI_variables_from_SPI(self):
        return self.read_EFI_variables_from_SPI(0, 0x800000)

    def read_EFI_variables_from_SPI(self, BIOS_region_base, BIOS_region_size):
        rom = self.cs.spi.read_spi(BIOS_region_base, BIOS_region_size)
        efi_var_store = find_EFI_variable_store(rom, self._FWType)
        if efi_var_store:
            efi_vars = EFI_VAR_DICT[self._FWType]['func_getefivariables']
            return efi_vars
        return efi_var_store

    def read_EFI_variables_from_file(self, filename):
        rom = read_file(filename)
        efi_var_store = find_EFI_variable_store(rom, self._FWType)
        if efi_var_store:
            efi_vars = EFI_VAR_DICT[self._FWType]['func_getefivariables']
            return efi_vars
        return efi_var_store

    ######################################################################
    # Runtime Variable API Functions
    ######################################################################

    def list_EFI_variables(self):
        return self.helper.list_EFI_variables()

    def get_EFI_variable(self, name, guid, filename=None):
        var = self.helper.get_EFI_variable(name, guid)
        if var:
            if filename:
                write_file(filename, var)
            if self.logger.UTIL_TRACE or self.logger.HAL:
                print_buffer_bytes(var)
            self.logger.log_hal('[uefi] EFI variable {}:{} :'.format(guid, name))
        return var

    def set_EFI_variable(self, name, guid, var, datasize=None, attrs=None):
        self.logger.log_hal('[uefi] writing EFI variable {}:{} {}'.format(guid, name, '' if attrs is None else ('(attributes = {})'.format(attrs))))
        return self.helper.set_EFI_variable(name, guid, var, datasize, attrs)

    def set_EFI_variable_from_file(self, name, guid, filename, datasize=None, attrs=None):
        if filename is None:
            self.logger.log_error('File with EFI variable is not specified')
            return False
        var = read_file(filename)
        return self.set_EFI_variable(name, guid, var, datasize, attrs)

    def delete_EFI_variable(self, name, guid):
        self.logger.log_hal('[uefi] deleting EFI variable {}:{}'.format(guid, name))
        return self.helper.delete_EFI_variable(name, guid)

    ######################################################################
    # UEFI System Tables
    ######################################################################

    def find_EFI_Table(self, table_sig):
        (smram_base, _, _) = self.cs.cpu.get_SMRAM()
        CHUNK_SZ = 1024 * 1024  # 1MB
        self.logger.log_hal("[uefi] searching memory for EFI table with signature '{}' ..".format(table_sig))
        table_pa, table_header, table, table_buf = None, None, None, None
        pa = smram_base - CHUNK_SZ
        isFound = False
        (tseg_base, tseg_limit, _) = self.cs.cpu.get_TSEG()
        while pa > CHUNK_SZ:
            if (pa <= tseg_limit) and (pa >= tseg_base):
                self.logger.log_hal("[uefi] Skipping memory read at pa: {:016X}".format(pa))
                pa -= CHUNK_SZ
                continue
            self.logger.log_hal('[uefi] Reading 0x{:016X}..'.format(pa))
            try:
                membuf = self.cs.mem.read_physical_mem(pa, CHUNK_SZ)
            except OsHelperError as err:
                self.logger.log_hal("[uefi] Unable to read memory at pa: {:016X} Error: {}".format(pa, err))
                pa -= CHUNK_SZ
                continue
            pos = membuf.find(stringtobytes(table_sig))
            if -1 != pos:
                table_pa = pa + pos
                self.logger.log_hal("[uefi] found signature '{}' at 0x{:016X}..".format(table_sig, table_pa))
                if pos < (CHUNK_SZ - EFI_TABLE_HEADER_SIZE):
                    hdr = membuf[pos: pos + EFI_TABLE_HEADER_SIZE]
                else:
                    hdr = self.cs.mem.read_physical_mem(table_pa, EFI_TABLE_HEADER_SIZE)
                table_header = EFI_TABLE_HEADER(*struct.unpack_from(EFI_TABLE_HEADER_FMT, hdr))
                # do some sanity checks on the header
                is_reserved = table_header.Reserved != 0
                is_bad_crc = table_header.CRC32 == 0
                is_not_table_rev = table_header.Revision not in EFI_REVISIONS
                is_not_correct_size = table_header.HeaderSize > MAX_EFI_TABLE_SIZE
                if is_reserved or is_bad_crc or is_not_table_rev or is_not_correct_size:
                    self.logger.log_hal("[uefi] found '{}' at 0x{:016X} but doesn't look like an actual table. keep searching...".format(table_sig, table_pa))
                    self.logger.log_hal(table_header)
                else:
                    isFound = True
                    self.logger.log_hal("[uefi] found EFI table at 0x{:016X} with signature '{}'..".format(table_pa, table_sig))
                    table_size = struct.calcsize(EFI_TABLES[table_sig]['fmt'])
                    if pos < (CHUNK_SZ - EFI_TABLE_HEADER_SIZE - table_size):
                        table_buf = membuf[pos: pos + EFI_TABLE_HEADER_SIZE + table_size]
                    else:
                        table_buf = self.cs.mem.read_physical_mem(table_pa, EFI_TABLE_HEADER_SIZE + table_size)
                    table = EFI_TABLES[table_sig]['struct'](*struct.unpack_from(EFI_TABLES[table_sig]['fmt'], table_buf[EFI_TABLE_HEADER_SIZE:]))
                    if self.logger.HAL:
                        print_buffer_bytes(table_buf)
                    self.logger.log_hal('[uefi] {}:'.format(EFI_TABLES[table_sig]['name']))
                    self.logger.log_hal(table_header)
                    self.logger.log_hal(table)
                    break
            pa -= CHUNK_SZ
        if not isFound:
            self.logger.log_hal("[uefi] could not find EFI table with signature '{}'".format(table_sig))
        return (isFound, table_pa, table_header, table, table_buf)

    def find_EFI_System_Table(self):
        return self.find_EFI_Table(EFI_SYSTEM_TABLE_SIGNATURE)

    def find_EFI_RuntimeServices_Table(self):
        return self.find_EFI_Table(EFI_RUNTIME_SERVICES_SIGNATURE)

    def find_EFI_BootServices_Table(self):
        return self.find_EFI_Table(EFI_BOOT_SERVICES_SIGNATURE)

    def find_EFI_DXEServices_Table(self):
        return self.find_EFI_Table(EFI_DXE_SERVICES_TABLE_SIGNATURE)
    # def find_EFI_PEI_Table(self):
    #    return self.find_EFI_Table(EFI_FRAMEWORK_PEI_SERVICES_TABLE_SIGNATURE)
    # def find_EFI_SMM_System_Table(self):
    #    return self.find_EFI_Table(EFI_SMM_SYSTEM_TABLE_SIGNATURE)

    def find_EFI_Configuration_Table(self):
        ect_pa = None
        ect = None
        ect_buf = None
        (isFound, est_pa, est_header, est, est_buf) = self.find_EFI_System_Table()
        if isFound and est is not None:
            if 0 != est.BootServices:
                self.logger.log_hal("[uefi] UEFI appears to be in Boot mode")
                ect_pa = est.ConfigurationTable
            else:
                self.logger.log_hal("[uefi] UEFI appears to be in Runtime mode")
                ect_pa = self.cs.mem.va2pa(est.ConfigurationTable)
                if not ect_pa:
                    # Most likely the VA in the System Table is not mapped so find the RST by signature and
                    # then compute the address of the configuration table.  This assumes the VA mapping keeps
                    # the pages in the same relative location as in physical memory.
                    (rst_found, rst_pa, rst_header, rst, rst_buf) = self.find_EFI_RuntimeServices_Table()
                    if rst_found:
                        self.logger.log_hal("Attempting to derive configuration table address")
                        ect_pa = rst_pa + (est.ConfigurationTable - est.RuntimeServices)
                    else:
                        self.logger.log_hal("Can't find UEFI ConfigurationTable")
                        return (None, ect_pa, ect, ect_buf)

        self.logger.log_hal("[uefi] EFI Configuration Table ({:d} entries): VA = 0x{:016X}, PA = 0x{:016X}".format(est.NumberOfTableEntries, est.ConfigurationTable, ect_pa))

        found = (ect_pa is not None)
        if found:
            ect_buf = self.cs.mem.read_physical_mem(ect_pa, EFI_VENDOR_TABLE_SIZE * est.NumberOfTableEntries)
            ect = EFI_CONFIGURATION_TABLE()
            for i in range(est.NumberOfTableEntries):
                vt = EFI_VENDOR_TABLE(*struct.unpack_from(EFI_VENDOR_TABLE_FORMAT, ect_buf[i * EFI_VENDOR_TABLE_SIZE:]))
                ect.VendorTables[vt.VendorGuid()] = vt.VendorTable
        return (found, ect_pa, ect, ect_buf)

    def dump_EFI_tables(self):
        (found, pa, hdr, table, table_buf) = self.find_EFI_System_Table()
        if found:
            self.logger.log("[uefi] EFI System Table:")
            print_buffer_bytes(table_buf)
            self.logger.log(hdr)
            self.logger.log(table)
        (found, ect_pa, ect, ect_buf) = self.find_EFI_Configuration_Table()
        if found:
            self.logger.log("\n[uefi] EFI Configuration Table:")
            print_buffer_bytes(ect_buf)
            self.logger.log(ect)
        (found, pa, hdr, table, table_buf) = self.find_EFI_RuntimeServices_Table()
        if found:
            self.logger.log("\n[uefi] EFI Runtime Services Table:")
            print_buffer_bytes(table_buf)
            self.logger.log(hdr)
            self.logger.log(table)
        (found, pa, hdr, table, table_buf) = self.find_EFI_BootServices_Table()
        if found:
            self.logger.log("\n[uefi] EFI Boot Services Table:")
            print_buffer_bytes(table_buf)
            self.logger.log(hdr)
            self.logger.log(table)
        (found, pa, hdr, table, table_buf) = self.find_EFI_DXEServices_Table()
        if found:
            self.logger.log("\n[uefi] EFI DXE Services Table:")
            print_buffer_bytes(table_buf)
            self.logger.log(hdr)
            self.logger.log(table)
