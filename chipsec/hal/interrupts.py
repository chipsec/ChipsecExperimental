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
Functionality encapsulating interrupt generation
CPU Interrupts specific functions (SMI, NMI)

usage:
    >>> send_SMI_APMC(0xDE)
    >>> send_NMI()
"""

# TODO IPIs through Local APIC??

import struct
import uuid

from chipsec.hal import hal_base
from chipsec.lib.display_format import print_buffer_bytes
from chipsec.hal.acpi import ACPI
from chipsec.lib.acpi_tables import UEFI_TABLE

SMI_APMC_PORT = 0xB2

NMI_TCO1_CTL = 0x8  # NMI_NOW is bit [8] in TCO1_CTL (or bit [1] in TCO1_CTL + 1)
NMI_NOW = 0x1


class Interrupts(hal_base.HALBase):

    def __init__(self, cs):
        super(Interrupts, self).__init__(cs)

    def send_SW_SMI(self, thread_id, SMI_code_port_value, SMI_data_port_value, _rax, _rbx, _rcx, _rdx, _rsi, _rdi):
        SMI_code_data = (SMI_data_port_value << 8 | SMI_code_port_value)
        self.logger.log_hal("[intr] Sending SW SMI: code port 0x{:02X} <- 0x{:02X}, data port 0x{:02X} <- 0x{:02X} (0x{:04X})".format(SMI_APMC_PORT, SMI_code_port_value, SMI_APMC_PORT + 1, SMI_data_port_value, SMI_code_data))
        self.logger.log_hal("       RAX = 0x{:016X} (AX will be overridden with values of SW SMI ports B2/B3)".format(_rax))
        self.logger.log_hal("       RBX = 0x{:016X}".format(_rbx))
        self.logger.log_hal("       RCX = 0x{:016X}".format(_rcx))
        self.logger.log_hal("       RDX = 0x{:016X} (DX will be overridden with 0x00B2)".format(_rdx))
        self.logger.log_hal("       RSI = 0x{:016X}".format(_rsi))
        self.logger.log_hal("       RDI = 0x{:016X}".format(_rdi))
        return self.cs.helper.send_sw_smi(thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi)

    def send_SMI_APMC(self, SMI_code_port_value, SMI_data_port_value):
        SMI_code_data = (SMI_data_port_value << 8 | SMI_code_port_value)
        self.logger.log_hal("[intr] sending SMI via APMC ports: code 0xB2 <- 0x{:02X}, data 0xB3 <- 0x{:02X} (0x{:04X})".format(SMI_code_port_value, SMI_data_port_value, SMI_code_data))
        return self.cs.io.write_port_word(SMI_APMC_PORT, SMI_code_data)

    def send_NMI(self):
        self.logger.log_hal("[intr] Sending NMI# through TCO1_CTL[NMI_NOW]")
        reg = self.cs.Cfg.get_io_def("8086.SMBUS.TCOBASE")
        if reg is not None:
            tcobase = self.cs.read_register_field(reg['register'], reg['base_field'])[0].value
            return self.cs.io.write_port_byte(tcobase + NMI_TCO1_CTL + 1, NMI_NOW)
        else:
            self.logger.log("Unable to find register 8086.SMBUS.TCOBASE")

    def find_ACPI_SMI_Buffer(self):
        self.logger.log_hal("Parsing ACPI tables to identify Communication Buffer")
        _acpi = ACPI(self.cs).get_ACPI_table("UEFI")
        if len(_acpi):
            _uefi = UEFI_TABLE()
            _uefi.parse(_acpi[0][1])
            self.logger.log_hal(str(_uefi))
            return _uefi.get_commbuf_info()
        self.logger.log_hal("Unable to find Communication Buffer")
        return None

    def send_ACPI_SMI(self, thread_id, smi_num, buf_addr, invoc_reg, guid, data):
        # Prepare Communication Data buffer
        # typedef struct {
        #   EFI_GUID HeaderGuid;
        #   UINTN MessageLength;
        #   UINT8 Data[ANYSIZE_ARRAY];
        # } EFI_SMM_COMMUNICATE_HEADER;
        _guid = uuid.UUID(guid).bytes_le
        data_hdr = _guid + struct.pack("Q", len(data)) + data
        if invoc_reg is not None:
            # need to write data_hdr to comm buffer
            tmp_buf = self.cs.mem.write_physical_mem(buf_addr, len(data_hdr), data_hdr)
            # USING GAS need to write buf_addr into invoc_reg
            if invoc_reg.addrSpaceID == 0:
                self.cs.mem.write_physical_mem(invoc_reg.addr, invoc_reg.access_size, buf_addr)
                # check for return status
                ret_buf = self.cs.mem.read_physical_mem(buf_addr, 8)
            elif invoc_reg.addrSpaceID == 1:
                self.cs.io._write_io_port(invoc_reg.addr, invoc_reg.access_size, buf_addr)
                # check for return status
                ret_buf = self.cs.io._read_io_port(buf_addr, 8)
            else:
                self.logger.log_error("Functionality is currently not implemented")
                ret_buf = None
            return ret_buf

        else:
            # Wait for Communication buffer to be empty
            buf = 1
            while not buf == b"\x00\x00":
                buf = self.cs.mem.read_physical_mem(buf_addr, 2)
            # write data to commbuffer
            tmp_buf = self.cs.mem.write_physical_mem(buf_addr, len(data_hdr), data_hdr)
            # call SWSMI
            self.send_SW_SMI(thread_id, smi_num, 0, 0, 0, 0, 0, 0, 0)
            # clear CommBuffer
            self.cs.mem.write_physical_mem(buf_addr, len(data_hdr), b"\x00" * len(data_hdr))
            return None

    # scan phys mem range start-end looking for 'smmc'
    def find_smmc(self, start, end):
        chunk_sz = 1024 * 8  # 8KB chunks
        phys_address = start
        found_at = 0
        while phys_address <= end:
            buffer = self.cs.mem.read_physical_mem(phys_address, chunk_sz)
            offset = buffer.find(b'smmc')
            if offset != -1:
                found_at = phys_address + offset
                break
            phys_address += chunk_sz
        return found_at

    '''
Send SWSMI in the same way as EFI_SMM_COMMUNICATION_PROTOCOL
    - Write Commbuffer location and Commbuffer size to 'smmc' structure
    - Write 0 to 0xb3 and 0xb2

MdeModulePkg/Core/PiSmmCore/PiSmmCorePrivateData.h

#define SMM_CORE_PRIVATE_DATA_SIGNATURE  SIGNATURE_32 ('s', 'm', 'm', 'c')
 struct {
  UINTN                           Signature;
   This field is used by the SMM Communicatioon Protocol to pass a buffer into
   a software SMI handler and for the software SMI handler to pass a buffer back to
   the caller of the SMM Communication Protocol.
  VOID                            *CommunicationBuffer;
  UINTN                           BufferSize;

  EFI_STATUS                      ReturnStatus;
} SMM_CORE_PRIVATE_DATA;
    '''
    def send_smmc_SMI(self, smmc, guid, payload, payload_loc, CommandPort=0x0, DataPort=0x0):
        guid_b = uuid.UUID(guid).bytes_le
        payload_sz = len(payload)

        data_hdr = guid_b + struct.pack("Q", payload_sz) + payload
        # write payload to payload_loc
        CommBuffer_offset = 56
        BufferSize_offset = CommBuffer_offset + 8
        ReturnStatus_offset = BufferSize_offset + 8

        self.cs.mem.write_physical_mem(smmc + CommBuffer_offset, 8, struct.pack("Q", payload_loc))
        self.cs.mem.write_physical_mem(smmc + BufferSize_offset, 8, struct.pack("Q", len(data_hdr)))
        self.cs.mem.write_physical_mem(payload_loc, len(data_hdr), data_hdr)

        self.logger.log_verbose("[*] Communication buffer on input")
        if self.logger.VERBOSE:
            print_buffer_bytes(self.cs.mem.read_physical_mem(payload_loc, len(data_hdr)))
        self.logger.log_verbose("")

        self.send_SMI_APMC(CommandPort, DataPort)

        self.logger.log_verbose("[*] Communication buffer on output")
        if self.logger.VERBOSE:
            print_buffer_bytes(self.cs.mem.read_physical_mem(payload_loc, len(data_hdr)))
        self.logger.log_verbose("")

        ReturnStatus = struct.unpack("Q", self.cs.mem.read_physical_mem(smmc + ReturnStatus_offset, 8))[0]
        return ReturnStatus
