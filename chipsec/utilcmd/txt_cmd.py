# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2020, Intel Corporation
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
Command-line utility providing access to Intel TXT (Trusted Execution Technology) registers

Usage:
>>> chipsec_util txt dump
>>> chipsec_util txt state
>>> chipsec_util txt all
>>> chipsec_util txt list
>>> chipsec_util txt read <offset> [field]

Examples:
>>> chipsec_util txt dump                                         - Display all LT/TXT Public Space as a hexdump
>>> chipsec_util txt state                                        - Dump Intel TXT state
>>> chipsec_util txt all                                          - Display all LT/TXT Public Space Entries
>>> chipsec_util txt list                                         - List all LT/TXT Public Space Entries
>>> chipsec_util txt read 8086.LT_PUBLIC_SPACE.TXT_PCH_DIDVID     - Read specific LT/TXT Public Space Entry
>>> chipsec_util txt read 8086.LT_PUBLIC_SPACE.TXT_PCH_DIDVID VID - Read field from Entry

"""

from argparse import ArgumentParser
import binascii
from chipsec.command import BaseCommand, toLoad
from chipsec.exceptions import HWAccessViolationError
from chipsec.hal.txt import TXT
import struct


class TXTCommand(BaseCommand):

    def requires_driver(self):
        parser = ArgumentParser(usage=__doc__)
        subparsers = parser.add_subparsers()

        parser_dump = subparsers.add_parser('dump')
        parser_dump.set_defaults(func=self.txt_dump)

        parser_state = subparsers.add_parser('state')
        parser_state.set_defaults(func=self.txt_state)

        parser_all = subparsers.add_parser('all')
        parser_all.set_defaults(func=self.txt_all)

        parser_list = subparsers.add_parser('list')
        parser_list.add_argument('values', nargs='?', default=None)
        parser_list.set_defaults(func=self.txt_list)

        parser_read = subparsers.add_parser('read')
        parser_read.add_argument('entry')
        parser_read.add_argument('field', nargs='?', default=None)
        parser_read.set_defaults(func=self.txt_entry)

        parser.parse_args(self.argv, namespace=self)
        return toLoad.All

    def txt_dump(self):
        # Read TXT Public area as hexdump, with absolute address and skipping zeros
        # try an MMIO read if it fails try using physical memory
        txt_public = self.cs.mmio.dump_MMIO(0xfed30000, 0x1000)
        if txt_public is None:
            txt_public = self.cs.mem.read_physical_mem(0xfed30000, 0x1000)
        has_skipped_line = False
        for offset in range(0, len(txt_public), 16):
            line_bytes = txt_public[offset:offset + 16]
            if all(b == 0 for b in line_bytes):
                has_skipped_line = True
                continue
            if has_skipped_line:
                self.logger.log("[CHIPSEC] *")
                has_skipped_line = False
            line_hex = " ".join("{:02X}".format(b) for b in line_bytes)
            self.logger.log("[CHIPSEC] {:08X}: {}".format(0xfed30000 + offset, line_hex))

    def txt_state(self):
        """Dump Intel TXT state

        This is similar to command "txt-stat" from Trusted Boot project
        https://sourceforge.net/p/tboot/code/ci/v2.0.0/tree/utils/txt-stat.c
        which was documented on
        https://www.intel.com/content/dam/www/public/us/en/documents/guides/dell-one-stop-txt-activation-guide.pdf
        and it is also similar to command "sl-stat" from TrenchBoot project
        https://github.com/TrenchBoot/sltools/blob/842cfd041b7454727b363b72b6d4dcca9c00daca/sl-stat/sl-stat.c
        """
        # Read bits in CPUID
        (eax, ebx, ecx, edx) = self.cs.cpu.cpuid(0x01, 0x00)
        self.logger.log("[CHIPSEC] CPUID.01H.ECX[Bit 6] = {} << Safer Mode Extensions (SMX)".format((ecx >> 6) & 1))
        self.logger.log("[CHIPSEC] CPUID.01H.ECX[Bit 5] = {} << Virtual Machine Extensions (VMX)".format((ecx >> 5) & 1))

        # Read bits in CR4
        cr4 = self.cs.cpu.read_cr(0, 4)
        self.logger.log("[CHIPSEC] CR4.SMXE[Bit 14] = {} << Safer Mode Extensions Enable".format((cr4 >> 14) & 1))
        self.logger.log("[CHIPSEC] CR4.VMXE[Bit 13] = {} << Virtual Machine Extensions Enable".format((cr4 >> 13) & 1))

        # Read bits in MSR IA32_FEATURE_CONTROL
        ia32 = self.cs.read_register("8086.MSR.IA32_FEATURE_CONTROL", 0)[0]
        self.cs.print_register("8086.MSR.IA32_FEATURE_CONTROL", ia32)
        self.logger.log("[CHIPSEC]")

        # Read TXT Device ID
        self.acm_txt.print_public_txt_reg('8086.LT_PUBLIC_SPACE.TXT_DIDVID')
        self.logger.log("[CHIPSEC]")

        # Read hashes of public keys
        txt_pubkey = struct.pack("<QQQQ",
                                 self.cs.read_register("8086.LT_PUBLIC_SPACE.TXT_PUBLIC_KEY_0")[0].value,
                                 self.cs.read_register("8086.LT_PUBLIC_SPACE.TXT_PUBLIC_KEY_1")[0].value,
                                 self.cs.read_register("8086.LT_PUBLIC_SPACE.TXT_PUBLIC_KEY_2")[0].value,
                                 self.cs.read_register("8086.LT_PUBLIC_SPACE.TXT_PUBLIC_KEY_3")[0].value,
                                 )
        self.logger.log("[CHIPSEC] TXT Public Key Hash: {}".format(
            binascii.hexlify(txt_pubkey).decode("ascii")))

        try:
            eax, edx = self.cs.msr.read_msr(0, 0x20)
            pubkey_in_msr = struct.pack("<II", eax, edx)
            eax, edx = self.cs.msr.read_msr(0, 0x21)
            pubkey_in_msr += struct.pack("<II", eax, edx)
            eax, edx = self.cs.msr.read_msr(0, 0x22)
            pubkey_in_msr += struct.pack("<II", eax, edx)
            eax, edx = self.cs.msr.read_msr(0, 0x23)
            pubkey_in_msr += struct.pack("<II", eax, edx)
            self.logger.log("[CHIPSEC] Public Key Hash in MSR[0x20...0x23]: {}".format(
                binascii.hexlify(pubkey_in_msr).decode("ascii")))
        except HWAccessViolationError as exc:
            # Report the exception and continue
            self.logger.log("[CHIPSEC] Unable to read Public Key Hash in MSR[0x20...0x23]: {}".format(exc))
        self.logger.log("[CHIPSEC]")

        # Read TXT status
        self.acm_txt.print_public_txt_reg("8086.LT_PUBLIC_SPACE.TXT_STS")
        self.acm_txt.print_public_txt_reg("8086.LT_PUBLIC_SPACE.TXT_ESTS")
        self.acm_txt.print_public_txt_reg("8086.LT_PUBLIC_SPACE.TXT_E2STS")
        self.acm_txt.print_public_txt_reg("8086.LT_PUBLIC_SPACE.TXT_ERRORCODE")
        self.logger.log("[CHIPSEC]")
        self.acm_txt.print_public_txt_reg("8086.LT_PUBLIC_SPACE.TXT_SPAD")
        self.acm_txt.print_public_txt_reg("8086.LT_PUBLIC_SPACE.TXT_ACM_STATUS")
        self.acm_txt.print_public_txt_reg("8086.LT_PUBLIC_SPACE.TXT_FIT")
        self.acm_txt.print_public_txt_reg("8086.LT_PUBLIC_SPACE.TXT_SCRATCHPAD")
        self.logger.log("[CHIPSEC]")

        # Read memory area for TXT components
        self.acm_txt.print_public_txt_reg("8086.LT_PUBLIC_SPACE.TXT_SINIT_BASE")
        self.acm_txt.print_public_txt_reg("8086.LT_PUBLIC_SPACE.TXT_SINIT_SIZE")
        self.acm_txt.print_public_txt_reg("8086.LT_PUBLIC_SPACE.TXT_MLE_JOIN")
        self.acm_txt.print_public_txt_reg("8086.LT_PUBLIC_SPACE.TXT_HEAP_BASE")
        self.acm_txt.print_public_txt_reg("8086.LT_PUBLIC_SPACE.TXT_HEAP_SIZE")
        self.acm_txt.print_public_txt_reg("8086.LT_PUBLIC_SPACE.TXT_MSEG_BASE")
        self.acm_txt.print_public_txt_reg("8086.LT_PUBLIC_SPACE.TXT_MSEG_SIZE")
        self.logger.log("[CHIPSEC]")

        # Read other registers in the TXT memory area
        self.acm_txt.print_public_txt_reg("8086.LT_PUBLIC_SPACE.TXT_DPR")
        self.acm_txt.print_public_txt_reg("8086.LT_PUBLIC_SPACE.TXT_VER_FSBIF")
        self.acm_txt.print_public_txt_reg("8086.LT_PUBLIC_SPACE.TXT_VER_QPIIF")
        self.acm_txt.print_public_txt_reg("8086.LT_PUBLIC_SPACE.TXT_PCH_DIDVID")
        self.acm_txt.print_public_txt_reg("8086.LT_PUBLIC_SPACE.INSMM")

    def txt_all(self):
        self.acm_txt.print_public_txt_space()

    def txt_list(self):
        self.acm_txt.list_txt_registers()

    def txt_entry(self):
        if self.field is None:
            self.acm_txt.print_public_txt_reg(self.entry)
        else:
            self.acm_txt.print_txt_field(self.entry, self.field.upper())

    def run(self):
        self.acm_txt = TXT(self.cs)
        self.func()


commands = {'txt': TXTCommand}
