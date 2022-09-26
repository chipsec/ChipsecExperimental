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
CPUID information

usage:
    >>> cpuid(0)
"""

from chipsec.hal.hal_base import HALBase


class CpuID(HALBase):

    def __init__(self, cs):
        super(CpuID, self).__init__(cs)

    def cpuid(self, eax, ecx):
        self.logger.log_hal("[cpuid] in: EAX=0x{:08X}, ECX=0x{:08X}".format(eax, ecx))
        (eax, ebx, ecx, edx) = self.helper.cpuid(eax, ecx)
        self.logger.log_hal("[cpuid] out: EAX=0x{:08X}, EBX=0x{:08X}, ECX=0x{:08X}, EDX=0x{:08X}".format(
            eax, ebx, ecx, edx))
        return (eax, ebx, ecx, edx)

    def get_proc_info(self):
        (eax, _, _, _) = self.cpuid(0x01, 0x00)
        stepping = eax & 0xF
        model = (eax >> 4) & 0xF
        extmodel = (eax >> 16) & 0xF
        family = (eax >> 8) & 0xF
        ptype = (eax >> 12) & 0x3
        extfamily = (eax >> 20) & 0xFF
        ret = '{:01X}{:01X}{:01X}{:01X}{:01X}'.format(extmodel, ptype, family, model, stepping)
        if extfamily == 0:
            return ret
        else:
            return '{:02X}{}'.format(extfamily, ret)
