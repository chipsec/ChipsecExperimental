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
#


"""
Access to CPU resources (for each CPU thread): Model Specific Registers (MSR), IDT/GDT

usage:
    >>> read_msr( 0x8B )
    >>> write_msr( 0x79, 0x12345678 )
"""

from chipsec.hal.hal_base import HALBase


MTRR_MEMTYPE_UC = 0x0
MTRR_MEMTYPE_WC = 0x1
MTRR_MEMTYPE_WT = 0x4
MTRR_MEMTYPE_WP = 0x5
MTRR_MEMTYPE_WB = 0x6
MemType = {
    MTRR_MEMTYPE_UC: 'Uncacheable (UC)',
    MTRR_MEMTYPE_WC: 'Write Combining (WC)',
    MTRR_MEMTYPE_WT: 'Write-through (WT)',
    MTRR_MEMTYPE_WP: 'Write-protected (WP)',
    MTRR_MEMTYPE_WB: 'Writeback (WB)'
}


class Msr(HALBase):

    def __init__(self, cs):
        super(Msr, self).__init__(cs)

    def get_cpu_thread_count(self):
        thread_count = self.helper.get_threads_count()
        if thread_count is None or thread_count < 0:
            if self.logger.HAL:
                self.logger.log("helper.get_threads_count didn't return anything. Reading MSR 0x35 to find out number of logical CPUs (use CPUID Leaf B instead?)")
            thread_count = self.cs.read_register_field("IA32_MSR_CORE_THREAD_COUNT", "Thread_Count")

        if 0 == thread_count:
            thread_count = 1
        if self.logger.HAL:
            self.logger.log("[cpu] # of logical CPUs: {:d}".format(thread_count))
        return thread_count

    def get_threads_from_scope(self, scope):
        topology = self.cs.cpu.get_cpu_topology()
        if scope == "packages":
            packages = topology['packages']
            threads_to_use = [packages[p][0] for p in packages]
        elif scope == "cores":
            cores = topology['cores']
            threads_to_use = [cores[p][0] for p in cores]
        else:  # Default to threads
            threads_to_use = range(self.get_cpu_thread_count())
        return threads_to_use

##########################################################################################################
#
# Read/Write CPU MSRs
#
##########################################################################################################

    def read_msr(self, cpu_thread_id, msr_addr):
        (eax, edx) = self.helper.read_msr(cpu_thread_id, msr_addr)
        if self.logger.HAL:
            self.logger.log("[cpu{:d}] RDMSR( 0x{:x} ): EAX = 0x{:08X}, EDX = 0x{:08X}".format(cpu_thread_id, msr_addr, eax, edx))
        return (eax, edx)

    def write_msr(self, cpu_thread_id, msr_addr, eax, edx):
        self.helper.write_msr(cpu_thread_id, msr_addr, eax, edx)
        if self.logger.HAL:
            self.logger.log("[cpu{:d}] WRMSR( 0x{:x} ): EAX = 0x{:08X}, EDX = 0x{:08X}".format(cpu_thread_id, msr_addr, eax, edx))
        return
