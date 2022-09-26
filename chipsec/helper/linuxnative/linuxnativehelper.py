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
Native Linux helper
"""

import mmap
import os
import platform
import resource
import struct
import sys

from chipsec import defines
from chipsec.exceptions import OsHelperError
from chipsec.helper.basehelper import Helper
from chipsec.helper.linuxnative.legacy_pci import LEGACY_PCI
from chipsec.logger import logger


class MemoryMapping(mmap.mmap):
    """Memory mapping based on Python's mmap.

    This subclass keeps tracks of the start and end of the mapping.
    """
    def __init__(self, fileno, length, flags, prot, offset):
        self.start = offset
        self.end = offset + length
        super().__init__()


class LinuxNativeHelper(Helper):

    DEV_MEM = "/dev/mem"
    DEV_PORT = "/dev/port"

    def __init__(self):
        super(LinuxNativeHelper, self).__init__()
        self.os_system = platform.system()
        self.os_release = platform.release()
        self.os_version = platform.version()
        self.os_machine = platform.machine()
        self.os_uname = platform.uname()
        self.name = "LinuxNativeHelper"
        self.dev_fh = None
        self.dev_mem = None
        self.dev_port = None
        self.dev_msr = None
        self.legacy_pci = None

        # A list of all the mappings allocated via map_io_space. When using
        # read/write MMIO, if the region is already mapped in the process's
        # memory, simply read/write from there.
        self.mappings = []

###############################################################################################
# Driver/service management functions
###############################################################################################
    def create(self):
        logger().log_debug("[helper] Linux Helper created")
        return True

    def start(self):
        self.init()
        logger().log_debug("[helper] Linux Helper started/loaded")
        return True

    def stop(self, start_driver):
        self.close()
        logger().log_debug("[helper] Linux Helper stopped/unloaded")
        return True

    def delete(self, start_driver):
        logger().log_debug("[helper] Linux Helper deleted")
        return True

    def init(self):
        x64 = True if sys.maxsize > 2**32 else False
        self._pack = 'Q' if x64 else 'I'

    def devmem_available(self):
        """Check if /dev/mem is usable.

           In case the driver is not loaded, we might be able to perform the
           requested operation via /dev/mem. Returns True if /dev/mem is
           accessible.
        """
        if self.dev_mem:
            return True

        try:
            self.dev_mem = os.open(self.DEV_MEM, os.O_RDWR)
            return True
        except IOError as err:
            raise OsHelperError("Unable to open /dev/mem.\n"
                                "This command requires access to /dev/mem.\n"
                                "Are you running this command as root?\n"
                                "{}".format(str(err)), err.errno)

    def devport_available(self):
        """Check if /dev/port is usable.

           In case the driver is not loaded, we might be able to perform the
           requested operation via /dev/port. Returns True if /dev/port is
           accessible.
        """
        if self.dev_port:
            return True

        try:
            self.dev_port = os.open(self.DEV_PORT, os.O_RDWR)
            return True
        except IOError as err:
            raise OsHelperError("Unable to open /dev/port.\n"
                                "This command requires access to /dev/port.\n"
                                "Are you running this command as root?\n"
                                "{}".format(str(err)), err.errno)

    def devmsr_available(self):
        """Check if /dev/cpu/CPUNUM/msr is usable.

           In case the driver is not loaded, we might be able to perform the
           requested operation via /dev/cpu/CPUNUM/msr. This requires loading
           the (more standard) msr driver. Returns True if /dev/cpu/CPUNUM/msr
           is accessible.
        """
        if self.dev_msr:
            return True

        try:
            self.dev_msr = {}
            if not os.path.exists("/dev/cpu/0/msr"):
                os.system("modprobe msr")
            for cpu in os.listdir("/dev/cpu"):
                logger().log_debug("found cpu = {}".format(cpu))
                if cpu.isdigit():
                    cpu = int(cpu)
                    self.dev_msr[cpu] = os.open("/dev/cpu/" + str(cpu) + "/msr", os.O_RDWR)
                    logger().log_debug("Added dev_msr {}".format(str(cpu)))
            return True
        except IOError as err:
            raise OsHelperError("Unable to open /dev/cpu/CPUNUM/msr.\n"
                                "This command requires access to /dev/cpu/CPUNUM/msr.\n"
                                "Are you running this command as root?\n"
                                "Do you have the msr kernel module installed?\n"
                                "{}".format(str(err)), err.errno)

    def close(self):
        if self.dev_mem:
            os.close(self.dev_mem)
        self.dev_mem = None

###############################################################################################
# Actual API functions to access HW resources
###############################################################################################

    def read_pci_reg(self, bus, device, function, offset, size, domain=0):
        device_name = "{domain:04x}:{bus:02x}:{device:02x}.{function}".format(
                      domain=domain, bus=bus, device=device, function=function)
        device_path = "/sys/bus/pci/devices/{}/config".format(device_name)
        if not os.path.exists(device_path):
            if offset < 256:
                if self.legacy_pci:
                    pci = self.legacy_pci
                else:
                    pci = LEGACY_PCI()
                    self.legacy_pci = pci
                value = pci.read_pci_config(bus, device, function, offset)
                if size == 1:
                    value = value & 0xFF
                elif size == 2:
                    value = value & 0xFFFF
                elif size == 4:
                    value = value & 0xFFFFFFFF

                return value
            else:
                byte = b"\xff"
                return defines.unpack1(byte * size, size)
        try:
            config = open(device_path, "rb")
        except IOError as err:
            raise OsHelperError("Unable to open {}".format(device_path), err.errno)
        config.seek(offset)
        reg = config.read(size)
        config.close()
        reg = defines.unpack1(reg, size)
        return reg

    def write_pci_reg(self, bus, device, function, offset, value, size=4, domain=0):
        device_name = "{domain:04x}:{bus:02x}:{device:02x}.{function}".format(
                      domain=domain, bus=bus, device=device, function=function)
        device_path = "/sys/bus/pci/devices/{}/config".format(device_name)
        if not os.path.exists(device_path):
            if offset < 256:
                if self.legacy_pci:
                    pci = self.legacy_pci
                else:
                    pci = LEGACY_PCI()
                    self.legacy_pci = pci
                value = pci.write_pci_config(bus, device, function, offset, value)
                return False
        try:
            config = open(device_path, "wb")
        except IOError as err:
            raise OsHelperError("Unable to open {}".format(device_path), err.errno)
        config.seek(offset)
        config.write(defines.pack1(value, size))
        config.close()

    def cpuid(self, eax, ecx):
        import chipsec.helper.linuxnative.cpuid as cpuid
        _cpuid = cpuid.CPUID()
        return _cpuid(eax, ecx)

    def read_msr(self, thread_id, msr_addr):
        if self.devmsr_available():
            os.lseek(self.dev_msr[thread_id], msr_addr, os.SEEK_SET)
            buf = os.read(self.dev_msr[thread_id], 8)
            unbuf = struct.unpack("2I", buf)
            return (unbuf[0], unbuf[1])

    def write_msr(self, thread_id, msr_addr, eax, edx):
        if self.devmsr_available():
            os.lseek(self.dev_msr[thread_id], msr_addr, os.SEEK_SET)
            buf = struct.pack("2I", eax, edx)
            written = os.write(self.dev_msr[thread_id], buf)
            if written != 8:
                logger().log_debug("Cannot write {:8X} to MSR {:x}".format(buf, msr_addr))

    #
    # Affinity functions
    #
    def get_affinity(self):
        try:
            affinity = os.sched_getaffinity(0)
            return list(affinity)[0]
        except Exception:
            return None

    def set_affinity(self, thread_id):
        try:
            os.sched_setaffinity(os.getpid(), {thread_id})
            return thread_id
        except Exception:
            return None

    #
    # Logical CPU count
    #
    def get_threads_count(self):
        import multiprocessing
        return multiprocessing.cpu_count()

    def memory_mapping(self, base, size):
        """Returns the mmap region that fully encompasses this area.

        Returns None if no region matches.
        """
        for region in self.mappings:
            if region.start <= base and region.end >= base + size:
                return region
        return None

    def map_io_space(self, base, size, cache_type):
        """Map to memory a specific region."""
        if self.devmem_available() and not self.memory_mapping(base, size):
            logger().log_debug("[helper] Mapping 0x{:x} to memory".format(base))
            length = max(size, resource.getpagesize())
            page_aligned_base = base - (base % resource.getpagesize())
            mapping = MemoryMapping(self.dev_mem, length, mmap.MAP_SHARED,
                                    mmap.PROT_READ | mmap.PROT_WRITE,
                                    offset=page_aligned_base)
            self.mappings.append(mapping)

    # @TODO fix memory mapping and bar_size
    def read_mmio_reg(self, bar_base, size, offset, bar_size):
        if bar_size is None or bar_size < offset:
            bar_size = offset + size
        if self.devmem_available():
            region = self.memory_mapping(bar_base, bar_size)
            if not region:
                self.map_io_space(bar_base, bar_size, 0)
                region = self.memory_mapping(bar_base, bar_size)
                if not region:
                    logger().error("Unable to map region {:08x}".format(bar_base))

            # Create memoryview into mmap'ed region in dword granularity
            region_mv = memoryview(region)
            region_dw = region_mv.cast('I')
            # read one DWORD
            offset_in_region = (bar_base + offset - region.start) // 4
            reg = region_dw[offset_in_region]
            return reg

    # @TODO fix memory mapping and bar_size
    def write_mmio_reg(self, bar_base, size, value, offset, bar_size):
        if bar_size is None:
            bar_size = offset + size
        if self.devmem_available():
            reg = defines.pack1(value, size)
            region = self.memory_mapping(bar_base, bar_size)
            if not region:
                self.map_io_space(bar_base, bar_size, 0)
                region = self.memory_mapping(bar_base, bar_size)
                if not region:
                    logger().error("Unable to map region {:08x}".format(bar_base))

            # Create memoryview into mmap'ed region in dword granularity
            region_mv = memoryview(region)
            region_dw = region_mv.cast('I')
            # Create memoryview containing data in dword
            data_mv = memoryview(reg)
            data_dw = data_mv.cast('I')
            # write one DWORD
            offset_in_region = (bar_base + offset - region.start) // 4
            region_dw[offset_in_region] = data_dw[0]

    def read_io_port(self, io_port, size):
        if self.devport_available():
            os.lseek(self.dev_port, io_port, os.SEEK_SET)

            value = os.read(self.dev_port, size)
            if 1 == size:
                return struct.unpack("B", value)[0]
            elif 2 == size:
                return struct.unpack("H", value)[0]
            elif 4 == size:
                return struct.unpack("I", value)[0]

    def write_io_port(self, io_port, newval, size):
        if self.devport_available():
            os.lseek(self.dev_port, io_port, os.SEEK_SET)
            if 1 == size:
                fmt = 'B'
            elif 2 == size:
                fmt = 'H'
            elif 4 == size:
                fmt = 'I'
            written = os.write(self.dev_port, struct.pack(fmt, newval))
            if written != size:
                logger().log_debug("Cannot write {} to port {:x} (wrote {:d} of {:d})".format(
                    newval, io_port, written, size))

    def get_bios_version(self):
        try:
            filename = "/sys/class/dmi/id/bios_version"
            with open(filename, 'r') as outfile:
                return outfile.read().strip()
        except FileNotFoundError:
            return 'Unable to read bios version'

    def write_phys_mem(self, phys_address, length, newval):
        if newval is None:
            return None
        if self.devmem_available():
            os.lseek(self.dev_mem, phys_address, os.SEEK_SET)
            written = os.write(self.dev_mem, newval)
            if written != length:
                logger().log_debug("Cannot write {} to memory {:016X} (wrote {:d} of {:d})".format(
                    newval, phys_address, written, length))

    def read_phys_mem(self, phys_address, length):
        if self.devmem_available():
            os.lseek(self.dev_mem, phys_address, os.SEEK_SET)
            return os.read(self.dev_mem, length)


def get_helper():
    return LinuxNativeHelper()
