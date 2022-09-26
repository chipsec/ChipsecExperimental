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
Linux helper
"""

import array
import errno
import fcntl
import os
import platform
import struct
import subprocess
import sys
from uuid import UUID

from chipsec import defines
from chipsec.exceptions import OsHelperError
from chipsec.helper.basehelper import Helper
from chipsec.lib.uefi_common import EFI_STATUS_DICT
from chipsec.logger import logger
import chipsec.file
from chipsec.lib.uefi_variables import CHIPSEC_EFI_VARIABLE

MSGBUS_MDR_IN_MASK = 0x1
MSGBUS_MDR_OUT_MASK = 0x2

IOCTL_BASE = 0x0
IOCTL_RDIO = 0x1
IOCTL_WRIO = 0x2
IOCTL_RDPCI = 0x3
IOCTL_WRPCI = 0x4
IOCTL_RDMSR = 0x5
IOCTL_WRMSR = 0x6
IOCTL_CPUID = 0x7
IOCTL_GET_CPU_DESCRIPTOR_TABLE = 0x8
IOCTL_HYPERCALL = 0x9
IOCTL_SWSMI = 0xA
IOCTL_LOAD_UCODE_PATCH = 0xB
IOCTL_ALLOC_PHYSMEM = 0xC
IOCTL_GET_EFIVAR = 0xD
IOCTL_SET_EFIVAR = 0xE
IOCTL_GET_NEXT_EFIVAR = 0xF
IOCTL_RDCR = 0x10
IOCTL_WRCR = 0x11
IOCTL_RDMMIO = 0x12
IOCTL_WRMMIO = 0x13
IOCTL_VA2PA = 0x14
IOCTL_MSGBUS_SEND_MESSAGE = 0x15
IOCTL_FREE_PHYSMEM = 0x16

_tools = {}


class LinuxHelper(Helper):

    DEVICE_NAME = "/dev/chipsec"
    DEV_MEM = "/dev/mem"
    DEV_PORT = "/dev/port"
    MODULE_NAME = "chipsec"
    SUPPORT_KERNEL26_GET_PAGE_IS_RAM = False
    SUPPORT_KERNEL26_GET_PHYS_MEM_ACCESS_PROT = False
    DKMS_DIR = "/var/lib/dkms/"

    def __init__(self):
        super(LinuxHelper, self).__init__()
        self.os_system = platform.system()
        self.os_release = platform.release()
        self.os_version = platform.version()
        self.os_machine = platform.machine()
        self.os_uname = platform.uname()
        self.name = "LinuxHelper"
        self.dev_fh = None
        self.dev_mem = None
        self.dev_port = None
        self.dev_msr = None

###############################################################################################
# Driver/service management functions
###############################################################################################

    def get_dkms_module_location(self):
        version = defines.get_version()
        from os import listdir
        from os.path import isdir, join
        p = os.path.join(self.DKMS_DIR, self.MODULE_NAME, version, self.os_release)
        os_machine_dir_name = [f for f in listdir(p) if isdir(join(p, f))][0]
        return os.path.join(self.DKMS_DIR, self.MODULE_NAME, version, self.os_release, os_machine_dir_name, "module", "chipsec.ko")

    # This function load CHIPSEC driver
    def load_chipsec_module(self):
        page_is_ram = ""
        phys_mem_access_prot = ""
        a1 = ""
        a2 = ""
        if self.SUPPORT_KERNEL26_GET_PAGE_IS_RAM:
            page_is_ram = self.get_page_is_ram()
            if not page_is_ram:
                logger().log_debug("Cannot find symbol 'page_is_ram'")
            else:
                a1 = "a1=0x{}".format(page_is_ram)
        if self.SUPPORT_KERNEL26_GET_PHYS_MEM_ACCESS_PROT:
            phys_mem_access_prot = self.get_phys_mem_access_prot()
            if not phys_mem_access_prot:
                logger().log_debug("Cannot find symbol 'phys_mem_access_prot'")
            else:
                a2 = "a2=0x{}".format(phys_mem_access_prot)

        driver_path = os.path.join(chipsec.file.get_main_dir(), "chipsec", "helper", "linux", "chipsec.ko")
        if not os.path.exists(driver_path):
            driver_path += ".xz"
            if not os.path.exists(driver_path):
                # check DKMS modules location
                try:
                    driver_path = self.get_dkms_module_location()
                except Exception:
                    pass
                if not os.path.exists(driver_path):
                    driver_path += ".xz"
                    if not os.path.exists(driver_path):
                        raise Exception("Cannot find chipsec.ko module")
        try:
            subprocess.check_output(["insmod", driver_path, a1, a2])
        except Exception as err:
            raise Exception("Could not start Linux Helper, are you running as Admin/root?\n\t{}".format(err))
        uid = gid = 0
        os.chown(self.DEVICE_NAME, uid, gid)
        os.chmod(self.DEVICE_NAME, 600)
        if os.path.exists(self.DEVICE_NAME):
            logger().log_debug("Module {} loaded successfully".format(self.DEVICE_NAME))
        else:
            logger().error("Fail to load module: {}".format(driver_path))
        self.driverpath = driver_path

    def create(self):
        logger().log_debug("[helper] Linux Helper created")
        return True

    def start(self):
        if os.path.exists(self.DEVICE_NAME):
            subprocess.call(["rmmod", self.MODULE_NAME])
        self.load_chipsec_module()
        self.init()
        logger().log_debug("[helper] Linux Helper started/loaded")
        return True

    def stop(self, start_driver):
        self.close()
        if self.driver_loaded:
            subprocess.call(["rmmod", self.MODULE_NAME])
        logger().log_debug("[helper] Linux Helper stopped/unloaded")
        return True

    def delete(self, start_driver):
        logger().log_debug("[helper] Linux Helper deleted")
        return True

    def init(self):
        x64 = True if sys.maxsize > 2**32 else False
        self._pack = 'Q' if x64 else 'I'
        estr = "Unable to open chipsec device. Did you run as root/sudo and load the driver?\n {}"
        try:
            self.dev_fh = open(self.DEVICE_NAME, "rb+")
            self.driver_loaded = True
        except IOError as e:
            raise OsHelperError(estr.format(str(e)), e.errno)
        except BaseException as be:
            raise OsHelperError(estr.format(str(be)), errno.ENXIO)

        self._ioctl_base = self.compute_ioctlbase()

    def close(self):
        if self.dev_fh:
            self.dev_fh.close()
        self.dev_fh = None
        if self.dev_mem:
            os.close(self.dev_mem)
        self.dev_mem = None

    # code taken from /include/uapi/asm-generic/ioctl.h
    # by default itype is 'C' see drivers/linux/include/chipsec.h
    # currently all chipsec ioctl functions are _IOWR
    # currently all size are pointer
    def compute_ioctlbase(self, itype='C'):
        # define _IOWR(type,nr,size)	 _IOC(_IOC_READ|_IOC_WRITE,(type),(nr),(_IOC_TYPECHECK(size)))
        # define _IOC(dir,type,nr,size) \
        #    (((dir)  << _IOC_DIRSHIFT) | \
        #    ((type) << _IOC_TYPESHIFT) | \
        #    ((nr)   << _IOC_NRSHIFT) | \
        #    ((size) << _IOC_SIZESHIFT))
        # IOC_READ | _IOC_WRITE is 3
        # default _IOC_DIRSHIFT is 30
        # default _IOC_TYPESHIFT is 8
        # nr will be 0
        # _IOC_SIZESHIFT is 16
        return (3 << 30) | (ord(itype) << 8) | (struct.calcsize(self._pack) << 16)

    def ioctl(self, nr, args, *mutate_flag):
        return fcntl.ioctl(self.dev_fh, self._ioctl_base + nr, args)

###############################################################################################
# Actual API functions to access HW resources
###############################################################################################
    # def map_io_space(self, base, size, cache_type):
    #     raise UnimplementedAPIError("map_io_space")

    def __mem_block(self, sz, newval=None):
        if newval is None:
            return self.dev_fh.read(sz)
        else:
            self.dev_fh.write(newval)
            self.dev_fh.flush()
        return 1

    def write_phys_mem(self, phys_address, length, newval):
        if newval is None:
            return None
        # addr = (phys_address_hi << 32) | phys_address_lo
        self.dev_fh.seek(phys_address)
        return self.__mem_block(length, newval)

    def read_phys_mem(self, phys_address, length):
        # addr = (phys_address_hi << 32) | phys_address_lo
        self.dev_fh.seek(phys_address)
        return self.__mem_block(length)

    def va2pa(self, va):
        error_code = 0

        in_buf = struct.pack(self._pack, va)
        out_buf = self.ioctl(IOCTL_VA2PA, in_buf)
        pa = struct.unpack(self._pack, out_buf)[0]

        # Check if PA > max physical address
        max_pa = self.cpuid(0x80000008, 0x0)[0] & 0xFF
        if pa > 1 << max_pa:
            logger().log_debug("[helper] Error in va2pa: PA higher that max physical address: VA (0x{:016X}) -> PA (0x{:016X})".format(va, pa))
            error_code = 1
        return (pa, error_code)

    def read_pci_reg(self, bus, device, function, offset, size=4):
        _PCI_DOM = 0  # Change PCI domain, if there is more than one.
        d = struct.pack("5" + self._pack, ((_PCI_DOM << 16) | bus), ((device << 16) | function), offset, size, 0)
        try:
            ret = self.ioctl(IOCTL_RDPCI, d)
        except IOError:
            logger().log_debug("IOError\n")
            return None
        x = struct.unpack("5" + self._pack, ret)
        return x[4]

    def write_pci_reg(self, bus, device, function, offset, value, size=4):
        _PCI_DOM = 0  # Change PCI domain, if there is more than one.
        d = struct.pack("5" + self._pack, ((_PCI_DOM << 16) | bus), ((device << 16) | function), offset, size, value)
        try:
            ret = self.ioctl(IOCTL_WRPCI, d)
        except IOError:
            logger().log_debug("IOError\n")
            return None
        x = struct.unpack("5" + self._pack, ret)
        return x[4]

    def read_io_port(self, io_port, size):
        in_buf = struct.pack("3" + self._pack, io_port, size, 0)
        out_buf = self.ioctl(IOCTL_RDIO, in_buf)
        try:
            if 1 == size:
                value = struct.unpack("3" + self._pack, out_buf)[2] & 0xff
            elif 2 == size:
                value = struct.unpack("3" + self._pack, out_buf)[2] & 0xffff
            else:
                value = struct.unpack("3" + self._pack, out_buf)[2] & 0xffffffff
        except Exception:
            logger().log_debug("DeviceIoControl did not return value of proper size {:x} (value = '{}')".format(
                size, out_buf))

        return value

    def write_io_port(self, io_port, value, size):
        in_buf = struct.pack("3" + self._pack, io_port, size, value)
        return self.ioctl(IOCTL_WRIO, in_buf)

    def read_msr(self, thread_id, msr_addr):
        self.set_affinity(thread_id)
        edx = eax = 0
        in_buf = struct.pack("4" + self._pack, thread_id, msr_addr, edx, eax)
        _, _, edx_ret, eax_ret = struct.unpack("4" + self._pack, self.ioctl(IOCTL_RDMSR, in_buf))
        return (eax_ret, edx_ret)

    def write_msr(self, thread_id, msr_addr, eax, edx):
        self.set_affinity(thread_id)
        in_buf = struct.pack("4" + self._pack, thread_id, msr_addr, edx, eax)
        self.ioctl(IOCTL_WRMSR, in_buf)
        return

    def cpuid(self, eax, ecx):
        in_buf = struct.pack("4" + self._pack, eax, 0, ecx, 0)
        out_buf = self.ioctl(IOCTL_CPUID, in_buf)
        return struct.unpack("4" + self._pack, out_buf)

    def read_mmio_reg(self, bar_base, size, offset=0, bar_size=None):
        phys_address = bar_base + offset
        in_buf = struct.pack("2" + self._pack, phys_address, size)
        out_buf = self.ioctl(IOCTL_RDMMIO, in_buf)
        reg = out_buf[:size]
        return defines.unpack1(reg, size)

    def write_mmio_reg(self, bar_base, size, value, offset=0, bar_size=None):
        phys_address = bar_base + offset
        in_buf = struct.pack("3" + self._pack, phys_address, size, value)
        self.ioctl(IOCTL_WRMMIO, in_buf)

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

    def get_page_is_ram(self):
        PROC_KALLSYMS = "/proc/kallsyms"
        symarr = chipsec.file.read_file(PROC_KALLSYMS).splitlines()
        for line in symarr:
            if "page_is_ram" in line:
                return line.split(" ")[0]

    def get_phys_mem_access_prot(self):
        PROC_KALLSYMS = "/proc/kallsyms"
        symarr = chipsec.file.read_file(PROC_KALLSYMS).splitlines()
        for line in symarr:
            if "phys_mem_access_prot" in line:
                return line.split(" ")[0]

    #
    # Logical CPU count
    #
    def get_threads_count(self):
        import multiprocessing
        return multiprocessing.cpu_count()

    def read_cr(self, cpu_thread_id, cr_number):
        self.set_affinity(cpu_thread_id)
        cr = 0
        in_buf = struct.pack("3" + self._pack, cpu_thread_id, cr_number, cr)
        unbuf = struct.unpack("3" + self._pack, self.ioctl(IOCTL_RDCR, in_buf))
        return (unbuf[2])

    def write_cr(self, cpu_thread_id, cr_number, value):
        self.set_affinity(cpu_thread_id)
        in_buf = struct.pack("3" + self._pack, cpu_thread_id, cr_number, value)
        self.ioctl(IOCTL_WRCR, in_buf)
        return

    def get_descriptor_table(self, cpu_thread_id, desc_table_code):
        self.set_affinity(cpu_thread_id)
        in_buf = struct.pack("5" + self._pack, cpu_thread_id, desc_table_code, 0, 0, 0)
        out_buf = self.ioctl(IOCTL_GET_CPU_DESCRIPTOR_TABLE, in_buf)
        (limit, base_hi, base_lo, pa_hi, pa_lo) = struct.unpack("5" + self._pack, out_buf)
        pa = (pa_hi << 32) + pa_lo
        base = (base_hi << 32) + base_lo
        return (limit, base, pa)

    # EFI Variables
    def get_Buffer_size(self, n_size, v_size=0):
        in_size = n_size + v_size
        if in_size < 128:
            size = 128
        else:
            size = in_size + (in_size % 32) + 24 + 32
        if v_size:
            str_size1 = str(n_size)  # buffer_size, GUID, string_size
            str_size2 = str(size - 24 - n_size)
        else:
            str_size1 = str(size - 24)  # buffer_size, GUID, string_size
            str_size2 = str(v_size)
        return size, str_size1, str_size2

    def EFI_supported(self):
        return os.path.exists("/sys/firmware/efi/vars/") or os.path.exists("/sys/firmware/efi/efivars/")

    def get_EFI_variable(self, name_str, guid, encode=True):
        if encode:
            name = name_str.encode('utf-16-le')
        else:
            name = name_str
        tguid = guid
        data_size, str_size, _ = self.get_Buffer_size(len(name))
        off = 0
        data = ""
        attr = 0
        buf = []
        hdr = 0
        base = 12
        namelen = len(name)
        in_buf = struct.pack('I' + '16s' + 'I' + str_size + 's', data_size, tguid.bytes_le, namelen, name)
        buffer = array.array("B", in_buf)
        try:
            self.ioctl(IOCTL_GET_EFIVAR, buffer)
        except IOError:
            logger().log_debug("IOError IOCTL GetUEFIvar\n")
            return CHIPSEC_EFI_VARIABLE(off, buf, hdr, None, guid, attr)
        new_size, status = struct.unpack("2I", buffer[:8])
        if (status == 0x5):
            data_size, str_size, _ = self.get_Buffer_size(new_size + namelen)
            in_buf = struct.pack('I' + '16s' + 'I' + str_size + 's', data_size, tguid.bytes_le, namelen, name)
            buffer = array.array("B", in_buf)
            try:
                self.ioctl(IOCTL_GET_EFIVAR, buffer)
            except IOError:
                logger().log_debug("IOError IOCTL GetUEFIvar\n")
                return (off, buf, hdr, None, guid, attr)
            new_size, status = struct.unpack("2I", buffer[:8])

        if (new_size > data_size):
            logger().log_debug("Incorrect size returned from driver")
            return CHIPSEC_EFI_VARIABLE(off, buf, hdr, None, guid, attr)

        if (status != 0):
            logger().log_debug("Reading variable (GET_EFIVAR) did not succeed for {}: {} ({:d})".format(
                name_str, EFI_STATUS_DICT.get(status, 'UNKNOWN'), status))
        else:
            data = buffer[base:base + new_size].tobytes()
            attr = struct.unpack("I", buffer[8:12])[0]
        return CHIPSEC_EFI_VARIABLE(off, buf, hdr, data, guid, attr, status)

    def list_EFI_variables(self):
        varlist = []
        vname = b''
        vguid = UUID('00000000-0000-0000-0000-000000000000')
        nname = None
        nguid = None
        while vname is not None and vname != nname:
            nname, nguid = self.get_next_EFI_variable(vname, vguid, False)
            if vname and vname != nname.encode('latin-1'):
                vname = nname.encode('latin-1')
                vguid = nguid
                varlist.append((vname, vguid))
            else:
                break
        variables = {}
        for name, guid in varlist:
            var = self.get_EFI_variable(name, guid, encode=False)
            variables[name] = [var]

        return variables

    def get_next_EFI_variable(self, name_str, guid, encode=True):
        if guid:
            tguid = guid
        else:
            tguid = UUID('00000000-0000-0000-0000-000000000000')
        if name_str and encode:
            name = name_str.encode('utf-16-le')
        elif name_str:
            name = name_str
        else:
            name = b''
        data_size, str_size, _ = self.get_Buffer_size(len(name))
        namelen = len(name)
        in_buf = struct.pack('I' + '16s' + 'I' + str_size + 's', data_size, tguid.bytes_le, namelen, name)
        buffer = array.array("B", in_buf)
        try:
            self.ioctl(IOCTL_GET_NEXT_EFIVAR, buffer)
        except IOError:
            logger().log_debug("IOError IOCTL GetNextUEFIvar\n")
            return (None, None)
        status = struct.unpack("I", buffer[:4])[0]
        new_size = struct.unpack('I', buffer[20:24])[0]
        if (status == 0x5):
            data_size, str_size, _ = self.get_Buffer_size(new_size + namelen)
            in_buf = struct.pack('I' + '16s' + 'I' + str_size + 's', data_size, tguid.bytes_le, namelen, name)
            buffer = array.array("B", in_buf)
            try:
                self.ioctl(IOCTL_GET_NEXT_EFIVAR, buffer)
            except IOError:
                logger().log_debug("IOError IOCTL GetNextUEFIvar\n")
                return (None, None)
            status = struct.unpack("I", buffer[:4])[0]
            new_size = struct.unpack('I', buffer[20:24])[0]

        if (new_size > data_size):
            logger().log_debug("Incorrect size returned from driver")
            return (None, None)

        if (status != 0):
            logger().log_debug("Reading variable (GET_NEXT_EFIVAR) did not succeed: {} ({:d})".format(
                EFI_STATUS_DICT.get(status, 'UNKNOWN'), status))
        else:
            guid = UUID(bytes_le=buffer[4:20].tobytes())
            name = buffer[24: 24 + new_size].tobytes()
        return (name.decode('utf-8', 'strict'), guid)

    def set_EFI_variable(self, name_str, guid, value='', datasize=None, attr=0):
        tguid = guid
        name = name_str.encode('utf-16-le')

        namelen = len(name)
        datalen = len(value)
        data_size, str_size, value_size = self.get_Buffer_size(len(name), len(value))

        in_buf = struct.pack('I' + '16s' + '3I' + str_size + 's' + value_size + 's', data_size, tguid.bytes_le, attr, namelen, datalen, name, value)
        buffer = array.array("B", in_buf)
        self.ioctl(IOCTL_SET_EFIVAR, buffer)
        status = struct.unpack("I", buffer[4:8])[0]

        if status != 0:
            logger().log_debug("Setting EFI (SET_EFIVAR) variable did not succeed: '{}' ({:d})".format(
                EFI_STATUS_DICT.get(status, 'UNKNOWN'), status))
        return status


def get_helper():
    return LinuxHelper()
