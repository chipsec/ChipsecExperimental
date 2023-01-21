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
Management and communication with Windows kernel mode driver which provides access to hardware resources

.. note::
    On Windows you need to install pywin32 Python extension corresponding to your Python version:
    http://sourceforge.net/projects/pywin32/
"""

import os.path
import struct
import sys
import platform
import errno
from collections import namedtuple
from ctypes import c_ushort, c_char_p, c_size_t, c_int, c_uint32, c_wchar_p, c_void_p, c_char
from ctypes import windll, pythonapi, py_object, create_string_buffer, POINTER, addressof, sizeof, Structure

import pywintypes
import win32service
import win32con
import winerror
from win32file import FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, INVALID_HANDLE_VALUE
import win32api
import win32process
import win32security
import win32file
import win32serviceutil

from chipsec.exceptions import OsHelperError, HWAccessViolationError, UnimplementedAPIError
from chipsec.helper.basehelper import Helper
from chipsec.defines import stringtobytes
from chipsec.logger import logger
import chipsec.file
from chipsec.lib.uefi_common import EFI_GUID_STR
from chipsec import defines


class PCI_BDF(Structure):
    _fields_ = [("BUS", c_ushort, 16),  # Bus
                ("DEV", c_ushort, 16),  # Device
                ("FUNC", c_ushort, 16),  # Function
                ("OFF", c_ushort, 16)]  # Offset


kernel32 = windll.kernel32


drv_hndl_error_msg = "Cannot open chipsec driver handle. Make sure chipsec driver is installed and started if you are using option -e (see README)"

DRIVER_FILE_PATHS = [os.path.join("C:\\", "Windows", "System32", "drivers"), os.path.join(chipsec.file.get_main_dir(), "chipsec", "helper", "windows", "win7_" + platform.machine().lower())]
DRIVER_FILE_NAME = "chipsec_hlpr.sys"
DEVICE_FILE = "\\\\.\\chipsec_hlpr"
SERVICE_NAME = "chipsec"
DISPLAY_NAME = "CHIPSEC Service"

CHIPSEC_INSTALL_PATH = os.path.join(sys.prefix, "Lib\site-packages\chipsec")

# Status Codes
STATUS_PRIVILEGED_INSTRUCTION = 0xC0000096

# Defines for Win32 API Calls
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000

FILE_DEVICE_UNKNOWN = 0x00000022

METHOD_BUFFERED = 0
METHOD_IN_DIRECT = 1
METHOD_OUT_DIRECT = 2
METHOD_NEITHER = 3

FILE_ANY_ACCESS = 0
FILE_SPECIAL_ACCESS = (FILE_ANY_ACCESS)
FILE_READ_ACCESS = (0x0001)
FILE_WRITE_ACCESS = (0x0002)


def CTL_CODE(DeviceType, Function, Method, Access):
    return ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method)


#
# chipsec driver IOCTL codes
#
CHIPSEC_CTL_ACCESS = (FILE_READ_ACCESS | FILE_WRITE_ACCESS)

CLOSE_DRIVER = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
READ_PCI_CFG_REGISTER = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
WRITE_PCI_CFG_REGISTER = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_READ_PHYSMEM = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_WRITE_PHYSMEM = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80a, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_LOAD_UCODE_PATCH = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80b, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_WRMSR = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80c, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_RDMSR = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80d, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_READ_IO_PORT = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80e, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_WRITE_IO_PORT = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80f, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_GET_CPU_DESCRIPTOR_TABLE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_SWSMI = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_ALLOC_PHYSMEM = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_CPUID = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_HYPERCALL = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x814, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_GET_PHYSADDR = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x815, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_MAP_IO_SPACE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x816, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_FREE_PHYSMEM = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x817, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_WRCR = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x818, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_RDCR = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x819, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_MSGBUS_SEND_MESSAGE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81a, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_WRITE_MMIO = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81b, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)
IOCTL_READ_MMIO = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81c, METHOD_BUFFERED, CHIPSEC_CTL_ACCESS)

#
# Format for IOCTL Structures
#
_pack = 'Q' if sys.maxsize > 2**32 else 'I'
_smi_msg_t_fmt = 7 * _pack

#
# NT Errors
#
# Defined in WinDDK\7600.16385.1\inc\api\ntstatus.h
#

#
# UEFI constants
#
# Default buffer size for EFI variables
EFI_VAR_MAX_BUFFER_SIZE = 1024 * 1024

attributes = {
    "EFI_VARIABLE_NON_VOLATILE": 0x00000001,
    "EFI_VARIABLE_BOOTSERVICE_ACCESS": 0x00000002,
    "EFI_VARIABLE_RUNTIME_ACCESS": 0x00000004,
    "EFI_VARIABLE_HARDWARE_ERROR_RECORD": 0x00000008,
    "EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS": 0x00000010,
    "EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS": 0x00000020,
    "EFI_VARIABLE_APPEND_WRITE": 0x00000040
}

PyLong_AsByteArray = pythonapi._PyLong_AsByteArray
PyLong_AsByteArray.argtypes = [py_object,
                               c_char_p,
                               c_size_t,
                               c_int,
                               c_int]


def packl_ctypes(lnum, bitlength):
    length = (bitlength + 7) // 8
    a = create_string_buffer(length)
    PyLong_AsByteArray(lnum, a, len(a), 1, 1)  # 4th param is for endianness 0 - big, non 0 - little
    return a.raw


#
# Firmware Table Provider Signatures
#
FirmwareTableProviderSignature_ACPI = 0x41435049  # 'ACPI' - The ACPI firmware table provider
FirmwareTableProviderSignature_FIRM = 0x4649524D  # 'FIRM' - The raw firmware table provider
FirmwareTableProviderSignature_RSMB = 0x52534D42  # 'RSMB' - The raw SMBIOS firmware table provider

FirmwareTableID_RSDT = 0x54445352
FirmwareTableID_XSDT = 0x54445358


class EFI_HDR_WIN(namedtuple('EFI_HDR_WIN', 'Size DataOffset DataSize Attributes guid')):
    __slots__ = ()

    def __str__(self):
        return """
Header (Windows)
----------------
VendorGuid= {{{}}}
Size = 0x{:08X}
DataOffset= 0x{:08X}
DataSize = 0x{:08X}
Attributes= 0x{:08X}
""".format(EFI_GUID_STR(self.guid), self.Size, self.DataOffset, self.DataSize, self.Attributes)


def _handle_winerror(fn, msg, hr):
    _handle_error(("{} failed: {} ({:d})".format(fn, msg, hr)), hr)


def _handle_error(err, hr=0):
    logger().log_debug(err)
    raise OsHelperError(err, hr)


class WindowsHelper(Helper):

    def __init__(self):
        super(WindowsHelper, self).__init__()

        self.os_system = platform.system()
        self.os_release = platform.release()
        self.os_version = platform.version()
        self.os_machine = platform.machine()
        self.os_uname = platform.uname()
        self.name = "WindowsHelper"
        if "windows" == self.os_system.lower():
            win_ver = "win7_" + self.os_machine.lower()
            if ("5" == self.os_release):
                win_ver = "winxp"
            logger().log_debug("[helper] OS: {} {} {}".format(self.os_system, self.os_release, self.os_version))

        self.use_existing_service = False

        self.win_ver = win_ver
        self.driver_handle = None
        self.device_file = str(DEVICE_FILE)

        c_int_p = POINTER(c_int)
        c_uint32_p = POINTER(c_uint32)

        # enable required SeSystemEnvironmentPrivilege privilege
        privilege = win32security.LookupPrivilegeValue(None, 'SeSystemEnvironmentPrivilege')
        token = win32security.OpenProcessToken(win32process.GetCurrentProcess(), win32security.TOKEN_READ | win32security.TOKEN_ADJUST_PRIVILEGES)
        win32security.AdjustTokenPrivileges(token, False, [(privilege, win32security.SE_PRIVILEGE_ENABLED)])
        win32api.CloseHandle(token)
        # import firmware variable API
        try:
            self.GetFirmwareEnvironmentVariable = kernel32.GetFirmwareEnvironmentVariableW
            self.GetFirmwareEnvironmentVariable.restype = c_int
            self.GetFirmwareEnvironmentVariable.argtypes = [c_wchar_p, c_wchar_p, c_void_p, c_int]
            self.SetFirmwareEnvironmentVariable = kernel32.SetFirmwareEnvironmentVariableW
            self.SetFirmwareEnvironmentVariable.restype = c_int
            self.SetFirmwareEnvironmentVariable.argtypes = [c_wchar_p, c_wchar_p, c_void_p, c_int]
        except AttributeError:
            logger().log_warning("G[S]etFirmwareEnvironmentVariableW function doesn't seem to exist")

        try:
            self.NtEnumerateSystemEnvironmentValuesEx = windll.ntdll.NtEnumerateSystemEnvironmentValuesEx
            self.NtEnumerateSystemEnvironmentValuesEx.restype = c_int
            self.NtEnumerateSystemEnvironmentValuesEx.argtypes = [c_int, c_void_p, c_void_p]
        except AttributeError:
            logger().log_warning("NtEnumerateSystemEnvironmentValuesEx function doesn't seem to exist")

        try:
            self.GetFirmwareEnvironmentVariableEx = kernel32.GetFirmwareEnvironmentVariableExW
            self.GetFirmwareEnvironmentVariableEx.restype = c_int
            self.GetFirmwareEnvironmentVariableEx.argtypes = [c_wchar_p, c_wchar_p, c_void_p, c_int, c_int_p]
            self.SetFirmwareEnvironmentVariableEx = kernel32.SetFirmwareEnvironmentVariableExW
            self.SetFirmwareEnvironmentVariableEx.restype = c_int
            self.SetFirmwareEnvironmentVariableEx.argtypes = [c_wchar_p, c_wchar_p, c_void_p, c_int, c_int]
        except AttributeError:
            logger().log_debug("G[S]etFirmwareEnvironmentVariableExW function doesn't seem to exist")

        try:
            self.GetSystemFirmwareTbl = kernel32.GetSystemFirmwareTable
            self.GetSystemFirmwareTbl.restype = c_int
            self.GetSystemFirmwareTbl.argtypes = [c_int, c_int, c_void_p, c_int]
        except AttributeError:
            logger().log_warning("GetSystemFirmwareTable function doesn't seem to exist")

        try:
            self.EnumSystemFirmwareTbls = kernel32.EnumSystemFirmwareTables
            self.EnumSystemFirmwareTbls.restype = c_int
            self.EnumSystemFirmwareTbls.argtypes = [c_int, c_void_p, c_int]
        except AttributeError:
            logger().log_warning("GetSystemFirmwareTable function doesn't seem to exist")

        try:
            self.NtQuerySystemInformation = windll.ntdll.NtQuerySystemInformation
            self.NtQuerySystemInformation.restype = c_int
            self.NtQuerySystemInformation.argtypes = [c_uint32, c_void_p, c_uint32, c_uint32_p]
        except AttributeError:
            logger().log_warning("NtQuerySystemInformation function doesn't seem to exist")

    def __del__(self):
        if self.driver_handle:
            win32api.CloseHandle(self.driver_handle)
            self.driver_handle = None

###############################################################################################
# Driver/service management functions
###############################################################################################

    def show_warning(self):
        logger().log("")
        logger().log_warning("*******************************************************************")
        logger().log_warning("Chipsec should only be used on test systems!")
        logger().log_warning("It should not be installed/deployed on production end-user systems.")
        logger().log_warning("See WARNING.txt")
        logger().log_warning("*******************************************************************")
        logger().log("")

    #
    # Create (register/install) chipsec service
    #
    def create(self):
        # check DRIVER_FILE_PATHS for the DRIVER_FILE_NAME
        self.driver_path = None
        for path in DRIVER_FILE_PATHS:
            driver_path = os.path.join(path, DRIVER_FILE_NAME)
            if os.path.isfile(driver_path):
                self.driver_path = driver_path
                logger().log_debug("[helper] found driver in {}".format(driver_path))
        if self.driver_path is None:
            logger().log_debug("[helper] CHIPSEC Windows Driver Not Found")
            raise Exception("CHIPSEC Windows Driver Not Found")

        self.show_warning()

        try:
            hscm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)  # SC_MANAGER_CREATE_SERVICE
        except win32service.error as err:
            _handle_winerror(err.args[1], err.args[2], err.args[0])
        logger().log_debug("[helper] service control manager opened (handle = {})".format(hscm))
        logger().log_debug("[helper] driver path: '{}'".format(os.path.abspath(self.driver_path)))

        try:
            hs = win32service.CreateService(
                hscm,
                SERVICE_NAME,
                DISPLAY_NAME,
                (win32service.SERVICE_QUERY_STATUS | win32service.SERVICE_START | win32service.SERVICE_STOP),
                win32service.SERVICE_KERNEL_DRIVER,
                win32service.SERVICE_DEMAND_START,
                win32service.SERVICE_ERROR_NORMAL,
                os.path.abspath(self.driver_path),
                None, 0, u"", None, None)
            if hs:
                logger().log_debug("[helper] service '{}' created (handle = 0x{:08X})".format(SERVICE_NAME, int(hs)))
        except win32service.error as err:
            if (winerror.ERROR_SERVICE_EXISTS == err.args[0]):
                logger().log_debug("[helper] service '{}' already exists: {} ({:d})".format(SERVICE_NAME, err.args[2], err.args[0]))
                try:
                    hs = win32service.OpenService(hscm, SERVICE_NAME, (win32service.SERVICE_QUERY_STATUS | win32service.SERVICE_START | win32service.SERVICE_STOP))  # SERVICE_ALL_ACCESS
                except win32service.error as _err:
                    _handle_winerror(_err.args[1], _err.args[2], _err.args[0])
            else:
                _handle_winerror(err.args[1], err.args[2], err.args[0])

        finally:
            win32service.CloseServiceHandle(hs)
            win32service.CloseServiceHandle(hscm)

        return True

    #
    # Remove (delete/unregister/uninstall) chipsec service
    #
    def delete(self, start_driver):
        if not start_driver:
            return True
        if self.use_existing_service:
            return True

        if win32serviceutil.QueryServiceStatus(SERVICE_NAME)[1] != win32service.SERVICE_STOPPED:
            logger().log_warning("cannot delete service '{}' (not stopped)".format(SERVICE_NAME))
            return False

        logger().log_debug("[helper] deleting service '{}'...".format(SERVICE_NAME))
        try:
            win32serviceutil.RemoveService(SERVICE_NAME)
            logger().log_debug("[helper] service '{}' deleted".format(SERVICE_NAME))
        except win32service.error as err:
            logger().log_debug("RemoveService failed: {} ({:d})".format(err.args[2], err.args[0]))
            return False

        return True

    #
    # Start chipsec service
    #
    def start(self):
        # we are in native API mode so not starting the service/driver
        self.use_existing_service = (win32serviceutil.QueryServiceStatus(SERVICE_NAME)[1] == win32service.SERVICE_RUNNING)

        if self.use_existing_service:
            self.driver_loaded = True
            logger().log_debug("[helper] service '{}' already running".format(SERVICE_NAME))
            logger().log_debug("[helper] trying to connect to existing '{}' service...".format(SERVICE_NAME))
        else:
            # if self.use_existing_service:
            #    _handle_error("connecting to existing '{}' service failed (service is not running)".format(SERVICE_NAME))
            try:
                win32serviceutil.StartService(SERVICE_NAME)
                win32serviceutil.WaitForServiceStatus(SERVICE_NAME, win32service.SERVICE_RUNNING, 1)
                self.driver_loaded = True
                logger().log_debug("[helper] service '{}' started".format(SERVICE_NAME))
            except pywintypes.error as err:
                _handle_error("service '{}' didn't start: {} ({:d})".format(SERVICE_NAME, err.args[2], err.args[0]), err.args[0])
        self.driverpath = win32serviceutil.LocateSpecificServiceExe(SERVICE_NAME)
        return True

    #
    # Stop chipsec service
    #
    def stop(self, start_driver):
        if not start_driver:
            return True
        if self.use_existing_service:
            return True

        logger().log_debug("[helper] stopping service '{}'..".format(SERVICE_NAME))
        try:
            win32api.CloseHandle(self.driver_handle)
            self.driver_handle = None
            win32serviceutil.StopService(SERVICE_NAME)
        except pywintypes.error as err:
            logger().log_debug("StopService failed: {} ({:d})".format(err.args[2], err.args[0]))
            return False
        finally:
            self.driver_loaded = False

        try:
            win32serviceutil.WaitForServiceStatus(SERVICE_NAME, win32service.SERVICE_STOPPED, 1)
            logger().log_debug("[helper] service '{}' stopped".format(SERVICE_NAME))
        except pywintypes.error as err:
            logger().log_debug("service '{}' didn't stop: {} ({:d})".format(SERVICE_NAME, err.args[2], err.args[0]))
            return False

        return True

    def get_driver_handle(self):
        # This is bad but DeviceIoControl fails ocasionally if new device handle is not opened every time ;(
        if (self.driver_handle is not None) and (INVALID_HANDLE_VALUE != self.driver_handle):
            return self.driver_handle

        self.driver_handle = win32file.CreateFile(self.device_file, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, None)
        if (self.driver_handle is None) or (INVALID_HANDLE_VALUE == self.driver_handle):
            _handle_error(drv_hndl_error_msg, errno.ENXIO)
        else:
            logger().log_debug("[helper] opened device '{:.64}' (handle: {:08X})".format(DEVICE_FILE, int(self.driver_handle)))
        return self.driver_handle

    def check_driver_handle(self):
        if (0x6 == kernel32.GetLastError()):
            # kernel32.CloseHandle(self.driver_handle)
            win32api.CloseHandle(self.driver_handle)
            self.driver_handle = None
            self.get_driver_handle()
            logger().log_warning("Invalid handle (wtf?): re-opened device '{:.64}' (new handle: {:08X})".format(self.device_file, int(self.driver_handle)))
            return False
        return True

    #
    # Auxiliary functions
    #
    def get_threads_count(self):
        sum = 0
        proc_group_count = (kernel32.GetActiveProcessorGroupCount() & 0xFFFF)
        for grp in range(proc_group_count):
            procs = kernel32.GetActiveProcessorCount(grp)
            sum = sum + procs
        return sum

    def getcwd(self):
        return ("\\\\?\\" + os.getcwd())

    #
    # Generic IOCTL call function
    #
    def _ioctl(self, ioctl_code, in_buf, out_length):

        if not self.driver_loaded:
            _handle_error("chipsec kernel driver is not loaded (in native API mode?)")

        out_buf = (c_char * out_length)()
        self.get_driver_handle()
        try:
            out_buf = win32file.DeviceIoControl(self.driver_handle, ioctl_code, in_buf, out_length, None)
        except pywintypes.error as _err:
            err_status = _err.args[0] + 0x100000000
            if STATUS_PRIVILEGED_INSTRUCTION == err_status:
                err_msg = "HW Access Violation: DeviceIoControl returned STATUS_PRIVILEGED_INSTRUCTION (0x{:X})".format(err_status)
                logger().log_debug(err_msg)
                raise HWAccessViolationError(err_msg, err_status)
            else:
                _handle_error("HW Access Error: DeviceIoControl returned status 0x{:X} ({})".format(err_status, _err.args[2]), err_status)

        return out_buf

###############################################################################################
# Actual driver IOCTL functions to access HW resources
###############################################################################################

    def read_phys_mem(self, phys_address, length):
        out_length = length
        in_buf = struct.pack('3I', (phys_address >> 32) & 0xFFFFFFFF, phys_address & 0xFFFFFFFF, length)
        out_buf = self._ioctl(IOCTL_READ_PHYSMEM, in_buf, out_length)
        return out_buf

    def write_phys_mem(self, phys_address, length, buf):
        in_buf = struct.pack('3I', (phys_address >> 32) & 0xFFFFFFFF, phys_address & 0xFFFFFFFF, length) + stringtobytes(buf)
        out_buf = self._ioctl(IOCTL_WRITE_PHYSMEM, in_buf, 4)
        return out_buf

    # @TODO: Temporarily the same as read_phys_mem for compatibility
    def read_mmio_reg(self, bar_base, size, offset=0, bar_size=None):
        phys_address = bar_base + offset
        out_size = size
        logger().log_debug("[helper] -> read_mmio_reg(phys_address=0x{:X}, size={})".format(phys_address, size))
        in_buf = struct.pack('3I', (phys_address >> 32) & 0xFFFFFFFF, phys_address & 0xFFFFFFFF, size)
        out_buf = self._ioctl(IOCTL_READ_MMIO, in_buf, out_size)
        return defines.unpack1(out_buf, size)

    def write_mmio_reg(self, bar_base, size, value, offset=0, bar_size=None):
        phys_address = bar_base + offset
        if size == 8:
            buf = struct.pack('=Q', value)
        elif size == 4:
            buf = struct.pack('=I', value & 0xFFFFFFFF)
        elif size == 2:
            buf = struct.pack('=H', value & 0xFFFF)
        elif size == 1:
            buf = struct.pack('=B', value & 0xFF)
        else:
            return False
        in_buf = struct.pack('3I', ((phys_address >> 32) & 0xFFFFFFFF), (phys_address & 0xFFFFFFFF), size) + buf
        out_buf = self._ioctl(IOCTL_WRITE_MMIO, in_buf, 4)
        return out_buf

    def alloc_phys_mem(self, length, max_pa):
        out_length = 16
        in_buf = struct.pack('QI', max_pa, length)
        out_buf = self._ioctl(IOCTL_ALLOC_PHYSMEM, in_buf, out_length)
        (va, pa) = struct.unpack('2Q', out_buf)
        return (va, pa)

    def va2pa(self, va):
        error_code = 0
        out_length = 8
        in_buf = struct.pack('Q', va)
        out_buf = self._ioctl(IOCTL_GET_PHYSADDR, in_buf, out_length)
        pa = struct.unpack('Q', out_buf)[0]
        return (pa, error_code)

    #
    # HYPERCALL
    #
    def hypercall(self, rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer):
        if self.os_machine == 'AMD64':
            arg_type = 'Q'
            out_length = 8
        else:
            arg_type = 'I'
            out_length = 4
        in_buf = struct.pack('<11' + arg_type, rcx, rdx, r8, r9, r10, r11, rax, rbx, rdi, rsi, xmm_buffer)
        out_buf = self._ioctl(IOCTL_HYPERCALL, in_buf, out_length)
        return struct.unpack('<' + arg_type, out_buf)[0]

    #
    # MAP_IO_SPACE
    #
    def map_io_space(self, physical_address, length, cache_type):
        out_length = 8
        in_buf = struct.pack('<3Q', physical_address, length, cache_type)
        out_buf = self._ioctl(IOCTL_MAP_IO_SPACE, in_buf, out_length)
        virtual_address = struct.unpack('<Q', out_buf)[0]
        return virtual_address

    #
    # FREE_PHYS_MEM
    #
    def free_phys_mem(self, physical_address):
        out_length = 8
        in_buf = struct.pack('<Q', physical_address)
        self._ioctl(IOCTL_FREE_PHYSMEM, in_buf, out_length)
        return

    def read_msr(self, cpu_thread_id, msr_addr):
        out_length = 8
        in_buf = struct.pack('=2I', cpu_thread_id, msr_addr)
        out_buf = self._ioctl(IOCTL_RDMSR, in_buf, out_length)
        (eax, edx) = struct.unpack('2I', out_buf)
        return (eax, edx)

    def write_msr(self, cpu_thread_id, msr_addr, eax, edx):
        out_length = 0
        in_buf = struct.pack('=4I', cpu_thread_id, msr_addr, eax, edx)
        self._ioctl(IOCTL_WRMSR, in_buf, out_length)
        return

    def read_pci_reg(self, bus, device, function, address, size):
        bdf = PCI_BDF(bus & 0xFFFF, device & 0xFFFF, function & 0xFFFF, address & 0xFFFF)
        out_length = size
        in_buf = struct.pack('4HB', bdf.BUS, bdf.DEV, bdf.FUNC, bdf.OFF, size)
        out_buf = self._ioctl(READ_PCI_CFG_REGISTER, in_buf, out_length)
        if 1 == size:
            value = struct.unpack('B', out_buf)[0]
        elif 2 == size:
            value = struct.unpack('H', out_buf)[0]
        else:
            value = struct.unpack('I', out_buf)[0]
        return value

    def write_pci_reg(self, bus, device, function, address, value, size):
        bdf = PCI_BDF(bus & 0xFFFF, device & 0xFFFF, function & 0xFFFF, address & 0xFFFF)
        out_length = 0
        in_buf = struct.pack('4HIB', bdf.BUS, bdf.DEV, bdf.FUNC, bdf.OFF, value, size)
        self._ioctl(WRITE_PCI_CFG_REGISTER, in_buf, out_length)
        return True

    def load_ucode_update(self, cpu_thread_id, ucode_update_buf):
        out_length = 0
        in_buf = struct.pack('=IH', cpu_thread_id, len(ucode_update_buf)) + ucode_update_buf
        self._ioctl(IOCTL_LOAD_UCODE_PATCH, in_buf, out_length)
        return True

    def read_io_port(self, io_port, size):
        value = 0
        in_buf = struct.pack('=HB', io_port, size)
        out_buf = self._ioctl(IOCTL_READ_IO_PORT, in_buf, size)
        if 1 == size:
            value = struct.unpack('B', out_buf)[0]
        elif 2 == size:
            value = struct.unpack('H', out_buf)[0]
        else:
            value = struct.unpack('I', out_buf)[0]
        return value

    def write_io_port(self, io_port, value, size):
        in_buf = struct.pack('=HIB', io_port, value, size)
        self._ioctl(IOCTL_WRITE_IO_PORT, in_buf, 0)
        return True

    def read_cr(self, cpu_thread_id, cr_number):
        value = 0
        in_buf = struct.pack('=HI', cr_number, cpu_thread_id)
        out_buf = self._ioctl(IOCTL_RDCR, in_buf, 8)
        value, = struct.unpack('=Q', out_buf)
        return value

    def write_cr(self, cpu_thread_id, cr_number, value):
        in_buf = struct.pack('=HQI', cr_number, value, cpu_thread_id)
        self._ioctl(IOCTL_WRCR, in_buf, 0)
        return True

    #
    # IDTR/GDTR/LDTR
    #
    def get_descriptor_table(self, cpu_thread_id, desc_table_code):
        in_buf = struct.pack('IB', cpu_thread_id, desc_table_code)
        out_buf = self._ioctl(IOCTL_GET_CPU_DESCRIPTOR_TABLE, in_buf, 18)
        (limit, base, pa) = struct.unpack('=HQQ', out_buf)
        return (limit, base, pa)

    #
    # Interrupts
    #
    def send_sw_smi(self, cpu_thread_id, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi):
        if (sys.maxsize < 2**32 and self.os_machine == 'AMD64') or (sys.maxsize > 2**32 and self.os_machine == 'i386'):
            logger().log("[helper] Python architecture must match OS architecture.  Run with {} architecture of python".format(self.os_machine))
        out_length = struct.calcsize(_smi_msg_t_fmt)
        in_buf = struct.pack(_smi_msg_t_fmt, SMI_code_data, _rax, _rbx, _rcx, _rdx, _rsi, _rdi)
        out_buf = self._ioctl(IOCTL_SWSMI, in_buf, out_length)
        if out_buf:
            ret = struct.unpack(_smi_msg_t_fmt, out_buf)
        else:
            ret = None
        return ret

    def _get_handle_for_pid(self, pid=0, ro=True):
        if pid == 0:
            pHandle = win32process.GetCurrentProcess()
        else:
            flags = win32con.PROCESS_QUERY_INFORMATION
            if not ro:
                flags |= win32con.PROCESS_SET_INFORMATION
            try:
                pHandle = win32api.OpenProcess(flags, 0, pid)
            except pywintypes.error as e:
                logger().log_debug("unable to open a process handle")
                raise ValueError(e)
        return pHandle

    def set_affinity(self, value):
        pHandle = self._get_handle_for_pid(0, False)
        current = win32process.GetProcessAffinityMask(pHandle)[0]
        try:
            win32process.SetProcessAffinityMask(pHandle, current)
        except win32process.error as e:
            logger().log_debug("unable to set process affinity")
            raise ValueError(e)
        return current

    def get_affinity(self):
        pHandle = self._get_handle_for_pid()
        try:
            return win32process.GetProcessAffinityMask(pHandle)[0]
        except win32process.error as e:
            logger().log_debug("unable to get the running cpu")
            raise ValueError(e)

    #
    # CPUID
    #
    def cpuid(self, eax, ecx):
        out_length = 16
        in_buf = struct.pack('=2I', eax, ecx)
        out_buf = self._ioctl(IOCTL_CPUID, in_buf, out_length)
        (eax, ebx, ecx, edx) = struct.unpack('4I', out_buf)
        return (eax, ebx, ecx, edx)

    def get_ACPI_SDT(self):
        sdt = self.native_get_ACPI_table('XSDT')  # FirmwareTableID_XSDT
        xsdt = sdt is not None
        if not xsdt:
            sdt = self.native_get_ACPI_table('RSDT')  # FirmwareTableID_RSDT
        return sdt, xsdt

    def native_get_ACPI_table(self, table_name):
        table_size = 36
        tBuffer = create_string_buffer(table_size)
        tbl = struct.unpack("<I", bytes(table_name, 'ascii'))[0]
        retVal = self.GetSystemFirmwareTbl(FirmwareTableProviderSignature_ACPI, tbl, tBuffer, table_size)
        if retVal == 0:
            logger().log_debug('GetSystemFirmwareTable({}) returned error: {}'.format(table_name, winerror()))
            return None
        if retVal > table_size:
            table_size = retVal
            tBuffer = create_string_buffer(table_size)
            retVal = self.GetSystemFirmwareTbl(FirmwareTableProviderSignature_ACPI, tbl, tBuffer, table_size)
        return tBuffer[:retVal]

    # ACPI access is implemented through ACPI HAL rather than through kernel module
    def get_ACPI_table(self, table_name):
        raise UnimplementedAPIError("get_ACPI_table")

    #
    # IOSF Message Bus access
    #

    def msgbus_send_read_message(self, mcr, mcrx):
        logger().log_debug("[helper] Message Bus is not supported yet")
        return None

    def msgbus_send_write_message(self, mcr, mcrx, mdr):
        logger().log_debug("[helper] Message Bus is not supported yet")
        return None

    def msgbus_send_message(self, mcr, mcrx, mdr=None):
        logger().log_debug("[helper] Message Bus is not supported yet")
        return None

    #
    # Speculation control
    #
    def retpoline_enabled(self):
        # See https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
        speculation_control = c_uint32(0)
        SystemSpeculationControlInformation = 0xC9
        SpecCtrlRetpolineEnabled = 0x4000
        self.NtQuerySystemInformation(SystemSpeculationControlInformation, addressof(speculation_control), sizeof(speculation_control), None)
        return speculation_control.value & SpecCtrlRetpolineEnabled


#
# Get instance of this OS helper
#
def get_helper():
    return WindowsHelper()
