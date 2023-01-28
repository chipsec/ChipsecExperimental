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
Common UEFI/EFI functionality including UEFI variables, Firmware Volumes, Secure Boot variables,
S3 boot-script, UEFI tables, etc.
"""

from collections import namedtuple
import struct
from uuid import UUID
from chipsec.defines import bytestostring


class StatusCode:
    EFI_SUCCESS = 0
    EFI_LOAD_ERROR = 1
    EFI_INVALID_PARAMETER = 2
    EFI_UNSUPPORTED = 3
    EFI_BAD_BUFFER_SIZE = 4
    EFI_BUFFER_TOO_SMALL = 5
    EFI_NOT_READY = 6
    EFI_DEVICE_ERROR = 7
    EFI_WRITE_PROTECTED = 8
    EFI_OUT_OF_RESOURCES = 9
    EFI_VOLUME_CORRUPTED = 10
    EFI_VOLUME_FULL = 11
    EFI_NO_MEDIA = 12
    EFI_MEDIA_CHANGED = 13
    EFI_NOT_FOUND = 14
    EFI_ACCESS_DENIED = 15
    EFI_NO_RESPONSE = 16
    EFI_NO_MAPPING = 17
    EFI_TIMEOUT = 18
    EFI_NOT_STARTED = 19
    EFI_ALREADY_STARTED = 20
    EFI_ABORTED = 21
    EFI_ICMP_ERROR = 22
    EFI_TFTP_ERROR = 23
    EFI_PROTOCOL_ERROR = 24
    EFI_INCOMPATIBLE_VERSION = 25
    EFI_SECURITY_VIOLATION = 26
    EFI_CRC_ERROR = 27
    EFI_END_OF_MEDIA = 28
    EFI_END_OF_FILE = 31
    EFI_INVALID_LANGUAGE = 32
    EFI_COMPROMISED_DATA = 33
    EFI_HTTP_ERROR = 35


EFI_STATUS_DICT = {
    StatusCode.EFI_SUCCESS: "EFI_SUCCESS",
    StatusCode.EFI_LOAD_ERROR: "EFI_LOAD_ERROR",
    StatusCode.EFI_INVALID_PARAMETER: "EFI_INVALID_PARAMETER",
    StatusCode.EFI_UNSUPPORTED: "EFI_UNSUPPORTED",
    StatusCode.EFI_BAD_BUFFER_SIZE: "EFI_BAD_BUFFER_SIZE",
    StatusCode.EFI_BUFFER_TOO_SMALL: "EFI_BUFFER_TOO_SMALL",
    StatusCode.EFI_NOT_READY: "EFI_NOT_READY",
    StatusCode.EFI_DEVICE_ERROR: "EFI_DEVICE_ERROR",
    StatusCode.EFI_WRITE_PROTECTED: "EFI_WRITE_PROTECTED",
    StatusCode.EFI_OUT_OF_RESOURCES: "EFI_OUT_OF_RESOURCES",
    StatusCode.EFI_VOLUME_CORRUPTED: "EFI_VOLUME_CORRUPTED",
    StatusCode.EFI_VOLUME_FULL: "EFI_VOLUME_FULL",
    StatusCode.EFI_NO_MEDIA: "EFI_NO_MEDIA",
    StatusCode.EFI_MEDIA_CHANGED: "EFI_MEDIA_CHANGED",
    StatusCode.EFI_NOT_FOUND: "EFI_NOT_FOUND",
    StatusCode.EFI_ACCESS_DENIED: "EFI_ACCESS_DENIED",
    StatusCode.EFI_NO_RESPONSE: "EFI_NO_RESPONSE",
    StatusCode.EFI_NO_MAPPING: "EFI_NO_MAPPING",
    StatusCode.EFI_TIMEOUT: "EFI_TIMEOUT",
    StatusCode.EFI_NOT_STARTED: "EFI_NOT_STARTED",
    StatusCode.EFI_ALREADY_STARTED: "EFI_ALREADY_STARTED",
    StatusCode.EFI_ABORTED: "EFI_ABORTED",
    StatusCode.EFI_ICMP_ERROR: "EFI_ICMP_ERROR",
    StatusCode.EFI_TFTP_ERROR: "EFI_TFTP_ERROR",
    StatusCode.EFI_PROTOCOL_ERROR: "EFI_PROTOCOL_ERROR",
    StatusCode.EFI_INCOMPATIBLE_VERSION: "EFI_INCOMPATIBLE_VERSION",
    StatusCode.EFI_SECURITY_VIOLATION: "EFI_SECURITY_VIOLATION",
    StatusCode.EFI_CRC_ERROR: "EFI_CRC_ERROR",
    StatusCode.EFI_END_OF_MEDIA: "EFI_END_OF_MEDIA",
    StatusCode.EFI_END_OF_FILE: "EFI_END_OF_FILE",
    StatusCode.EFI_INVALID_LANGUAGE: "EFI_INVALID_LANGUAGE",
    StatusCode.EFI_COMPROMISED_DATA: "EFI_COMPROMISED_DATA",
    StatusCode.EFI_HTTP_ERROR: "EFI_HTTP_ERROR"
}

EFI_MAX_BIT = 0x8000000000000000


def EFI_ERROR_STR(error):
    """
    Translates an EFI_STATUS value into its corresponding textual representation.
    """
    error &= ~EFI_MAX_BIT
    try:
        return EFI_STATUS_DICT[error]
    except KeyError:
        return "UNKNOWN"


def align(of, size):
    of = (((of + size - 1) // size) * size)
    return of


def bit_set(value, mask, polarity=False):
    if polarity:
        value = ~value
    return ((value & mask) == mask)


def get_3b_size(s):
    return struct.unpack("I", s[:3] + b'\x00')[0]


EFI_GUID_FMT = "16s"
EFI_GUID_SIZE = struct.calcsize(EFI_GUID_FMT)


def EFI_GUID_STR(guid):
    guid_str = UUID(bytes_le=guid)
    return str(guid_str).upper()


# ################################################################################################3
# List of supported types of EFI NVRAM format (platform/vendor specific)
# ################################################################################################3

class FWType:
    # See "A Tour Beyond BIOS Implementing UEFI Authenticated
    # Variables in SMM with EDKII"
    EFI_FW_TYPE_UEFI = 'uefi'
    EFI_FW_TYPE_UEFI_AUTH = 'uefi_auth'
    # EFI_FW_TYPE_WIN = 'win'  # Windows 8 GetFirmwareEnvironmentVariable format
    EFI_FW_TYPE_VSS = 'vss'  # NVRAM using format with '$VSS' signature
    EFI_FW_TYPE_VSS_AUTH = 'vss_auth'  # NVRAM using format with '$VSS' signature with extra fields
    EFI_FW_TYPE_VSS2 = 'vss2'
    EFI_FW_TYPE_VSS2_AUTH = 'vss2_auth'
    EFI_FW_TYPE_VSS_APPLE = 'vss_apple'
    EFI_FW_TYPE_NVAR = 'nvar'  # 'NVAR' NVRAM format
    EFI_FW_TYPE_EVSA = 'evsa'  # 'EVSA' NVRAM format


fw_types = []
for i in [t for t in dir(FWType) if not callable(getattr(FWType, t))]:
    if not i.startswith('__'):
        fw_types.append(getattr(FWType, i))


NVRAM_ATTR_RT = 1
NVRAM_ATTR_DESC_ASCII = 2
NVRAM_ATTR_GUID = 4
NVRAM_ATTR_DATA = 8
NVRAM_ATTR_EXTHDR = 0x10
NVRAM_ATTR_AUTHWR = 0x40
NVRAM_ATTR_HER = 0x20
NVRAM_ATTR_VLD = 0x80

#
# Known GUIDs of NVRAM stored in EFI firmware volumes, FS files etc. of various firmware implementations
#
VARIABLE_STORE_FV_GUID = UUID('FFF12B8D-7696-4C8B-A985-2747075B4F50')
ADDITIONAL_NV_STORE_GUID = UUID('00504624-8A59-4EEB-BD0F-6B36E96128E0')
NVAR_NVRAM_FS_FILE = UUID("CEF5B9A3-476D-497F-9FDC-E98143E0422C")

LENOVO_FS1_GUID = UUID("16B45DA2-7D70-4AEA-A58D-760E9ECB841D")
LENOVO_FS2_GUID = UUID("E360BDBA-C3CE-46BE-8F37-B231E5CB9F35")

EFI_PLATFORM_FS_GUIDS = [LENOVO_FS1_GUID, LENOVO_FS2_GUID]
EFI_NVRAM_GUIDS = [VARIABLE_STORE_FV_GUID, ADDITIONAL_NV_STORE_GUID, NVAR_NVRAM_FS_FILE]

# #################################################################################################
#
# UEFI Table Parsing Functionality
#
# #################################################################################################
MAX_EFI_TABLE_SIZE = 0x1000

# typedef struct {
#   UINT64  Signature;
#   UINT32  Revision;
#   UINT32  HeaderSize;
#   UINT32  CRC32;
#   UINT32  Reserved;
# } EFI_TABLE_HEADER;

EFI_TABLE_HEADER_FMT = '=8sIIII'
EFI_TABLE_HEADER_SIZE = 0x18


class EFI_TABLE_HEADER(namedtuple('EFI_TABLE_HEADER', 'Signature Revision HeaderSize CRC32 Reserved')):
    __slots__ = ()

    def __str__(self):
        return """Header:
  Signature     : {}
  Revision      : {}
  HeaderSize    : 0x{:08X}
  CRC32         : 0x{:08X}
  Reserved      : 0x{:08X}""".format(bytestostring(self.Signature), EFI_SYSTEM_TABLE_REVISION(self.Revision), self.HeaderSize, self.CRC32, self.Reserved)


# #################################################################################################
# EFI System Table
# #################################################################################################
#
# \MdePkg\Include\Uefi\UefiSpec.h

EFI_SYSTEM_TABLE_SIGNATURE = 'IBI SYST'

EFI_2_70_SYSTEM_TABLE_REVISION = ((2 << 16) | (70))
EFI_2_60_SYSTEM_TABLE_REVISION = ((2 << 16) | (60))
EFI_2_50_SYSTEM_TABLE_REVISION = ((2 << 16) | (50))
EFI_2_40_SYSTEM_TABLE_REVISION = ((2 << 16) | (40))
EFI_2_31_SYSTEM_TABLE_REVISION = ((2 << 16) | (31))
EFI_2_30_SYSTEM_TABLE_REVISION = ((2 << 16) | (30))
EFI_2_20_SYSTEM_TABLE_REVISION = ((2 << 16) | (20))
EFI_2_10_SYSTEM_TABLE_REVISION = ((2 << 16) | (10))
EFI_2_00_SYSTEM_TABLE_REVISION = ((2 << 16) | (00))
EFI_1_10_SYSTEM_TABLE_REVISION = ((1 << 16) | (10))
EFI_1_02_SYSTEM_TABLE_REVISION = ((1 << 16) | (0o2))
EFI_REVISIONS = [EFI_2_70_SYSTEM_TABLE_REVISION, EFI_2_60_SYSTEM_TABLE_REVISION, EFI_2_50_SYSTEM_TABLE_REVISION, EFI_2_40_SYSTEM_TABLE_REVISION, EFI_2_31_SYSTEM_TABLE_REVISION, EFI_2_30_SYSTEM_TABLE_REVISION, EFI_2_20_SYSTEM_TABLE_REVISION, EFI_2_10_SYSTEM_TABLE_REVISION, EFI_2_00_SYSTEM_TABLE_REVISION, EFI_1_10_SYSTEM_TABLE_REVISION, EFI_1_02_SYSTEM_TABLE_REVISION]


def EFI_SYSTEM_TABLE_REVISION(revision):
    return ('{:d}.{:d}'.format(revision >> 16, revision & 0xFFFF))


EFI_SYSTEM_TABLE_FMT = '=12Q'


class EFI_SYSTEM_TABLE(namedtuple('EFI_SYSTEM_TABLE', 'FirmwareVendor FirmwareRevision ConsoleInHandle ConIn ConsoleOutHandle ConOut StandardErrorHandle StdErr RuntimeServices BootServices NumberOfTableEntries ConfigurationTable')):
    __slots__ = ()

    def __str__(self):
        return """EFI System Table:
  FirmwareVendor      : 0x{:016X}
  FirmwareRevision    : 0x{:016X}
  ConsoleInHandle     : 0x{:016X}
  ConIn               : 0x{:016X}
  ConsoleOutHandle    : 0x{:016X}
  ConOut              : 0x{:016X}
  StandardErrorHandle : 0x{:016X}
  StdErr              : 0x{:016X}
  RuntimeServices     : 0x{:016X}
  BootServices        : 0x{:016X}
  NumberOfTableEntries: 0x{:016X}
  ConfigurationTable  : 0x{:016X}
""".format(self.FirmwareVendor, self.FirmwareRevision, self.ConsoleInHandle, self.ConIn, self.ConsoleOutHandle, self.ConOut, self.StandardErrorHandle, self.StdErr, self.RuntimeServices, self.BootServices, self.NumberOfTableEntries, self.ConfigurationTable)


# #################################################################################################
# EFI Runtime Services Table
# #################################################################################################
#
# \MdePkg\Include\Uefi\UefiSpec.h

EFI_RUNTIME_SERVICES_SIGNATURE = 'RUNTSERV'
EFI_RUNTIME_SERVICES_REVISION = EFI_2_31_SYSTEM_TABLE_REVISION

EFI_RUNTIME_SERVICES_TABLE_FMT = '=14Q'


class EFI_RUNTIME_SERVICES_TABLE(namedtuple('EFI_RUNTIME_SERVICES_TABLE', 'GetTime SetTime GetWakeupTime SetWakeupTime SetVirtualAddressMap ConvertPointer GetVariable GetNextVariableName SetVariable GetNextHighMonotonicCount ResetSystem UpdateCapsule QueryCapsuleCapabilities QueryVariableInfo')):
    __slots__ = ()

    def __str__(self):
        return """Runtime Services:
  GetTime                  : 0x{:016X}
  SetTime                  : 0x{:016X}
  GetWakeupTime            : 0x{:016X}
  SetWakeupTime            : 0x{:016X}
  SetVirtualAddressMap     : 0x{:016X}
  ConvertPointer           : 0x{:016X}
  GetVariable              : 0x{:016X}
  GetNextVariableName      : 0x{:016X}
  SetVariable              : 0x{:016X}
  GetNextHighMonotonicCount: 0x{:016X}
  ResetSystem              : 0x{:016X}
  UpdateCapsule            : 0x{:016X}
  QueryCapsuleCapabilities : 0x{:016X}
  QueryVariableInfo        : 0x{:016X}
""".format(self.GetTime, self.SetTime, self.GetWakeupTime, self.SetWakeupTime, self.SetVirtualAddressMap, self.ConvertPointer, self.GetVariable, self.GetNextVariableName, self.SetVariable, self.GetNextHighMonotonicCount, self.ResetSystem, self.UpdateCapsule, self.QueryCapsuleCapabilities, self.QueryVariableInfo)


# #################################################################################################
# EFI Boot Services Table
# #################################################################################################
#
# \MdePkg\Include\Uefi\UefiSpec.h

EFI_BOOT_SERVICES_SIGNATURE = 'BOOTSERV'
EFI_BOOT_SERVICES_REVISION = EFI_2_31_SYSTEM_TABLE_REVISION

EFI_BOOT_SERVICES_TABLE_FMT = '=44Q'


class EFI_BOOT_SERVICES_TABLE(namedtuple('EFI_BOOT_SERVICES_TABLE', 'RaiseTPL RestoreTPL AllocatePages FreePages GetMemoryMap AllocatePool FreePool CreateEvent SetTimer WaitForEvent SignalEvent CloseEvent CheckEvent InstallProtocolInterface ReinstallProtocolInterface UninstallProtocolInterface HandleProtocol Reserved RegisterProtocolNotify LocateHandle LocateDevicePath InstallConfigurationTable LoadImage StartImage Exit UnloadImage ExitBootServices GetNextMonotonicCount Stall SetWatchdogTimer ConnectController DisconnectController OpenProtocol CloseProtocol OpenProtocolInformation ProtocolsPerHandle LocateHandleBuffer LocateProtocol InstallMultipleProtocolInterfaces UninstallMultipleProtocolInterfaces CalculateCrc32 CopyMem SetMem CreateEventEx')):
    __slots__ = ()

    def __str__(self):
        return """Boot Services:
  RaiseTPL                           : 0x{:016X}
  RestoreTPL                         : 0x{:016X}
  AllocatePages                      : 0x{:016X}
  FreePages                          : 0x{:016X}
  GetMemoryMap                       : 0x{:016X}
  AllocatePool                       : 0x{:016X}
  FreePool                           : 0x{:016X}
  CreateEvent                        : 0x{:016X}
  SetTimer                           : 0x{:016X}
  WaitForEvent                       : 0x{:016X}
  SignalEvent                        : 0x{:016X}
  CloseEvent                         : 0x{:016X}
  CheckEvent                         : 0x{:016X}
  InstallProtocolInterface           : 0x{:016X}
  ReinstallProtocolInterface         : 0x{:016X}
  UninstallProtocolInterface         : 0x{:016X}
  HandleProtocol                     : 0x{:016X}
  Reserved                           : 0x{:016X}
  RegisterProtocolNotify             : 0x{:016X}
  LocateHandle                       : 0x{:016X}
  LocateDevicePath                   : 0x{:016X}
  InstallConfigurationTable          : 0x{:016X}
  LoadImage                          : 0x{:016X}
  StartImage                         : 0x{:016X}
  Exit                               : 0x{:016X}
  UnloadImage                        : 0x{:016X}
  ExitBootServices                   : 0x{:016X}
  GetNextMonotonicCount              : 0x{:016X}
  Stall                              : 0x{:016X}
  SetWatchdogTimer                   : 0x{:016X}
  ConnectController                  : 0x{:016X}
  DisconnectController               : 0x{:016X}
  OpenProtocol                       : 0x{:016X}
  CloseProtocol                      : 0x{:016X}
  OpenProtocolInformation            : 0x{:016X}
  ProtocolsPerHandle                 : 0x{:016X}
  LocateHandleBuffer                 : 0x{:016X}
  LocateProtocol                     : 0x{:016X}
  InstallMultipleProtocolInterfaces  : 0x{:016X}
  UninstallMultipleProtocolInterfaces: 0x{:016X}
  CalculateCrc32                     : 0x{:016X}
  CopyMem                            : 0x{:016X}
  SetMem                             : 0x{:016X}
  CreateEventEx                      : 0x{:016X}
""".format(self.RaiseTPL, self.RestoreTPL, self.AllocatePages, self.FreePages, self.GetMemoryMap,
            self.AllocatePool, self.FreePool, self.CreateEvent, self.SetTimer, self.WaitForEvent,
            self.SignalEvent, self.CloseEvent, self.CheckEvent, self.InstallProtocolInterface,
            self.ReinstallProtocolInterface, self.UninstallProtocolInterface, self.HandleProtocol,
            self.Reserved, self.RegisterProtocolNotify, self.LocateHandle, self.LocateDevicePath,
            self.InstallConfigurationTable, self.LoadImage, self.StartImage, self.Exit, self.UnloadImage,
            self.ExitBootServices, self.GetNextMonotonicCount, self.Stall, self.SetWatchdogTimer, self.ConnectController,
            self.DisconnectController, self.OpenProtocol, self.CloseProtocol, self.OpenProtocolInformation,
            self.ProtocolsPerHandle, self.LocateHandleBuffer, self.LocateProtocol, self.InstallMultipleProtocolInterfaces,
            self.UninstallMultipleProtocolInterfaces, self.CalculateCrc32, self.CopyMem, self.SetMem, self.CreateEventEx)


# #################################################################################################
# EFI System Configuration Table
# #################################################################################################
#
# \MdePkg\Include\Uefi\UefiSpec.h
# -------------------------------

EFI_VENDOR_TABLE_FORMAT = '<' + EFI_GUID_FMT + 'Q'
EFI_VENDOR_TABLE_SIZE = struct.calcsize(EFI_VENDOR_TABLE_FORMAT)


class EFI_VENDOR_TABLE(namedtuple('EFI_VENDOR_TABLE', 'VendorGuidData VendorTable')):
    __slots__ = ()

    def VendorGuid(self):
        return EFI_GUID_STR(self.VendorGuidData)


class EFI_CONFIGURATION_TABLE:
    def __init__(self):
        self.VendorTables = {}

    def __str__(self):
        return ('Vendor Tables:\n{}'.format(''.join(['{{{}}} : 0x{:016X}\n'.format(vt, self.VendorTables[vt]) for vt in self.VendorTables])))


# #################################################################################################
# EFI DXE Services Table
# #################################################################################################
#
# \MdePkg\Include\Pi\PiDxeCis.h
# -----------------------------
#
EFI_DXE_SERVICES_TABLE_SIGNATURE = 'DXE_SERV'  # 0x565245535f455844
EFI_DXE_SERVICES_TABLE_FMT = '=17Q'


class EFI_DXE_SERVICES_TABLE(namedtuple('EFI_DXE_SERVICES_TABLE', 'AddMemorySpace AllocateMemorySpace FreeMemorySpace RemoveMemorySpace GetMemorySpaceDescriptor SetMemorySpaceAttributes GetMemorySpaceMap AddIoSpace AllocateIoSpace FreeIoSpace RemoveIoSpace GetIoSpaceDescriptor GetIoSpaceMap Dispatch Schedule Trust ProcessFirmwareVolume')):
    __slots__ = ()

    def __str__(self):
        return """DXE Services:
  AddMemorySpace          : 0x{:016X}
  AllocateMemorySpace     : 0x{:016X}
  FreeMemorySpace         : 0x{:016X}
  RemoveMemorySpace       : 0x{:016X}
  GetMemorySpaceDescriptor: 0x{:016X}
  SetMemorySpaceAttributes: 0x{:016X}
  GetMemorySpaceMap       : 0x{:016X}
  AddIoSpace              : 0x{:016X}
  AllocateIoSpace         : 0x{:016X}
  FreeIoSpace             : 0x{:016X}
  RemoveIoSpace           : 0x{:016X}
  GetIoSpaceDescriptor    : 0x{:016X}
  GetIoSpaceMap           : 0x{:016X}
  Dispatch                : 0x{:016X}
  Schedule                : 0x{:016X}
  Trust                   : 0x{:016X}
  ProcessFirmwareVolume   : 0x{:016X}
""".format(self.AddMemorySpace, self.AllocateMemorySpace, self.FreeMemorySpace, self.RemoveMemorySpace,
            self.GetMemorySpaceDescriptor, self.SetMemorySpaceAttributes, self.GetMemorySpaceMap, self.AddIoSpace,
            self.AllocateIoSpace, self.FreeIoSpace, self.RemoveIoSpace, self.GetIoSpaceDescriptor, self.GetIoSpaceMap,
            self.Dispatch, self.Schedule, self.Trust, self.ProcessFirmwareVolume)


# #################################################################################################
# EFI PEI Services Table
# #################################################################################################

EFI_FRAMEWORK_PEI_SERVICES_TABLE_SIGNATURE = 0x5652455320494550
FRAMEWORK_PEI_SPECIFICATION_MAJOR_REVISION = 0
FRAMEWORK_PEI_SPECIFICATION_MINOR_REVISION = 91
FRAMEWORK_PEI_SERVICES_REVISION = ((FRAMEWORK_PEI_SPECIFICATION_MAJOR_REVISION << 16) | (FRAMEWORK_PEI_SPECIFICATION_MINOR_REVISION))

# #################################################################################################
# EFI System Management System Table
# #################################################################################################

EFI_SMM_SYSTEM_TABLE_SIGNATURE = 'SMST'
EFI_SMM_SYSTEM_TABLE_REVISION = (0 << 16) | (0x09)

EFI_TABLES = {
    EFI_SYSTEM_TABLE_SIGNATURE: {'name': 'EFI System Table', 'struct': EFI_SYSTEM_TABLE, 'fmt': EFI_SYSTEM_TABLE_FMT},
    EFI_RUNTIME_SERVICES_SIGNATURE: {'name': 'EFI Runtime Services Table', 'struct': EFI_RUNTIME_SERVICES_TABLE, 'fmt': EFI_RUNTIME_SERVICES_TABLE_FMT},
    EFI_BOOT_SERVICES_SIGNATURE: {'name': 'EFI Boot Services Table', 'struct': EFI_BOOT_SERVICES_TABLE, 'fmt': EFI_BOOT_SERVICES_TABLE_FMT},
    EFI_DXE_SERVICES_TABLE_SIGNATURE: {'name': 'EFI DXE Services Table', 'struct': EFI_DXE_SERVICES_TABLE, 'fmt': EFI_DXE_SERVICES_TABLE_FMT}
    # EFI_FRAMEWORK_PEI_SERVICES_TABLE_SIGNATURE : {'name': 'EFI Framework PEI Services Table', 'struct': EFI_FRAMEWORK_PEI_SERVICES_TABLE, 'fmt': EFI_FRAMEWORK_PEI_SERVICES_TABLE_FMT},
    # EFI_SMM_SYSTEM_TABLE_SIGNATURE: {'name': 'EFI SMM System Table', 'struct': EFI_SMM_SYSTEM_TABLE, 'fmt': EFI_SMM_SYSTEM_TABLE_FMT},
    # EFI_CONFIG_TABLE_SIGNATURE: {'name': 'EFI Configuration Table', 'struct': EFI_CONFIG_TABLE, 'fmt': EFI_CONFIG_TABLE_FMT}
}
