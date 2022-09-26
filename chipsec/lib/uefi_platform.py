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
Platform specific UEFI functionality (parsing platform specific EFI NVRAM, capsules, etc.)
"""

import struct
from uuid import UUID

#################################################################################################
# Dell PFS support,
# relied heavily on uefi-firmware-parser (https://github.com/theopolis/uefi-firmware-parser)
#################################################################################################

PFS_SEC_HDR = "<16sIIIIIIIIII16s"
PFS_SEC_HDR_SIZE = struct.calcsize(PFS_SEC_HDR)
U1_GUID = UUID('59b3e2f6-4e42-41f3-b1f4-446a84bfc6d0')


class PfsFileSection:
    def __init__(self, data):
        self.data = data
        self.valid = (len(data) >= PFS_SEC_HDR_SIZE)
        data_offset = 0
        if (self.valid):
            gu1, u1, u2, u3, u4, u5, u6, sec_size, size1, size2, size3, gu2 = struct.unpack(
                PFS_SEC_HDR, data[:PFS_SEC_HDR_SIZE])
            self.valid = (len(data) >= (PFS_SEC_HDR_SIZE + sec_size + size1 + size2 + size3))
            if UUID(bytes_le=gu1) == U1_GUID:
                data_offset = 0x248
        if (self.valid):
            self.body = data[PFS_SEC_HDR_SIZE + data_offset:PFS_SEC_HDR_SIZE + sec_size]
            self.tail = data[PFS_SEC_HDR_SIZE + sec_size + size1 + size2 + size3:]

    def parse(self):
        return self.body


PFS_HDR_SIG = b"PFS.HDR."
PFS_FTR_SIG = b"PFS.FTR."
PFS_HDR_STRUC = "<8sII"
PFS_HDR_STRUC_SIZE = struct.calcsize(PFS_HDR_STRUC)
PFS_FTR_STRUC = "<II8s"
PFS_FTR_STRUC_SIZE = struct.calcsize(PFS_FTR_STRUC)


class PfsFile:

    def __init__(self, data, concat=False):
        self.data = data
        self.concat = concat
        self.valid = (len(data) >= (PFS_HDR_STRUC_SIZE + PFS_FTR_STRUC_SIZE))
        self.size = 0
        hdr_sig = ""
        ver = 0
        if (self.valid):
            hdr_sig, ver, self.size = struct.unpack(PFS_HDR_STRUC, data[:PFS_HDR_STRUC_SIZE])
            self.valid = (PFS_FTR_STRUC_SIZE <= len(data[PFS_HDR_STRUC_SIZE + self.size:]))
        if (self.valid):
            offset = PFS_HDR_STRUC_SIZE + self.size
            ftr_size, u, ftr_sig = struct.unpack(PFS_FTR_STRUC, data[offset:offset + PFS_FTR_STRUC_SIZE])
            self.valid = (hdr_sig == PFS_HDR_SIG) and (ftr_sig == PFS_FTR_SIG)
            self.valid = self.valid and (self.size == ftr_size) and ((offset + PFS_FTR_STRUC_SIZE) <= len(data))
        if (self.valid):
            self.body = data[PFS_HDR_STRUC_SIZE:PFS_HDR_STRUC_SIZE + self.size + PFS_FTR_STRUC_SIZE]
            self.tail = data[PFS_HDR_STRUC_SIZE + self.size + PFS_FTR_STRUC_SIZE:]

    def parse(self):
        pfs_sec = PfsFileSection(self.body)
        pfs_sec_data = []
        while pfs_sec.valid:
            sec_data = pfs_sec.parse()
            if sec_data[:len(PFS_HDR_SIG)] == PFS_HDR_SIG:
                sec_data = PfsFile(sec_data, True).parse()
            if sec_data is not None:
                pfs_sec_data.append(sec_data)
            pfs_sec = PfsFileSection(pfs_sec.tail)
        if self.concat:
            return b''.join(pfs_sec_data)
        else:
            return pfs_sec_data


def ParsePFS(data):
    pfs_file = PfsFile(data, True)
    if not pfs_file.valid:
        return None
    pfs_file_data = []
    while pfs_file.valid:
        pfs_data = pfs_file.parse()
        if pfs_data is not None:
            pfs_file_data.append(pfs_data)
        pfs_file = PfsFile(pfs_file.tail)
    return (pfs_file_data, pfs_file.data)
