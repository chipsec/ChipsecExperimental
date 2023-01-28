# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2022, Intel Corporation

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

import codecs
from collections import namedtuple
import os
import struct
from uuid import UUID

from chipsec.defines import is_printable
from chipsec.file import read_file, write_file
from chipsec.logger import logger
from chipsec.lib.uefi_common import fw_types, FWType, VARIABLE_STORE_FV_GUID
from chipsec.lib.display_format import print_buffer_bytes
from chipsec.lib.uefi_common import EFI_GUID_STR, EFI_GUID_SIZE, EFI_GUID_FMT
from chipsec.lib.uefi_fv import NextFwVolume, NextFwFile, EFI_FVB2_ERASE_POLARITY
from chipsec.lib.uefi_fv import EFI_FV_FILETYPE_RAW
from chipsec.lib.uefi_common import bit_set, get_3b_size, NVAR_NVRAM_FS_FILE
from chipsec.lib.uefi_common import NVRAM_ATTR_VLD, NVRAM_ATTR_DATA, NVRAM_ATTR_GUID
from chipsec.lib.uefi_common import NVRAM_ATTR_DESC_ASCII, NVRAM_ATTR_RT, NVRAM_ATTR_HER
from chipsec.lib.uefi_common import NVRAM_ATTR_EXTHDR, NVRAM_ATTR_AUTHWR, ADDITIONAL_NV_STORE_GUID

################################################################################################
#
# EFI Variable and Variable Store Defines
#
################################################################################################

# UDK2010.SR1\MdeModulePkg\Include\Guid\VariableFormat.h
#
# Variable data start flag.
#
VARIABLE_DATA = 0x55aa
VARIABLE_DATA_SIGNATURE = struct.pack('=H', VARIABLE_DATA)


#
# Variable Attributes
#
EFI_VARIABLE_NON_VOLATILE = 0x00000001  # Variable is non volatile
EFI_VARIABLE_BOOTSERVICE_ACCESS = 0x00000002  # Variable is boot time accessible
EFI_VARIABLE_RUNTIME_ACCESS = 0x00000004  # Variable is run-time accessible
EFI_VARIABLE_HARDWARE_ERROR_RECORD = 0x00000008  #
EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS = 0x00000010  # Variable is authenticated
EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS = 0x00000020  # Variable is time based authenticated
EFI_VARIABLE_APPEND_WRITE = 0x00000040  # Variable allows append
UEFI23_1_AUTHENTICATED_VARIABLE_ATTRIBUTES = (
    EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS)


def IS_VARIABLE_ATTRIBUTE(_c, _Mask):
    return ((_c & _Mask) != 0)


def IS_EFI_VARIABLE_AUTHENTICATED(attr):
    return (IS_VARIABLE_ATTRIBUTE(
        attr,
        EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS) or IS_VARIABLE_ATTRIBUTE(
            attr, EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS))


def IS_VARIABLE_STATE(_c, _Mask):
    return ((((~_c) & 0xFF) & ((~_Mask) & 0xFF)) != 0)


#
# Variable State flags
#
VAR_IN_DELETED_TRANSITION = 0xfe  # Variable is in obsolete transistion
VAR_DELETED = 0xfd  # Variable is obsolete
VAR_ADDED = 0x7f  # Variable has been completely added

MAX_VARIABLE_SIZE = 1024
MAX_NVRAM_SIZE = 1024 * 1024


def get_nvar_name(nvram, name_offset, isAscii):
    if isAscii:
        nend = nvram.find(b'\x00', name_offset)
        name = nvram[name_offset:nend].decode('latin1')
        name_size = len(name) + 1
        return (name, name_size)
    else:
        nend = nvram.find(b'\x00\x00', name_offset)
        name = nvram[name_offset:nend].decode('utf-16le')
        name_size = len(name) + 2
        return (name, name_size)


VARIABLE_SIGNATURE_VSS = VARIABLE_DATA_SIGNATURE


########################################################################################################
#
# UEFI Variables Parsing Functionality
#
########################################################################################################


EFI_VAR_NAME_PK = 'PK'
EFI_VAR_NAME_KEK = 'KEK'
EFI_VAR_NAME_db = 'db'
EFI_VAR_NAME_dbx = 'dbx'
EFI_VAR_NAME_SecureBoot = 'SecureBoot'
EFI_VAR_NAME_SetupMode = 'SetupMode'
EFI_VAR_NAME_CustomMode = 'CustomMode'
EFI_VAR_NAME_SignatureSupport = 'SignatureSupport'
EFI_VAR_NAME_certdb = 'certdb'
EFI_VAR_NAME_AuthVarKeyDatabase = 'AuthVarKeyDatabase'

#
# \MdePkg\Include\Guid\ImageAuthentication.h
#
# #define EFI_IMAGE_SECURITY_DATABASE_GUID \
#  { \
#    0xd719b2cb, 0x3d3a, 0x4596, { 0xa3, 0xbc, 0xda, 0xd0, 0xe, 0x67, 0x65, 0x6f } \
#  }
#
# \MdePkg\Include\Guid\GlobalVariable.h
#
# #define EFI_GLOBAL_VARIABLE \
#  { \
#    0x8BE4DF61, 0x93CA, 0x11d2, {0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C } \
#  }
#
EFI_GLOBAL_VARIABLE_GUID = '8be4df61-93ca-11d2-aa0d-00e098032b8c'
EFI_IMAGE_SECURITY_DATABASE_GUID = 'd719b2cb-3d3a-4596-a3bc-dad00e67656f'
# EFI_VAR_GUID_SecureBoot = EFI_GLOBAL_VARIABLE
# EFI_VAR_GUID_db         = EFI_IMAGE_SECURITY_DATABASE_GUID

EFI_VARIABLE_DICT = {
    EFI_VAR_NAME_PK: EFI_GLOBAL_VARIABLE_GUID,
    EFI_VAR_NAME_KEK: EFI_GLOBAL_VARIABLE_GUID,
    EFI_VAR_NAME_db: EFI_IMAGE_SECURITY_DATABASE_GUID,
    EFI_VAR_NAME_dbx: EFI_IMAGE_SECURITY_DATABASE_GUID,
    EFI_VAR_NAME_SecureBoot: EFI_GLOBAL_VARIABLE_GUID,
    EFI_VAR_NAME_SetupMode: EFI_GLOBAL_VARIABLE_GUID,
    EFI_VAR_NAME_CustomMode: EFI_GLOBAL_VARIABLE_GUID,
    EFI_VAR_NAME_SignatureSupport: EFI_GLOBAL_VARIABLE_GUID
}


SECURE_BOOT_KEY_VARIABLES = (EFI_VAR_NAME_PK, EFI_VAR_NAME_KEK, EFI_VAR_NAME_db, EFI_VAR_NAME_dbx)
SECURE_BOOT_VARIABLES = (EFI_VAR_NAME_SecureBoot, EFI_VAR_NAME_SetupMode) + SECURE_BOOT_KEY_VARIABLES
SECURE_BOOT_VARIABLES_ALL = (EFI_VAR_NAME_CustomMode, EFI_VAR_NAME_SignatureSupport) + SECURE_BOOT_VARIABLES
AUTHENTICATED_VARIABLES = (EFI_VAR_NAME_AuthVarKeyDatabase, EFI_VAR_NAME_certdb) + SECURE_BOOT_KEY_VARIABLES


def get_auth_attr_string(attr):
    attr_str = ' '
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS):
        attr_str = attr_str + 'AWS+'
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS):
        attr_str = attr_str + 'TBAWS+'
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_APPEND_WRITE):
        attr_str = attr_str + 'AW+'
    return attr_str[:-1].lstrip()


def get_attr_string(attr):
    attr_str = ' '
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_NON_VOLATILE):
        attr_str = attr_str + 'NV+'
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_BOOTSERVICE_ACCESS):
        attr_str = attr_str + 'BS+'
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_RUNTIME_ACCESS):
        attr_str = attr_str + 'RT+'
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_HARDWARE_ERROR_RECORD):
        attr_str = attr_str + 'HER+'
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS):
        attr_str = attr_str + 'AWS+'
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS):
        attr_str = attr_str + 'TBAWS+'
    if IS_VARIABLE_ATTRIBUTE(attr, EFI_VARIABLE_APPEND_WRITE):
        attr_str = attr_str + 'AW+'
    return attr_str[:-1].lstrip()


def print_efi_variable(offset, efi_var_buf, EFI_var_header, efi_var_name, efi_var_data, efi_var_guid, efi_var_attributes):
    logger().log('\n--------------------------------')
    logger().log('EFI Variable (offset = 0x{:X}):'.format(offset))
    logger().log('--------------------------------')

    # Print Variable Name
    logger().log(u'Name      : {}'.format(efi_var_name))
    # Print Variable GUID
    logger().log('Guid      : {}'.format(efi_var_guid))

    # Print Variable State
    if EFI_var_header:
        if 'State' in EFI_var_header._fields:
            state = EFI_var_header.State
            state_str = 'State     :'
            if IS_VARIABLE_STATE(state, VAR_IN_DELETED_TRANSITION):
                state_str = state_str + ' IN_DELETED_TRANSITION +'
            if IS_VARIABLE_STATE(state, VAR_DELETED):
                state_str = state_str + ' DELETED +'
            if IS_VARIABLE_STATE(state, VAR_ADDED):
                state_str = state_str + ' ADDED +'
            logger().log(state_str)

        # Print Variable Complete Header
        if EFI_var_header.__str__:
            logger().log_verbose(EFI_var_header)
        else:
            logger().log_verbose('Decoded Header ({}):'.format(EFI_VAR_DICT[FWType.EFI_FW_TYPE_UEFI]['name']))
            for attr in EFI_var_header._fields:
                logger().log_verbose('{} = {:X}'.format('{0:<16}'.format(attr), getattr(EFI_var_header, attr)))

    attr_str = ('Attributes: 0x{:X} ({})'.format(efi_var_attributes, get_attr_string(efi_var_attributes)))
    logger().log(attr_str)

    # Print Variable Data
    logger().log('Data:')
    print_buffer_bytes(efi_var_data)

    # Print Variable Full Contents
    logger().log_verbose('Full Contents:')
    if logger().VERBOSE:
        if efi_var_buf is not None:
            print_buffer_bytes(efi_var_buf)


def print_sorted_EFI_variables(variables):
    sorted_names = sorted(variables.keys())
    for name in sorted_names:
        for rec in variables[name]:
            #                   off,    buf,     hdr,         data,   guid,   attrs
            print_efi_variable(rec[0], rec[1], rec[2], name, rec[3], rec[4], rec[5])


def decode_EFI_variables(efi_vars, nvram_pth):
    # print decoded and sorted EFI variables into a log file
    print_sorted_EFI_variables(efi_vars)
    # write each EFI variable into its own binary file
    for name in efi_vars.keys():
        n = 0
        # off, buf, hdr, data, guid, attrs
        for (_, _, _, data, guid, attrs) in efi_vars[name]:
            # efi_vars[name] = (off, buf, hdr, data, guid, attrs)
            attr_str = get_attr_string(attrs)
            var_fname = os.path.join(nvram_pth, '{}_{}_{}_{:d}.bin'.format(name, guid, attr_str.strip(), n))
            write_file(var_fname, data)
            if name in SECURE_BOOT_KEY_VARIABLES:
                parse_efivar_file(var_fname, data, SECURE_BOOT_SIG_VAR)
            elif name == EFI_VAR_NAME_certdb:
                parse_efivar_file(var_fname, data, AUTH_SIG_VAR)
            elif name == EFI_VAR_NAME_AuthVarKeyDatabase:
                parse_efivar_file(var_fname, data, ESAL_SIG_VAR)
            n = n + 1


def identify_EFI_NVRAM(buffer):
    b = buffer
    for fw_type in fw_types:
        if EFI_VAR_DICT[fw_type]['func_getnvstore']:
            (offset, size, hdr) = EFI_VAR_DICT[fw_type]['func_getnvstore'](b)
            if offset != -1:
                return fw_type

    return None


def parse_EFI_variables(self, fname, rom, authvars, _fw_type=None):
    if _fw_type in fw_types:
        logger().log("[uefi] Using FW type (NVRAM format): {}".format(_fw_type))
    else:
        logger().error("Unrecognized FW type (NVRAM format) '{}'..".format(_fw_type))
        return False

    logger().log("[uefi] Searching for NVRAM in the binary..")
    efi_vars_store = find_EFI_variable_store(rom, _fw_type)
    if efi_vars_store:
        nvram_fname = fname + '.nvram.bin'
        write_file(nvram_fname, efi_vars_store)
        nvram_pth = fname + '.nvram.dir'
        if not os.path.exists(nvram_pth):
            os.makedirs(nvram_pth)
        logger().log("[uefi] Extracting EFI Variables in the NVRAM..")
        efi_vars = EFI_VAR_DICT[_fw_type]['func_getefivariables'](efi_vars_store)
        decode_EFI_variables(efi_vars, nvram_pth)
    else:
        logger().error("Did not find NVRAM")
        return False
    return True


def find_EFI_variable_store(rom_buffer, _FWType):
    if rom_buffer is None:
        logger().error('rom_buffer is None')
        return None

    rom = rom_buffer
    offset = 0
    size = len(rom_buffer)
    nvram_header = None

    if EFI_VAR_DICT[_FWType]['func_getnvstore']:
        (offset, size, nvram_header) = EFI_VAR_DICT[_FWType]['func_getnvstore'](rom)
        if (-1 == offset):
            logger().error("'func_getnvstore' is defined but could not find EFI NVRAM. Exiting..")
            return None
    else:
        logger().log("[uefi] 'func_getnvstore' is not defined in EFI_VAR_DICT. Assuming start offset 0..")

    if -1 == size:
        size = len(rom_buffer)
    nvram_buf = rom[offset: offset + size]

    if logger().UTIL_TRACE:
        logger().log('[uefi] Found EFI NVRAM at offset 0x{:08X}'.format(offset))
        logger().log("""
==================================================================
NVRAM: EFI Variable Store
==================================================================""")
        if nvram_header:
            logger().log(nvram_header)
    return nvram_buf


# #################################################################################################
#
# UEFI Variable (NVRAM) Parsing Functionality
#
# #################################################################################################

SIGNATURE_LIST = "<16sIII"
SIGNATURE_LIST_size = struct.calcsize(SIGNATURE_LIST)


def parse_sha256(data):
    return


def parse_rsa2048(data):
    return


def parse_rsa2048_sha256(data):
    return


def parse_sha1(data):
    return


def parse_rsa2048_sha1(data):
    return


def parse_x509(data):
    return


def parse_sha224(data):
    return


def parse_sha384(data):
    return


def parse_sha512(data):
    return


def parse_x509_sha256(data):
    return


def parse_x509_sha384(data):
    return


def parse_x509_sha512(data):
    return


def parse_external(data):
    return


def parse_pkcs7(data):
    return


sig_types = {"C1C41626-504C-4092-ACA9-41F936934328": ("EFI_CERT_SHA256_GUID", parse_sha256, 0x30, "SHA256"),
             "3C5766E8-269C-4E34-AA14-ED776E85B3B6": ("EFI_CERT_RSA2048_GUID", parse_rsa2048, 0x110, "RSA2048"),
             "E2B36190-879B-4A3D-AD8D-F2E7BBA32784": ("EFI_CERT_RSA2048_SHA256_GUID", parse_rsa2048_sha256, 0x110, "RSA2048_SHA256"),
             "826CA512-CF10-4AC9-B187-BE01496631BD": ("EFI_CERT_SHA1_GUID", parse_sha1, 0x24, "SHA1"),
             "67F8444F-8743-48F1-A328-1EAAB8736080": ("EFI_CERT_RSA2048_SHA1_GUID", parse_rsa2048_sha1, 0x110, "RSA2048_SHA1"),
             "A5C059A1-94E4-4AA7-87B5-AB155C2BF072": ("EFI_CERT_X509_GUID", parse_x509, 0, "X509"),
             "0B6E5233-A65C-44C9-9407-D9AB83BFC8BD": ("EFI_CERT_SHA224_GUID", parse_sha224, 0x2c, "SHA224"),
             "FF3E5307-9FD0-48C9-85F1-8AD56C701E01": ("EFI_CERT_SHA384_GUID", parse_sha384, 0x40, "SHA384"),
             "093E0FAE-A6C4-4F50-9F1B-D41E2B89C19A": ("EFI_CERT_SHA512_GUID", parse_sha512, 0x50, "SHA512"),
             "3bd2a492-96c0-4079-b420-fcf98ef103ed": ("EFI_CERT_X509_SHA256_GUID", parse_x509_sha256, 0x40, "X509_SHA256"),
             "7076876e-80c2-4ee6-aad2-28b349a6865b": ("EFI_CERT_X509_SHA384_GUID", parse_x509_sha384, 0x50, "X509_SHA384"),
             "446dbf63-2502-4cda-bcfa-2465d2b0fe9d": ("EFI_CERT_X509_SHA512_GUID", parse_x509_sha512, 0x60, "X509_SHA512"),
             "452e8ced-dfff-4b8c-ae01-5118862e682c": ("EFI_CERT_EXTERNAL_MANAGEMENT_GUID", parse_external, 0x11, "EXTERNAL_MANAGEMENT"),
             "4AAFD29D-68DF-49EE-8AA9-347D375665A7": ("EFI_CERT_TYPE_PKCS7_GUID", parse_pkcs7, 0, "PKCS7"),
             }


def parse_sb_db(db, decode_dir):
    entries = []
    dof = 0
    nsig = 0
    db_size = len(db)
    if 0 == db_size:
        return entries

    # some platforms have 0's in the beginnig, skip all 0 (no known SignatureType starts with 0x00):
    while (dof + SIGNATURE_LIST_size) < db_size:
        SignatureType0, SignatureListSize, SignatureHeaderSize, SignatureSize \
            = struct.unpack(SIGNATURE_LIST, db[dof:dof + SIGNATURE_LIST_size])

        # prevent infinite loop when parsing malformed var
        if SignatureListSize == 0:
            logger().log_bad("db parsing failed!")
            return entries

        # Determine the signature type
        SignatureType = EFI_GUID_STR(SignatureType0)
        sig_parse_f = None
        sig_size = 0
        if (SignatureType in sig_types.keys()):
            sig_name, sig_parse_f, sig_size, short_name = sig_types[SignatureType]
        else:
            logger().log_bad('Unknown signature type {}, skipping signature decode.'.format(SignatureType))
            dof += SignatureListSize
            continue

        # Extract signature data blobs
        if (((sig_size > 0) and (sig_size == SignatureSize)) or ((sig_size == 0) and (SignatureSize >= 0x10))):
            sof = 0
            sig_list = db[dof + SIGNATURE_LIST_size + SignatureHeaderSize:dof + SignatureListSize]
            sig_list_size = len(sig_list)
            while ((sof + EFI_GUID_SIZE) < sig_list_size):
                sig_data = sig_list[sof:sof + SignatureSize]
                owner0 = struct.unpack(EFI_GUID_FMT, sig_data[:EFI_GUID_SIZE])[0]
                owner = EFI_GUID_STR(owner0)
                data = sig_data[EFI_GUID_SIZE:]
                entries.append(data)
                sig_file_name = "{}-{}-{:02d}.bin".format(short_name, owner, nsig)
                sig_file_name = os.path.join(decode_dir, sig_file_name)
                write_file(sig_file_name, data)
                if (sig_parse_f is not None):
                    sig_parse_f(data)
                sof = sof + SignatureSize
                nsig = nsig + 1
        else:
            err_str = "Wrong SignatureSize for {} type: 0x{:X}." .format(SignatureType, SignatureSize)
            if (sig_size > 0):
                err_str = err_str + " Must be 0x{:X}.".format(sig_size)
            else:
                err_str = err_str + " Must be >= 0x10."
            logger().error(err_str)
            logger().error('Skipping signature decode for this list.')
        dof = dof + SignatureListSize

    return entries


#
#  "certdb" variable stores the signer's certificates for non PK/KEK/DB/DBX
# variables with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS|EFI_VARIABLE_NON_VOLATILE set.
#  "certdbv" variable stores the signer's certificates for non PK/KEK/DB/DBX
# variables with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS set
#
# GUID: gEfiCertDbGuid
#
# We need maintain atomicity.
#
# Format:
# +----------------------------+
# | UINT32                     | <-- CertDbListSize, including this UINT32
# +----------------------------+
# | AUTH_CERT_DB_DATA          | <-- First CERT
# +----------------------------+
# | ........                   |
# +----------------------------+
# | AUTH_CERT_DB_DATA          | <-- Last CERT
# +----------------------------+
#
# typedef struct {
#   EFI_GUID    VendorGuid;
#   UINT32      CertNodeSize;
#   UINT32      NameSize;
#   UINT32      CertDataSize;
#   /// CHAR16  VariableName[NameSize];
#   /// UINT8   CertData[CertDataSize];
# } AUTH_CERT_DB_DATA;
#
AUTH_CERT_DB_LIST_HEAD = "<I"
AUTH_CERT_DB_LIST_HEAD_size = struct.calcsize(AUTH_CERT_DB_LIST_HEAD)
AUTH_CERT_DB_DATA = "<16sIII"
AUTH_CERT_DB_DATA_size = struct.calcsize(AUTH_CERT_DB_DATA)


def parse_auth_var(db, decode_dir):
    entries = []
    dof = 0
    nsig = 0
    db_size = len(db)

    # Verify that list makes sense
    if db_size < AUTH_CERT_DB_LIST_HEAD_size:
        logger().log_warning("Cert list empty.")
        return entries
    expected_size = struct.unpack(AUTH_CERT_DB_LIST_HEAD, db[dof:dof + AUTH_CERT_DB_LIST_HEAD_size])[0]
    if db_size != expected_size:
        logger().error("Expected size of cert list did not match actual size.")
        return entries
    dof += AUTH_CERT_DB_LIST_HEAD_size

    # Loop through all the certs in the list.
    while dof + AUTH_CERT_DB_DATA_size < db_size:
        ven_guid0, cert_node_size, name_size, cert_data_size = struct.unpack(
            AUTH_CERT_DB_DATA, db[dof:dof + AUTH_CERT_DB_DATA_size])
        vendor_guid = EFI_GUID_STR(ven_guid0)
        name_size *= 2  # Name size is actually the number of CHAR16 in the name array
        tof = dof + AUTH_CERT_DB_DATA_size
        try:
            var_name = codecs.decode(db[tof:tof + name_size], 'utf-16')
        except UnicodeDecodeError:
            logger().log_warning("Unable to decode {}".format(db[tof:tof + name_size]))
            var_name = "chipsec.exceptions!"
        tof += name_size
        sig_data = db[tof:tof + cert_data_size]
        entries.append(sig_data)
        sig_file_name = '{}-{}-{:02X}.bin'.format(vendor_guid, codecs.encode(var_name), nsig)
        sig_file_name = os.path.join(decode_dir, sig_file_name)
        write_file(sig_file_name, sig_data)
        dof += cert_node_size
        nsig += 1

    return entries


ESAL_SIG_SIZE = 256


def parse_esal_var(db, decode_dir):
    entries = []
    dof = 0
    nsig = 0
    db_size = len(db)

    # Check to see how many signatures exist
    if db_size < ESAL_SIG_SIZE:
        logger().log('No signatures present.')
        return entries

    # Extract signatures
    while dof + ESAL_SIG_SIZE <= db_size:
        key_data = db[dof:dof + ESAL_SIG_SIZE]
        entries.append(key_data)
        key_file_name = os.path.join(decode_dir, 'AuthVarKeyDatabase-cert-{:02X}.bin'.format(nsig))
        write_file(key_file_name, key_data)
        dof += ESAL_SIG_SIZE
        nsig += 1

    return entries


SECURE_BOOT_SIG_VAR = 1
AUTH_SIG_VAR = 2
ESAL_SIG_VAR = 3


def parse_efivar_file(fname, var=None, var_type=SECURE_BOOT_SIG_VAR):
    logger().log('Processing certs in file: {}'.format(fname))
    if not var:
        var = read_file(fname)
    var_path = fname + '.dir'
    if not os.path.exists(var_path):
        os.makedirs(var_path)
    if var_type == SECURE_BOOT_SIG_VAR:
        parse_sb_db(var, var_path)
    elif var_type == AUTH_SIG_VAR:
        parse_auth_var(var, var_path)
    elif var_type == ESAL_SIG_VAR:
        parse_esal_var(var, var_path)
    else:
        logger().log_warning('Unsupported variable type requested: {}'.format(var_type))


# ################################################################################################3
# This Variable header is defined by UEFI
# ################################################################################################3


# Variable Store Status

# typedef enum {
#  EfiRaw,
#  EfiValid,
#  EfiInvalid,
#  EfiUnknown
# } VARIABLE_STORE_STATUS;
VARIABLE_STORE_STATUS_RAW = 0
VARIABLE_STORE_STATUS_VALID = 1
VARIABLE_STORE_STATUS_INVALID = 2
VARIABLE_STORE_STATUS_UNKNOWN = 3

# typedef struct {
#  UINT16    StartId;
#  UINT8     State;
#  UINT8     Reserved;
#  UINT32    Attributes;
#  UINT32    NameSize;
#  UINT32    DataSize;
#  EFI_GUID  VendorGuid;
# } VARIABLE_HEADER;

# typedef struct {
#  UINT32  Data1;
#  UINT16  Data2;
#  UINT16  Data3;
#  UINT8   Data4[8];
# } EFI_GUID;

UEFI_VARIABLE_HEADER_SIZE = 28


class UEFI_VARIABLE_HEADER(
    namedtuple(
        'UEFI_VARIABLE_HEADER',
        'StartId State Reserved Attributes NameSize DataSize VendorGuid0 VendorGuid1 VendorGuid2 VendorGuid3')):
    __slots__ = ()

    def __str__(self):
        return """
Header (UEFI)
-------------
StartId    : 0x{:04X}
State      : 0x{:02X}
Reserved   : 0x{:02X}
Attributes : 0x{:08X}
NameSize   : 0x{:08X}
DataSize   : 0x{:08X}
VendorGuid : {{0x{:08X}-0x{:04X}-0x{:04X}-0x{:08X}}}
""".format(
            self.StartId, self.State, self.Reserved, self.Attributes, self.NameSize,
            self.DataSize, self.VendorGuid0, self.VendorGuid1, self.VendorGuid2, self.VendorGuid3)


UEFI_VARIABLE_STORE_HEADER = "<16sIBBHI"
UEFI_VARIABLE_STORE_HEADER_SIZE = struct.calcsize(UEFI_VARIABLE_STORE_HEADER)
'''
EFI_VARIABLE_HEADER_AUTH = "<HBBI28sIIIHH8s"
EFI_VARIABLE_HEADER_AUTH_SIZE = struct.calcsize(EFI_VARIABLE_HEADER_AUTH)

EFI_VARIABLE_HEADER = "<HBBIIIIHH8s"
EFI_VARIABLE_HEADER_SIZE = struct.calcsize(EFI_VARIABLE_HEADER)
'''
VARIABLE_STORE_FORMATTED = 0x5a
VARIABLE_STORE_HEALTHY = 0xfe


def _getNVstore_EFI(nvram_buf, efi_type):
    ret = (-1, -1, None)
    FvOffset = 0
    FvLength = 0
    fv = NextFwVolume(nvram_buf, FvOffset + FvLength)
    while True:
        if (fv is None):
            break
        if (fv.Guid == VARIABLE_STORE_FV_GUID):
            nvram_start = fv.HeaderSize
            StoreGuid0, Size, Format, State, R0, R1 = \
                struct.unpack(
                    UEFI_VARIABLE_STORE_HEADER, fv.Image[nvram_start:nvram_start + UEFI_VARIABLE_STORE_HEADER_SIZE])
            if ((Format == VARIABLE_STORE_FORMATTED) and (State == VARIABLE_STORE_HEALTHY)):
                if (isCorrectVSStype(fv.Image[nvram_start:], efi_type)):
                    ret = (fv.Offset + nvram_start, fv.Size - nvram_start, None)
                break
        fv = NextFwVolume(nvram_buf, fv.Offset + fv.Size)
    return ret


def getNVstore_EFI(nvram_buf):
    return _getNVstore_EFI(nvram_buf, FWType.EFI_FW_TYPE_VSS)


def getNVstore_EFI_AUTH(nvram_buf):
    return _getNVstore_EFI(nvram_buf, FWType.EFI_FW_TYPE_VSS_AUTH)


def getEFIvariables_UEFI(nvram_buf):
    return _getEFIvariables_VSS(nvram_buf, FWType.EFI_FW_TYPE_VSS)


def getEFIvariables_UEFI_AUTH(nvram_buf):
    return _getEFIvariables_VSS(nvram_buf, FWType.EFI_FW_TYPE_VSS_AUTH)


##################################################################################################
#
# Platform/Vendor Specific EFI NVRAM Parsing Functions
#
# For each platform, EFI NVRAM parsing functionality includes:
# 1. Function to parse EFI variable within NVRAM binary (func_getefivariables)
#    May define/use platform specific EFI Variable Header
#    Function arguments:
#      In : binary buffer (as a string)
#      Out:
#        start           - offset in the buffer to the current EFI variable
#        next_var_offset - offset in the buffer to the next EFI variable
#        efi_var_buf     - full EFI variable buffer
#        efi_var_hdr     - EFI variable header object
#        efi_var_name    - EFI variable name
#        efi_var_data    - EFI variable data contents
#        efi_var_guid    - EFI variable GUID
#        efi_var_attr    - EFI variable attributes
# 2. [Optional] Function to find EFI NVRAM within arbitrary binary (func_getnvstore)
#    If this function is not defined, 'chipsec_util uefi' searches EFI variables from the beginning of the binary
#    Function arguments:
#      In : NVRAM binary buffer (as a string)
#      Out:
#        start        - offset of NVRAM     (-1 means NVRAM not found)
#        size         - size of NVRAM       (-1 means NVRAM is entire binary)
#        nvram_header - NVRAM header object
#
##################################################################################################

##################################################################################################
# NVAR format of NVRAM
#

class EFI_HDR_NVAR1(namedtuple('EFI_HDR_NVAR1', 'StartId TotalSize Reserved1 Reserved2 Reserved3 Attributes State')):
    __slots__ = ()

    def __str__(self):
        return """
Header (NVAR)
------------
StartId    : 0x{:04X}
TotalSize  : 0x{:04X}
Reserved1  : 0x{:02X}
Reserved2  : 0x{:02X}
Reserved3  : 0x{:02X}
Attributes : 0x{:02X}
State      : 0x{:02X}
""".format(self.StartId, self.TotalSize, self.Reserved1, self.Reserved2, self.Reserved3, self.Attributes, self.State)


NVAR_EFIvar_signature = b'NVAR'


def getNVstore_NVAR(nvram_buf):
    ret = (-1, -1, None)
    fv = NextFwVolume(nvram_buf)
    if (fv is None):
        return ret
    if (fv.Offset >= len(nvram_buf)):
        return ret
    if (fv.Offset + fv.Size) > len(nvram_buf):
        fv.Size = len(nvram_buf) - fv.Offset
    while fv is not None:
        polarity = bit_set(fv.Attributes, EFI_FVB2_ERASE_POLARITY)
        fwbin = NextFwFile(fv.Image, fv.Size, fv.HeaderSize, polarity)
        while fwbin is not None:
            if (fwbin.Type == EFI_FV_FILETYPE_RAW) and (fwbin.Guid == NVAR_NVRAM_FS_FILE):
                ret = ((fv.Offset + fwbin.Offset + fwbin.HeaderSize), fwbin.Size - fwbin.HeaderSize, None)
                if (not fwbin.UD):
                    return ret
            fwbin = NextFwFile(fv.Image, fv.Size, fwbin.Size + fwbin.Offset, polarity)
        fv = NextFwVolume(nvram_buf, fv.Offset + fv.Size)
    return ret


def _ord(c):
    return ord(c) if isinstance(c, str) else c


def getEFIvariables_NVAR(nvram_buf):
    _ = nvram_buf.find(NVAR_EFIvar_signature)
    nvram_size = len(nvram_buf)
    EFI_HDR_NVAR = "<4sH3sB"
    nvar_size = struct.calcsize(EFI_HDR_NVAR)
    variables = {}
    nof = 0  # start
    EMPTY = 0xffffffff
    while (nof + nvar_size) < nvram_size:
        start_id, size, _next, attributes = struct.unpack(EFI_HDR_NVAR, nvram_buf[nof:nof + nvar_size])
        _next = get_3b_size(_next)
        valid = (bit_set(attributes, NVRAM_ATTR_VLD) and (not bit_set(attributes, NVRAM_ATTR_DATA)))
        if not valid:
            nof = nof + size
            continue
        isvar = (start_id == NVAR_EFIvar_signature)
        if (not isvar) or (size == (EMPTY & 0xffff)):
            break
        var_name_off = 1
        if bit_set(attributes, NVRAM_ATTR_GUID):
            guid = UUID(bytes_le=nvram_buf[nof + nvar_size: nof + nvar_size + EFI_GUID_SIZE])
            guid = str(guid).upper()
            var_name_off = EFI_GUID_SIZE
        else:
            guid_idx = _ord(nvram_buf[nof + nvar_size])
            guid_off = (nvram_size - EFI_GUID_SIZE) - guid_idx * EFI_GUID_SIZE
            guid = UUID(bytes_le=nvram_buf[guid_off: guid_off + EFI_GUID_SIZE])
            guid = str(guid).upper()
        name_size = 0
        name_offset = nof + nvar_size + var_name_off
        if not bit_set(attributes, NVRAM_ATTR_DATA):
            name, name_size = get_nvar_name(nvram_buf, name_offset, bit_set(attributes, NVRAM_ATTR_DESC_ASCII))
        esize = 0
        eattrs = 0
        if bit_set(attributes, NVRAM_ATTR_EXTHDR):
            esize, = struct.unpack("<H", nvram_buf[nof + size - 2:nof + size])
            eattrs = _ord(nvram_buf[nof + size - esize])
        attribs = EFI_VARIABLE_BOOTSERVICE_ACCESS
        attribs = attribs | EFI_VARIABLE_NON_VOLATILE
        if bit_set(attributes, NVRAM_ATTR_RT):
            attribs = attribs | EFI_VARIABLE_RUNTIME_ACCESS
        if bit_set(attributes, NVRAM_ATTR_HER):
            attribs = attribs | EFI_VARIABLE_HARDWARE_ERROR_RECORD
        if bit_set(attributes, NVRAM_ATTR_AUTHWR):
            if bit_set(eattrs, EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS):
                attribs = attribs | EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS
            if bit_set(eattrs, EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS):
                attribs = attribs | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
        # Get variable data
        lof = nof
        lnext = _next
        lattributes = attributes
        lsize = size
        lesize = esize
        while lnext != (0xFFFFFF & EMPTY):
            lof = lof + lnext
            lstart_id, lsize, lnext, lattributes = struct.unpack(EFI_HDR_NVAR, nvram_buf[lof:lof + nvar_size])
            lnext = get_3b_size(lnext)
        dataof = lof + nvar_size
        if not bit_set(lattributes, NVRAM_ATTR_DATA):
            lnameof = 1
            if bit_set(lattributes, NVRAM_ATTR_GUID):
                lnameof = EFI_GUID_SIZE
            name_offset = lof + nvar_size + lnameof
            name, name_size = get_nvar_name(nvram_buf, name_offset, bit_set(attributes, NVRAM_ATTR_DESC_ASCII))
            dataof = name_offset + name_size
        if bit_set(lattributes, NVRAM_ATTR_EXTHDR):
            lesize, = struct.unpack("<H", nvram_buf[lof + lsize - 2:lof + lsize])
        data = nvram_buf[dataof:lof + lsize - lesize]
        if name not in variables:
            variables[name] = []
        #                       off, buf,  hdr,  data, guid, attrs
        variables[name].append((nof, None, None, data, guid, attribs))
        nof = nof + size
    return variables


NVAR_HDR_FMT = '=IHBBBBB'
NVAR_HDR_SIZE = struct.calcsize(NVAR_HDR_FMT)


#
# Linear/simple NVAR format parsing
#
def getNVstore_NVAR_simple(nvram_buf):
    return (nvram_buf.find(NVAR_EFIvar_signature), -1, None)


def getEFIvariables_NVAR_simple(nvram_buf):
    nvsize = len(nvram_buf)
    hdr_fmt = NVAR_HDR_FMT
    hdr_size = struct.calcsize(hdr_fmt)
    variables = {}
    start = nvram_buf.find(NVAR_EFIvar_signature)
    if -1 == start:
        return variables

    while (start + hdr_size) < nvsize:
        efi_var_hdr = EFI_HDR_NVAR1(*struct.unpack_from(hdr_fmt, nvram_buf[start:]))
        name_size = 0
        efi_var_name = "NA"
        if not IS_VARIABLE_ATTRIBUTE(efi_var_hdr.Attributes, EFI_VARIABLE_HARDWARE_ERROR_RECORD):
            name_size = nvram_buf[start + hdr_size:].find('\0')
            efi_var_name = "".join(nvram_buf[start + hdr_size: start + hdr_size + name_size])

        next_var_offset = start + efi_var_hdr.TotalSize
        _ = efi_var_hdr.TotalSize - name_size - hdr_size
        efi_var_buf = nvram_buf[start: next_var_offset]
        efi_var_data = nvram_buf[start + hdr_size + name_size: next_var_offset]

        if efi_var_name not in variables:
            variables[efi_var_name] = []
        #                               off,   buf,         hdr,         data,         guid, attrs
        variables[efi_var_name].append((start, efi_var_buf, efi_var_hdr, efi_var_data, '', efi_var_hdr.Attributes))

        if start >= next_var_offset:
            break
        start = next_var_offset

    return variables


#######################################################################
#
# VSS NVRAM (signature = '$VSS')
#
#

# define VARIABLE_STORE_SIGNATURE  EFI_SIGNATURE_32 ('$', 'V', 'S', 'S')
VARIABLE_STORE_SIGNATURE_VSS = b'$VSS'
VARIABLE_STORE_HEADER_FMT_VSS = '=IIBBHI'  # Signature is '$VSS'


class VARIABLE_STORE_HEADER_VSS(namedtuple('VARIABLE_STORE_HEADER_VSS', 'Signature Size Format State Reserved Reserved1')):
    __slots__ = ()

    def __str__(self):
        return """
EFI Variable Store
-----------------------------
Signature : {} (0x{:08X})
Size      : 0x{:08X} bytes
Format    : 0x{:02X}
State     : 0x{:02X}
Reserved  : 0x{:04X}
Reserved1 : 0x{:08X}
""".format(
            struct.pack('=I', self.Signature), self.Signature, self.Size, self.Format,
            self.State, self.Reserved, self.Reserved1)


VARIABLE_STORE_SIGNATURE_VSS2 = UUID('DDCF3617-3275-4164-98B6-FE85707FFE7D').bytes_le
VARIABLE_STORE_SIGNATURE_VSS2_AUTH = UUID('AAF32C78-947B-439A-A180-2E144EC37792').bytes_le

VARIABLE_STORE_HEADER_FMT_VSS2 = '=16sIBBHI'


class VARIABLE_STORE_HEADER_VSS2(
    namedtuple(
        'VARIABLE_STORE_HEADER_VSS2', 'Signature Size Format State Reserved Reserved1')):
    __slots__ = ()

    def __str__(self):
        return """
EFI Variable Store
-----------------------------
Signature : %s
Size      : 0x%08X bytes
Format    : 0x%02X
State     : 0x%02X
Reserved  : 0x%04X
Reserved1 : 0x%08X
""" % (UUID(bytes_le=self.Signature), self.Size, self.Format, self.State, self.Reserved, self.Reserved1)


VARIABLE_STORE_SIGNATURE_VSS2 = UUID('DDCF3617-3275-4164-98B6-FE85707FFE7D').bytes_le
VARIABLE_STORE_SIGNATURE_VSS2_AUTH = UUID('AAF32C78-947B-439A-A180-2E144EC37792').bytes_le

HDR_FMT_VSS = '<HBBIII16s'
# HDR_SIZE_VSS                  = struct.calcsize(HDR_FMT_VSS)
# NAME_OFFSET_IN_VAR_VSS        = HDR_SIZE_VSS


class EFI_HDR_VSS(namedtuple('EFI_HDR_VSS', 'StartId State Reserved Attributes NameSize DataSize guid')):
    __slots__ = ()

    def __str__(self):
        return """
Header (VSS)
------------
VendorGuid : {{{}}}
StartId    : 0x{:04X}
State      : 0x{:02X}
Reserved   : 0x{:02X}
Attributes : 0x{:08X}
NameSize   : 0x{:08X}
DataSize   : 0x{:08X}
""".format(
            EFI_GUID_STR(self.guid), self.StartId, self.State, self.Reserved,
            self.Attributes, self.NameSize, self.DataSize)


HDR_FMT_VSS_AUTH = '<HBBIQQQIII16s'


class EFI_HDR_VSS_AUTH(
    namedtuple(
        'EFI_HDR_VSS_AUTH',
        'StartId State Reserved Attributes MonotonicCount TimeStamp1 TimeStamp2 PubKeyIndex NameSize DataSize guid')):
    __slots__ = ()

    # if you don't re-define __str__ method, initialize is to None
    # __str__ = None
    def __str__(self):
        return """
Header (VSS_AUTH)
----------------
VendorGuid     : {{{}}}
StartId        : 0x{:04X}
State          : 0x{:02X}
Reserved       : 0x{:02X}
Attributes     : 0x{:08X}
MonotonicCount : 0x{:016X}
TimeStamp1     : 0x{:016X}
TimeStamp2     : 0x{:016X}
PubKeyIndex    : 0x{:08X}
NameSize       : 0x{:08X}
DataSize       : 0x{:08X}
""".format(
            EFI_GUID_STR(self.guid), self.StartId, self.State, self.Reserved,
            self.Attributes, self.MonotonicCount, self.TimeStamp1, self.TimeStamp2,
            self.PubKeyIndex, self.NameSize, self.DataSize)


HDR_FMT_VSS_APPLE = '<HBBIII16sI'


class EFI_HDR_VSS_APPLE(
    namedtuple(
        'EFI_HDR_VSS_APPLE', 'StartId State Reserved Attributes NameSize DataSize guid unknown')):
    __slots__ = ()

    def __str__(self):
        return """
Header (VSS_APPLE)
------------
VendorGuid : {{{}}}
StartId    : 0x{:04X}
State      : 0x{:02X}
Reserved   : 0x{:02X}
Attributes : 0x{:08X}
NameSize   : 0x{:08X}
DataSize   : 0x{:08X}
Unknown    : 0x{:08X}
""".format(
            EFI_GUID_STR(self.guid), self.StartId, self.State, self.Reserved,
            self.Attributes, self.NameSize, self.DataSize, self.unknown)


def _getNVstore_VSS(nvram_buf, vss_type):
    if vss_type == FWType.EFI_FW_TYPE_VSS2:
        sign = VARIABLE_STORE_SIGNATURE_VSS2
    elif vss_type == FWType.EFI_FW_TYPE_VSS2_AUTH:
        sign = VARIABLE_STORE_SIGNATURE_VSS2_AUTH
    else:
        sign = VARIABLE_STORE_SIGNATURE_VSS

    nvram_start = nvram_buf.find(sign)
    if -1 == nvram_start:
        return (-1, 0, None)
    buf = nvram_buf[nvram_start:]
    if (not isCorrectVSStype(buf, vss_type)):
        return (-1, 0, None)
    if vss_type in (FWType.EFI_FW_TYPE_VSS2, FWType.EFI_FW_TYPE_VSS2_AUTH):
        nvram_hdr = VARIABLE_STORE_HEADER_VSS2(*struct.unpack_from(VARIABLE_STORE_HEADER_FMT_VSS2, buf))
    else:
        nvram_hdr = VARIABLE_STORE_HEADER_VSS(*struct.unpack_from(VARIABLE_STORE_HEADER_FMT_VSS, buf))
    return (nvram_start, nvram_hdr.Size, nvram_hdr)


def getNVstore_VSS(nvram_buf):
    return _getNVstore_VSS(nvram_buf, FWType.EFI_FW_TYPE_VSS)


def getNVstore_VSS_AUTH(nvram_buf):
    return _getNVstore_VSS(nvram_buf, FWType.EFI_FW_TYPE_VSS_AUTH)


def getNVstore_VSS2(nvram_buf):
    return _getNVstore_VSS(nvram_buf, FWType.EFI_FW_TYPE_VSS2)


def getNVstore_VSS2_AUTH(nvram_buf):
    return _getNVstore_VSS(nvram_buf, FWType.EFI_FW_TYPE_VSS2_AUTH)


def getNVstore_VSS_APPLE(nvram_buf):
    return _getNVstore_VSS(nvram_buf, FWType.EFI_FW_TYPE_VSS_APPLE)


VSS_TYPES = (FWType.EFI_FW_TYPE_VSS,
             FWType.EFI_FW_TYPE_VSS_AUTH,
             FWType.EFI_FW_TYPE_VSS2,
             FWType.EFI_FW_TYPE_VSS2_AUTH,
             FWType.EFI_FW_TYPE_VSS_APPLE)
MAX_VSS_VAR_ALIGNMENT = 8


def isCorrectVSStype(nvram_buf, vss_type):
    if (vss_type not in VSS_TYPES):
        return False

    buf_size = len(nvram_buf)
    start = nvram_buf.find(VARIABLE_SIGNATURE_VSS)
    if (-1 == start):
        return False
    # skip the minimun bytes required for the header
    next_var = nvram_buf.find(VARIABLE_SIGNATURE_VSS, start + struct.calcsize(HDR_FMT_VSS))
    if (-1 == next_var):
        next_var = buf_size

    buf_size -= start

    if (vss_type in (FWType.EFI_FW_TYPE_VSS, FWType.EFI_FW_TYPE_VSS2)):
        hdr_fmt = HDR_FMT_VSS
        efi_var_hdr = EFI_HDR_VSS(*struct.unpack_from(hdr_fmt, nvram_buf[start:]))
    elif (vss_type in (FWType.EFI_FW_TYPE_VSS_AUTH, FWType.EFI_FW_TYPE_VSS2_AUTH)):
        hdr_fmt = HDR_FMT_VSS_AUTH
        efi_var_hdr = EFI_HDR_VSS_AUTH(*struct.unpack_from(hdr_fmt, nvram_buf[start:]))
    elif (vss_type == FWType.EFI_FW_TYPE_VSS_APPLE):
        hdr_fmt = HDR_FMT_VSS_APPLE
        efi_var_hdr = EFI_HDR_VSS_APPLE(*struct.unpack_from(hdr_fmt, nvram_buf[start:]))

    hdr_size = struct.calcsize(hdr_fmt)
    # check NameSize and DataSize
    name_offset = start + hdr_size
    if ((name_offset < next_var) and ((name_offset + efi_var_hdr.NameSize) < next_var)):
        valid_name = False
        if (efi_var_hdr.NameSize > 0):
            name = nvram_buf[name_offset: name_offset + efi_var_hdr.NameSize]
            try:
                name = name.decode("utf-16-le").split('\x00')[0]
                valid_name = is_printable(name)
            except Exception:
                pass
        if (valid_name):
            end_var_offset = name_offset + efi_var_hdr.NameSize + efi_var_hdr.DataSize
            off_diff = next_var - end_var_offset
            if (off_diff == 0):
                return True
            elif (off_diff > 0):
                if (next_var == len(nvram_buf)) or (off_diff <= (MAX_VSS_VAR_ALIGNMENT - 1)):
                    return True
            else:
                if (next_var < len(nvram_buf)):
                    new_nex_var = nvram_buf.find(
                        VARIABLE_SIGNATURE_VSS,
                        next_var, next_var + len(VARIABLE_SIGNATURE_VSS) + (MAX_VSS_VAR_ALIGNMENT - 1))
                    if (new_nex_var != -1):
                        return True
    return False


def _getEFIvariables_VSS(nvram_buf, _fwtype):
    variables = {}
    nvsize = len(nvram_buf)
    if _fwtype in (FWType.EFI_FW_TYPE_VSS, FWType.EFI_FW_TYPE_VSS2):
        hdr_fmt = HDR_FMT_VSS
    elif _fwtype in (FWType.EFI_FW_TYPE_VSS_AUTH, FWType.EFI_FW_TYPE_VSS2_AUTH):
        hdr_fmt = HDR_FMT_VSS_AUTH
    elif (FWType.EFI_FW_TYPE_VSS_APPLE == _fwtype):
        hdr_fmt = HDR_FMT_VSS_APPLE
    else:
        return variables
    hdr_size = struct.calcsize(hdr_fmt)
    start = nvram_buf.find(VARIABLE_SIGNATURE_VSS)
    if -1 == start:
        return variables

    while (start + hdr_size) < nvsize:
        if _fwtype in (FWType.EFI_FW_TYPE_VSS, FWType.EFI_FW_TYPE_VSS2):
            efi_var_hdr = EFI_HDR_VSS(*struct.unpack_from(hdr_fmt, nvram_buf[start:]))
        elif _fwtype in (FWType.EFI_FW_TYPE_VSS_AUTH, FWType.EFI_FW_TYPE_VSS2_AUTH):
            efi_var_hdr = EFI_HDR_VSS_AUTH(*struct.unpack_from(hdr_fmt, nvram_buf[start:]))
        elif (FWType.EFI_FW_TYPE_VSS_APPLE == _fwtype):
            efi_var_hdr = EFI_HDR_VSS_APPLE(*struct.unpack_from(hdr_fmt, nvram_buf[start:]))

        if (efi_var_hdr.StartId != VARIABLE_DATA):
            break

        if ((efi_var_hdr.State == 0xff) and (efi_var_hdr.DataSize == 0xffffffff) and (efi_var_hdr.NameSize == 0xffffffff) and (efi_var_hdr.Attributes == 0xffffffff)):
            name_size = 0
            data_size = 0
            # just skip variable with empty name and data for now
            next_var_offset = nvram_buf.find(
                VARIABLE_SIGNATURE_VSS,
                start + hdr_size, start + hdr_size + len(VARIABLE_SIGNATURE_VSS) + (MAX_VSS_VAR_ALIGNMENT - 1))
            if (next_var_offset == -1) or (next_var_offset > nvsize):
                break
        else:
            name_size = efi_var_hdr.NameSize
            data_size = efi_var_hdr.DataSize
            efi_var_name = "<not defined>"

            end_var_offset = start + hdr_size + name_size + data_size
            efi_var_buf = nvram_buf[start: end_var_offset]

            name_offset = hdr_size
            Name = efi_var_buf[name_offset: name_offset + name_size]
            if Name:
                efi_var_name = Name.decode("utf-16-le").split('\x00')[0]

            efi_var_data = efi_var_buf[name_offset + name_size: name_offset + name_size + data_size]
            guid = EFI_GUID_STR(efi_var_hdr.guid)
            if efi_var_name not in variables:
                variables[efi_var_name] = []
            #                                off,   buf,         hdr,         data,         guid, attrs
            variables[efi_var_name].append((start, efi_var_buf, efi_var_hdr, efi_var_data, guid, efi_var_hdr.Attributes))

            # deal with different alignments (1-8)
            next_var_offset = nvram_buf.find(
                VARIABLE_SIGNATURE_VSS,
                end_var_offset, end_var_offset + len(VARIABLE_SIGNATURE_VSS) + (MAX_VSS_VAR_ALIGNMENT - 1))
            if (next_var_offset == -1) or (next_var_offset > nvsize):
                break

        if start >= next_var_offset:
            break
        start = next_var_offset

    return variables


def getEFIvariables_VSS(nvram_buf):
    return _getEFIvariables_VSS(nvram_buf, FWType.EFI_FW_TYPE_VSS)


def getEFIvariables_VSS_AUTH(nvram_buf):
    return _getEFIvariables_VSS(nvram_buf, FWType.EFI_FW_TYPE_VSS_AUTH)


def getEFIvariables_VSS2(nvram_buf):
    return _getEFIvariables_VSS(nvram_buf, FWType.EFI_FW_TYPE_VSS2)


def getEFIvariables_VSS2_AUTH(nvram_buf):
    return _getEFIvariables_VSS(nvram_buf, FWType.EFI_FW_TYPE_VSS2_AUTH)


def getEFIvariables_VSS_APPLE(nvram_buf):
    return _getEFIvariables_VSS(nvram_buf, FWType.EFI_FW_TYPE_VSS_APPLE)


#######################################################################
#
# EVSA NVRAM (signature = 'EVSA')
#
#
VARIABLE_STORE_SIGNATURE_EVSA = b'EVSA'

TLV_HEADER = "<BBH"
tlv_h_size = struct.calcsize(TLV_HEADER)


def getNVstore_EVSA(nvram_buf):
    ret = (-1, -1, None)
    fv = NextFwVolume(nvram_buf)
    while fv is not None:
        if (fv.Guid == VARIABLE_STORE_FV_GUID):
            nvram_start = fv.Image.find(VARIABLE_STORE_SIGNATURE_EVSA)
            if (nvram_start != -1) and (nvram_start >= tlv_h_size):
                nvram_start = nvram_start - tlv_h_size
                ret = (fv.Offset + nvram_start, fv.Size - nvram_start, None)
                break
        if (fv.Guid == ADDITIONAL_NV_STORE_GUID):
            nvram_start = fv.Image.find(VARIABLE_STORE_SIGNATURE_EVSA)
            if (nvram_start != -1) and (nvram_start >= tlv_h_size):
                nvram_start = nvram_start - tlv_h_size
                ret = (fv.Offset + nvram_start, fv.Size - nvram_start, None)
        fv = NextFwVolume(nvram_buf, fv.Offset + fv.Size)
    return ret


def EFIvar_EVSA(nvram_buf):
    image_size = len(nvram_buf)
    EVSA_RECORD = "<IIII"
    GUID_RECORD = "<H16s"
    fof = 0
    variables = {}
    while fof < image_size:
        fof = nvram_buf.find(VARIABLE_STORE_SIGNATURE_EVSA, fof)
        if fof == -1:
            break
        if fof < tlv_h_size:
            fof = fof + 4
            continue
        start = fof - tlv_h_size
        Tag0, Tag1, Size = struct.unpack(TLV_HEADER, nvram_buf[start: start + tlv_h_size])
        if Tag0 != 0xEC:  # Wrong EVSA block
            fof = fof + 4
            continue
        value = nvram_buf[start + tlv_h_size:start + Size]
        Signature, Unkwn0, Length, Unkwn1 = struct.unpack(EVSA_RECORD, value)
        if start + Length > image_size:  # Wrong EVSA record
            fof = fof + 4
            continue
        # NV storage EVSA found
        bof = 0
        guid_map = {}
        var_list = []
        value_list = {}
        while (bof + tlv_h_size) < Length:
            Tag0, Tag1, Size = struct.unpack(TLV_HEADER, nvram_buf[start + bof: start + bof + tlv_h_size])
            if (Size < tlv_h_size):
                break
            value = nvram_buf[start + bof + tlv_h_size:start + bof + Size]
            bof = bof + Size
            if (Tag0 == 0xED) or (Tag0 == 0xE1):  # guid
                GuidId, guid0 = struct.unpack(GUID_RECORD, value)
                g = EFI_GUID_STR(guid0)
                guid_map[GuidId] = g
            elif (Tag0 == 0xEE) or (Tag0 == 0xE2):  # var name
                VAR_NAME_RECORD = "<H{:d}s".format(Size - tlv_h_size - 2)
                VarId, Name = struct.unpack(VAR_NAME_RECORD, value)
                Name = Name.decode("utf-16-le")[:-1]
                var_list.append((Name, VarId, Tag0, Tag1))
            elif (Tag0 == 0xEF) or (Tag0 == 0xE3) or (Tag0 == 0x83):  # values
                VAR_VALUE_RECORD = "<HHI{:d}s".format(Size - tlv_h_size - 8)
                GuidId, VarId, Attributes, Data = struct.unpack(VAR_VALUE_RECORD, value)
                value_list[VarId] = (GuidId, Attributes, Data, Tag0, Tag1)
            elif not ((Tag0 == 0xff) and (Tag1 == 0xff) and (Size == 0xffff)):
                pass
        # var_count = len(var_list)
        var_list.sort()
        # var1 = {}
        for i in var_list:
            name = i[0]
            VarId = i[1]
            # NameTag0 = i[2]
            # NameTag1 = i[3]
            if VarId in value_list:
                var_value = value_list[VarId]
            else:
                #  Value not found for VarId
                continue
            GuidId = var_value[0]
            guid = "NONE"
            if GuidId not in guid_map:
                # Guid not found for GuidId
                pass
            else:
                guid = guid_map[GuidId]
            if name not in variables:
                variables[name] = []
            #                       off,   buf,  hdr,  data,         guid, attrs
            variables[name].append((start, None, None, var_value[2], guid, var_value[1]))
        fof = fof + Length
    return variables


# ################################################################################################3
# EFI Variable Header Dictionary
# ################################################################################################3

#
# Add your EFI variable details to the dictionary
#
# Fields:
# name          func_getefivariables            func_getnvstore
#
EFI_VAR_DICT = {
    # UEFI
    FWType.EFI_FW_TYPE_UEFI: {'name': 'UEFI', 'func_getefivariables': getEFIvariables_UEFI,
                              'func_getnvstore': getNVstore_EFI},
    FWType.EFI_FW_TYPE_UEFI_AUTH: {'name': 'UEFI_AUTH', 'func_getefivariables': getEFIvariables_UEFI_AUTH,
                                   'func_getnvstore': getNVstore_EFI_AUTH},
    # Windows 8 NtEnumerateSystemEnvironmentValuesEx (infcls = 2)
    # FWType.EFI_FW_TYPE_WIN     : {'name' : 'WIN',
    #                               'func_getefivariables': getEFIvariables_NtEnumerateSystemEnvironmentValuesEx2,
    #                               'func_getnvstore' : None},
    # NVAR format
    FWType.EFI_FW_TYPE_NVAR: {'name': 'NVAR', 'func_getefivariables': getEFIvariables_NVAR,
                              'func_getnvstore': getNVstore_NVAR},
    # $VSS NVRAM format
    FWType.EFI_FW_TYPE_VSS: {'name': 'VSS', 'func_getefivariables': getEFIvariables_VSS,
                             'func_getnvstore': getNVstore_VSS},
    # $VSS Authenticated NVRAM format
    FWType.EFI_FW_TYPE_VSS_AUTH: {'name': 'VSS_AUTH', 'func_getefivariables': getEFIvariables_VSS_AUTH,
                                  'func_getnvstore': getNVstore_VSS_AUTH},
    # VSS2 NVRAM format
    FWType.EFI_FW_TYPE_VSS2: {'name': 'VSS2', 'func_getefivariables': getEFIvariables_VSS2,
                              'func_getnvstore': getNVstore_VSS2},
    # VSS2 Authenticated NVRAM format
    FWType.EFI_FW_TYPE_VSS2_AUTH: {'name': 'VSS2_AUTH', 'func_getefivariables': getEFIvariables_VSS2_AUTH,
                                   'func_getnvstore': getNVstore_VSS2_AUTH},
    # Apple $VSS formart
    FWType.EFI_FW_TYPE_VSS_APPLE: {'name': 'VSS_APPLE', 'func_getefivariables': getEFIvariables_VSS_APPLE,
                                   'func_getnvstore': getNVstore_VSS_APPLE},
    # EVSA
    FWType.EFI_FW_TYPE_EVSA: {'name': 'EVSA', 'func_getefivariables': EFIvar_EVSA, 'func_getnvstore': getNVstore_EVSA},
}
