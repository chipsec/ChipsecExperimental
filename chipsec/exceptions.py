# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2021, Intel Corporation

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


# Chipset
class UnknownChipsetError(RuntimeError):
    pass


class DeviceNotFoundError(RuntimeError):
    pass


class CSReadError(RuntimeError):
    def __init__(self, msg):
        super(CSReadError, self).__init__(msg)


class RegisterTypeNotFoundError(RuntimeError):
    pass


class RegisterNotFoundError(RuntimeError):
    pass


# OS Helper
class OsHelperError (RuntimeError):
    def __init__(self, msg, errorcode):
        super(OsHelperError, self).__init__(msg)
        self.errorcode = errorcode


class UnimplementedAPIError (OsHelperError):
    def __init__(self, api_name):
        super(UnimplementedAPIError, self).__init__("'{}' is not implemented".format(api_name), 0)


class HWAccessViolationError (OsHelperError):
    pass


# Config
class CSConfigError(RuntimeError):
    def __init__(self, msg):
        super(CSConfigError, self).__init__(msg)


# HAL
class AcpiRuntimeError (RuntimeError):
    pass


class IOBARRuntimeError (RuntimeError):
    pass


class IOBARNotFoundError (RuntimeError):
    pass


class IOMMUError (RuntimeError):
    pass


# SPI
class SpiRuntimeError (RuntimeError):
    pass


class SpiAccessError (RuntimeError):
    pass


# TPM
class TpmRuntimeError (RuntimeError):
    pass
