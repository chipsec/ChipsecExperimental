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
#
# Authors:
#  Aaron Frinzell

"""
LT / TXT related functionality
"""

from chipsec.hal.hal_base import HALBase


class TXT(HALBase):
    def __init__(self, cs):
        super(TXT, self).__init__(cs)

    # Return a list of TXT register names
    def get_txt_registers(self):
        matches = self.cs.Cfg.get_REGISTERS_match('8086.LT_PUBLIC_SPACE')
        regs = list(set([i[:i.rfind('.')] for i in matches]))  # find only unique registers from the results
        return regs

    # List all defined TXT register names and offsets (no values)
    def list_txt_registers(self):
        regs = self.get_txt_registers()
        self.logger.log('  Offset | Title ')
        self.logger.log(' -------------------------------------------------------')
        for reg in regs:
            regDefs = self.cs.Cfg.get_register_def(reg)
            self.logger.log('   {:05X} : {}'.format(regDefs['offset'], reg))

    # Print Register text based on offset
    def print_public_txt_reg(self, reg):
        values = self.cs.read_register(reg)
        for regdata in values:
            self.cs.print_register(reg, regdata)

    # Print field value based on offset
    def print_txt_field(self, reg, field):
        regData = self.cs.read_register_field(reg, field)
        for data in regData:
            self.logger.log("'{}'.'{}' - 0x{:X}".format(reg, field, data.value))

    # Print all defined TXT registers
    def print_public_txt_space(self):
        regs = self.get_txt_registers()
        for reg in regs:
            self.print_public_txt_reg(reg)
