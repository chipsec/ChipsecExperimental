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


"""
Command-line utility providing access to IOMMU engines

>>> chipsec_util iommu list
>>> chipsec_util iommu config [iommu_engine]
>>> chipsec_util iommu status [iommu_engine]
>>> chipsec_util iommu enable|disable <iommu_engine>
>>> chipsec_util iommu pt

Examples:

>>> chipsec_util iommu list
>>> chipsec_util iommu config VTD
>>> chipsec_util iommu status GFXVTD
>>> chipsec_util iommu enable VTD
>>> chipsec_util iommu pt
"""

from chipsec.command import BaseCommand, toLoad
from chipsec.hal.acpi import ACPI, ACPI_TABLE_SIG_DMAR
from chipsec.hal.iommu import IOMMU
from argparse import ArgumentParser
from chipsec.exceptions import IOMMUError, AcpiRuntimeError


# I/O Memory Management Unit (IOMMU), e.g. Intel VT-d
class IOMMUCommand(BaseCommand):

    def requires_driver(self):
        parser = ArgumentParser(prog='chipsec_util iommu', usage=__doc__)
        subparsers = parser.add_subparsers()

        parser_list = subparsers.add_parser('list')
        parser_list.set_defaults(func=self.iommu_list)

        parser_config = subparsers.add_parser('config')
        parser_config.add_argument('engine', type=str, default='', nargs='?', help='IOMMU Engine')
        parser_config.set_defaults(func=self.iommu_config)

        parser_status = subparsers.add_parser('status')
        parser_status.add_argument('engine', default=None, nargs='?', help='IOMMU Engine')
        parser_status.set_defaults(func=self.iommu_status)

        parser_enable = subparsers.add_parser('enable')
        parser_enable.add_argument('engine', type=str, help='IOMMU Engine')
        parser_enable.set_defaults(func=self.iommu_enable)

        parser_disable = subparsers.add_parser('disable')
        parser_disable.add_argument('engine', type=str, help='IOMMU Engine')
        parser_disable.set_defaults(func=self.iommu_disable)

        parser_pt = subparsers.add_parser('pt')
        parser_pt.add_argument('engine', type=str, default='', nargs='?', help='IOMMU Engine')
        parser_pt.set_defaults(func=self.iommu_pt)

        parser.parse_args(self.argv, namespace=self)

        return toLoad.All

    def iommu_list(self):
        self.logger.log("[CHIPSEC] Enumerating supported IOMMU engines..")
        self.logger.log(self._iommu.get_engines())

    def valid_engine(self):
        engines = self._iommu.get_engines()
        if self.engine:
            if self.engine not in engines:
                self.logger.error("IOMMU name {} not recognized. Run 'iommu list' command for supported IOMMU names".format(self.engine))
                return False
            else:
                self.engine = [self.engine]
        else:
            self.engine = engines
        return True

    def iommu_config(self):
        try:
            _acpi = ACPI(self.cs)
        except AcpiRuntimeError as msg:
            self.logger.log_error(msg)
            return

        if _acpi.is_ACPI_table_present(ACPI_TABLE_SIG_DMAR):
            self.logger.log("[CHIPSEC] Dumping contents of DMAR ACPI table..\n")
            _acpi.dump_ACPI_table(ACPI_TABLE_SIG_DMAR)
        else:
            self.logger.log("[CHIPSEC] Couldn't find DMAR ACPI table\n")

        if self.valid_engine():
            for e in self.engine:
                self._iommu.dump_IOMMU_configuration(e)

    def iommu_status(self):
        if self.valid_engine():
            for e in self.engine:
                self._iommu.dump_IOMMU_status(e)

    def iommu_enable(self):
        if self.valid_engine():
            self._iommu.set_IOMMU_Translation(self.engine, 1)

    def iommu_disable(self):
        if self.valid_engine():
            self._iommu.set_IOMMU_Translation(self.engine, 0)

    def iommu_pt(self):
        if self.valid_engine():
            for e in self.engine:
                self._iommu.dump_IOMMU_page_tables(e)

    def run(self):
        self._iommu = IOMMU(self.cs)
        self.func()


commands = {'iommu': IOMMUCommand}
