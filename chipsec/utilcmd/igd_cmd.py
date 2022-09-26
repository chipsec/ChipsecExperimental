# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
#
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
The igd command allows memory read/write operations using igd dma.

>>> chipsec_util igd enabled
>>> chipsec_util igd gmadr
>>> chipsec_util igd gttmadr

Examples:

>>> chipsec_util igd enabled
>>> chipsec_util igd gmadr
>>> chipsec_util igd gttmadr
"""


from chipsec.command import BaseCommand, toLoad
from argparse import ArgumentParser
from chipsec.hal.igd import IGD


# Port I/O
class IgdCommand(BaseCommand):

    def requires_driver(self):
        parser = ArgumentParser(prog='chipsec_util igd', usage=__doc__)
        subparsers = parser.add_subparsers()

        parser_read = subparsers.add_parser('enabled')
        parser_read.set_defaults(func=self.enabled)

        parser_write = subparsers.add_parser('gmadr')
        parser_write.set_defaults(func=self.gmadr)

        parser_write = subparsers.add_parser('gttmadr')
        parser_write.set_defaults(func=self.gttmadr)

        parser.parse_args(self.argv, namespace=self)

        return toLoad.All

    def enabled(self):
        self.logger.log('[CHIPSEC] IGD device is{} enabled'.format('' if self._igd.is_enabled() else ' not'))

    def gmadr(self):
        addr = self._igd.get_GMADR()
        if addr is not None:
            self.logger.log('Aperture (GMADR): 0x{:016X}'.format(addr))
        else:
            self.logger.log('Aperture (GMADR) is not available')

    def gttmadr(self):
        addr = self._igd.get_GTTMMADR()
        if addr is not None:
            self.logger.log('Graphics MMIO and GTT (GTTMMADR): 0x{:016X}'.format(addr))
        else:
            self.logger.log('Graphics MMIO and GTT (GTTMMADR) is not available')

    def run(self):
        self._igd = IGD(self.cs)
        self.func()


commands = {'igd': IgdCommand}
