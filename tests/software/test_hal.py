# CHIPSEC: Platform Security Assessment Framework

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

import unittest

from chipsec.chipset import Chipset
from chipsec.helper.oshelper import OsHelper
from chipsec.hal.pci import Pci


class TestChipsecHal(unittest.TestCase):
    """Test for hal functions."""

    def test_hal_pci_read_dword(self):
        """Run chipsec_util --help"""
        helper = OsHelper()
        helper.start("mockhelper")
        _cs = Chipset(helper)
        _pci = Pci(_cs)
        pci_read = _pci.read_dword(0, 0, 0, 0)
        self.assertEqual(0x9A128086, pci_read)
