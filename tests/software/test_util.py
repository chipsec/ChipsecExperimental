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

import chipsec_util
from chipsec.defines import ExitCode


class TestChipsecUtil(unittest.TestCase):
    """Test the util entry point script."""

    def test_help(self):
        """Run chipsec_util --help"""
        u = chipsec_util.ChipsecUtil(["--help"])
        self.assertEqual(ExitCode.OK, u.main())

    def test_platform(self):
        """Invoke platform command within unittest framework:
        chipsec_util --helper mockhelper platform"""
        u = chipsec_util.ChipsecUtil(["--helper", "mockhelper", "platform"])
        self.assertEqual(ExitCode.OK, u.main())
