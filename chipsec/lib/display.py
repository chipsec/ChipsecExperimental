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

import platform
from chipsec.logger import logger
from chipsec.defines import is_python_64_bits, get_message, get_version
from chipsec.chipset import cs


def print_banner(args=None):
    """
    Prints chipsec banner
    """
    logger().log('')
    logger().log("################################################################\n"
                 "##                                                            ##\n"
                 "##  CHIPSEC: Platform Hardware Security Assessment Framework  ##\n"
                 "##                                                            ##\n"
                 "################################################################")
    logger().log("[CHIPSEC] Version : {}".format(get_version()))
    logger().log("[CHIPSEC] Arguments: {}".format(" ".join(args)))
    logger().log("[CHIPSEC] OS      : {} {} {} {}".format(platform.system(), platform.release(), platform.version(),
                 platform.machine()))
    logger().log("[CHIPSEC] Python  : {} ({})".format(platform.python_version(), "64-bit" if is_python_64_bits()
                 else "32-bit"))
    logger().log(get_message())

    if not is_python_64_bits() and platform.machine().endswith("64"):
        logger().log_warning("Python architecture (32-bit) is different from OS architecture (64-bit)")


def chipsec_properties():
    chipset = cs()
    logger().log("[CHIPSEC] BIOS Version : {}".format(chipset.helper.get_bios_version()))
    logger().log("[CHIPSEC] Helper       : {} ({})".format(*chipset.helper.get_info()))
    chipset.Cfg.print_platform_info()
    if not chipset.is_atom():
        chipset.Cfg.print_pch_info()
