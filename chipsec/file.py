# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation

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

import os
from chipsec.logger import logger


def get_main_dir():
    path = os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir))
    return path


def read_file(filename, size=0):
    try:
        f = open(filename, 'rb')
    except Exception:
        logger().error("Unable to open file '{:.256}' for read access".format(filename))
        return 0

    if size:
        _file = f.read(size)
    else:
        _file = f.read()
    f.close()

    logger().log_debug("[file] read {:d} bytes from '{:256}'".format(len(_file), filename))
    return _file


def write_file(filename, buffer, append=False):
    perm = 'a' if append else 'w'
    if isinstance(buffer, bytes) or isinstance(buffer, bytearray):
        perm += 'b'
    try:
        f = open(filename, perm)
    except Exception:
        logger().error("Unable to open file '{:.256}' for write access".format(filename))
        return 0
    f.write(buffer)
    f.close()

    logger().log_debug("[file] wrote {:d} bytes to '{:.256}'".format(len(buffer), filename))
    return True
