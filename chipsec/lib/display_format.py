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

import string
import binascii
from typing import Tuple, Dict, List
from chipsec.logger import logger


def aligned_column_spacing(table_data: List[Tuple[str, Dict[str, str]]]) -> Tuple[int, ...]:
    clean_data = clean_data_table(table_data)
    all_column_widths = get_column_widths(clean_data)
    required_widths = find_required_col_widths(all_column_widths)
    return required_widths


def clean_data_table(data_table: List[Tuple[str, Dict[str, str]]]) -> List[List[str]]:
    clean_table = [extract_column_values(row) for row in data_table]
    return clean_table


def extract_column_values(row_data: Tuple[str, Dict[str, str]]) -> List[str]:
    clean_row = [row_data[0]]
    additional_column_values = row_data[1].values()
    [clean_row.append(value) for value in additional_column_values]
    return clean_row


def get_column_widths(data: List[List[str]]) -> List[List[int]]:
    col_widths = [[len(col) for col in row] for row in data]
    return col_widths


def find_required_col_widths(col_data: List[List[int]], minimum_width=2) -> Tuple[int, ...]:
    columns_per_row = len(col_data[0])
    max_widths = ([(max(rows[i] for rows in col_data)) for i in range(columns_per_row)])
    for i in range(len(max_widths)):
        max_widths[i] = max_widths[i] if max_widths[i] > minimum_width else minimum_width
    return tuple(max_widths)

##################################################################################
# Hex dump functions
##################################################################################


def hex_to_text(value):
    '''Generate text string based on bytestrings'''
    text = binascii.unhexlify('{:x}'.format(value))[::-1]
    if isinstance(text, str):
        return text   # Python 2.x
    else:
        return text.decode('latin-1')   # Python 3.x


def bytes2string(buffer, length=16):
    '''Generate text string based on str with ASCII side panel'''
    output = []
    num_string = []
    ascii_string = []
    index = 1
    for c in buffer:
        num_string += ['{:02X} '.format(ord(c))]
        if not (c in string.printable) or (c in string.whitespace):
            ascii_string += ['{}'.format(' ')]
        else:
            ascii_string += [f'{c}']
        if (index % length) == 0:
            num_string += ['| ']
            num_string += ascii_string
            output.append(''.join(num_string))
            ascii_string = []
            num_string = []
        index += 1
    if 0 != (len(buffer) % length):
        num_string += [(length - len(buffer) % length) * 3 * ' ']
        num_string += ['| ']
        num_string += ascii_string
        output.append(''.join(num_string))
    return '\n'.join(output)


def dump_buffer(arr, length=8):
    """Dumps the buffer (str) with ASCII"""
    return bytes2string(arr, length)


def print_buffer(arr, length=16):
    """Prints the buffer (str) with ASCII"""
    prt_str = bytes2string(arr, length)
    logger().log(prt_str)


def dump_buffer_bytes(arr, length=8):
    """Dumps the buffer (bytes, bytearray) with ASCII"""
    output = []
    num_string = []
    ascii_string = []
    index = 1
    for c in arr:
        num_string += ['{:02X} '.format(c)]
        if not (chr(c) in string.printable) or (chr(c) in string.whitespace):
            ascii_string += ['{}'.format(' ')]
        else:
            ascii_string += [chr(c)]
        if (index % length) == 0:
            num_string += ['| ']
            num_string += ascii_string
            output.append(''.join(num_string))
            ascii_string = []
            num_string = []
        index += 1
    if 0 != (len(arr) % length):
        num_string += [(length - len(arr) % length) * 3 * ' ']
        num_string += ['| ']
        num_string += ascii_string
        output.append(''.join(num_string))
    return '\n'.join(output)


def print_buffer_bytes(arr, length=16):
    """Prints the buffer (bytes, bytearray) with ASCII"""
    prt_str = dump_buffer_bytes(arr, length)
    logger().log(prt_str)


def pretty_print_hex_buffer(arr, length=16):
    """Prints the buffer (bytes, bytearray) in a grid"""
    _str = ['    _']
    for n in range(length):
        _str += ['{:02X}__'.format(n)]
    for n in range(len(arr)):
        if (n % length) == 0:
            _str += ['\n{:02X} | '.format(n)]
        _str += ['{:02X}  '.format(arr[n])]
    logger().log(''.join(_str))


def dump_data(data, length=16):
    """Dumps the buffer with ASCII"""
    if isinstance(data, str):
        dump_buffer(data, length)
    else:
        dump_buffer_bytes(data, length)


def print_data(data, length=16):
    """Prints the buffer with ASCII"""
    if isinstance(data, str):
        print_buffer(data, length)
    else:
        print_buffer_bytes(data, length)
