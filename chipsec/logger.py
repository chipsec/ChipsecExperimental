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
#

"""
Logging functions
"""
import logging
import platform
import string
import binascii
import sys
import os
import atexit
from time import localtime, strftime
from typing import Tuple, Dict, List, Optional
from enum import Enum

LOG_PATH = os.path.join(os.getcwd(), "logs")
if not os.path.exists(LOG_PATH):
    os.mkdir(LOG_PATH)

LOGGER_NAME = 'CHIPSEC_LOGGER'
FILE_LOGGER_NAME = 'CHIPSEC_LOG_FILE'

os.system('color')

class level(Enum):
    DEBUG = 10
    HELPER = 11
    HAL = 12
    VERBOSE = 13
    INFO = 20
    GOOD = 21
    BAD = 22
    IMPORTANT = 23
    WARNING = 30
    ERROR = 40
    CRITICAL = 50
    EXCEPTION = 60

class console_colors:
    GREY = '\033[90m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m' 
    WHITE = '\033[97m'
    ENDC = '\033[0m'

class tags():
    DEFAULT = ''
    ERROR = 'ERROR: '
    WARNING = 'WARNING: '
    IMPORTANT = '[!] '
    GOOD = '[+] '
    BAD = '[-] '
    DEBUG = '[*] [DEBUG] '
    VERBOSE = '[*] [VERBOSE] '
    HAL = '[*] [HAL] '
    HELPER = '[*] [HELPER] '

class Logger:
    def __init__(self):
        self.mytime = localtime()
        self.logfile = None
        self.ALWAYS_FLUSH = False
        self.logstream = logging.StreamHandler(sys.stdout)
        self.chipsecLogger = logging.getLogger(LOGGER_NAME)
        self.chipsecLogger.setLevel(logging.DEBUG)
        self.chipsecLogger.addHandler(self.logstream)
        logging.addLevelName(level.VERBOSE.value, level.VERBOSE.name)
        logging.addLevelName(level.HAL.value, level.HAL.name)
        logging.addLevelName(level.HELPER.value, level.HELPER.name)
        self.toLogFile = False

    def addFileHandlerLogger(self):
        self.toLogFile = True
        self.chipsecFileLogger = logging.getLogger(FILE_LOGGER_NAME)
        self.chipsecFileLogger.setLevel(logging.DEBUG)
        logname = f"{strftime('%a%b%d%y-%H%M%S')}.log"
        logPath = os.path.join(LOG_PATH, logname)
        file_handler = logging.FileHandler(logPath)
        self.chipsecFileLogger.addHandler(file_handler)

    def log(self, text: str, level: level = level.INFO.value, tag: tags = tags.DEFAULT, color: console_colors = console_colors.WHITE) -> None:
        self.chipsecLogger.log(level, f'{color}{tag}{text}{console_colors.ENDC}')
        if self.toLogFile:
            self.chipsecFileLogger.log(level, text)

    def log_verbose(self, text: str) -> None:
        self.log(text, level.VERBOSE.value, tags.VERBOSE, console_colors.BLUE)

    def log_hal(self, text: str) -> None:
        self.log(text, level.HAL.value, tags.HAL, console_colors.BLUE)

    def log_helper(self, text: str) -> None:
        self.log(text, level.HELPER.value, tags.HELPER, console_colors.BLUE)

    def log_important(self, text):
        self.log(text, level.IMPORTANT.value, tags.IMPORTANT, console_colors.YELLOW)

    def log_bad(self, text):
        self.log(text, level.BAD.value, tags.BAD, console_colors.RED)

    def log_good(self, text):
        self.log(text, level.GOOD.value, tags.GOOD, console_colors.GREEN)

    def log_debug(self, text: str) -> None:
        self.chipsecLogger.debug(f'{console_colors.BLUE}{tags.DEBUG}{text}{console_colors.ENDC}')
        if self.toLogFile:
            self.chipsecFileLogger.debug(text)

    def log_error(self, text):
        self.chipsecLogger.error(f'{console_colors.RED}{tags.ERROR}{text}{console_colors.ENDC}')
        if self.toLogFile:
            self.chipsecFileLogger.error(text)

    def log_warning(self, text):
        self.chipsecLogger.warning(f'{console_colors.YELLOW}{tags.WARNING}{text}{console_colors.ENDC}')
        if self.toLogFile:
            self.chipsecFileLogger.warning(text)
    
    def log_exception(self, text):
        self.chipsecLogger.exception(f'{console_colors.MAGENTA}{tags.DEFAULT}{text}{console_colors.ENDC}')
        if self.toLogFile:
            self.chipsecFileLogger.exception(text)

    def setlevel(self) -> None:
        if self.DEBUG:
            self.chipsecLogger.setLevel(level.DEBUG.value)
        elif self.HAL:
            self.chipsecLogger.setLevel(level.HAL.value)
        elif self.VERBOSE:
            self.chipsecLogger.setLevel(level.VERBOSE.value)
        else:
            self.chipsecLogger.setLevel(level.INFO.value)

    def set_log_file(self, name=None):
        """Sets the log file for the output."""
        # Close current log file if it's opened
        self.disable()
        self.LOG_FILE_NAME = name
        # specifying name=None effectively disables logging to file

        if self.LOG_FILE_NAME:
            # Open new log file and keep it opened
            try:
                # creates FileHandler for log file
                self.logfile = logging.FileHandler(filename=self.LOG_FILE_NAME, mode='w')
                self.chipsecLogger.addHandler(self.logfile)  # adds filehandler to root logger
                self.LOG_TO_FILE = True
            except Exception:
                print(f'WARNING: Could not open log file: {self.LOG_FILE_NAME}')
            self.chipsecLogger.removeHandler(self.logstream)
        else:
            try:
                self.chipsecLogger.addHandler(self.logstream)
            except Exception:
                pass

    def close(self) -> None:
        """Closes the log file."""
        if self.logfile:
            try:
                self.chipsecLogger.removeHandler(self.logfile)
                self.chipsecLogger.removeHandler(self.logstream)
                self.logfile.close()
                self.logstream.flush()
            except Exception:
                print('WARNING: Could not close log file')
            finally:
                self.logfile = None

    def disable(self) -> None:
        """Disables the logging to file and closes the file if any."""
        self.LOG_TO_FILE = False
        self.LOG_FILE_NAME = None
        self.close()

    def flush(self) -> None:
        sys.stdout.flush()
        if self.LOG_TO_FILE and self.logfile is not None:
            # flush should work with new python logging
            try:
                self.chipsecLogger.removeHandler(self.logfile)
                self.logfile.flush()
                self.chipsecLogger.addHandler(self.logfile)
            except Exception:
                self.disable()

    def set_always_flush(self, val) -> None:
        self.ALWAYS_FLUSH = val

    # -------------------------------------------------------
    # These logger methods are deprecated and will be removed
    # -------------------------------------------------------

    def log_passed(self, text):
        """Logs a passed message."""
        self.log_good(f'PASSED: {text}')

    def log_failed(self, text):
        """Logs a failed message."""
        self.log_bad(f'FAILED: {text}')

    def log_not_applicable(self, text):
        """Logs a NOT APPLICABLE message."""
        self.log_important(f'NOT APPLICABLE: {text}')

    def log_information(self, text):
        """Logs a message with information message"""
        self.log(f'[#] INFORMATION: {text}')
    
    def log_heading(self, text):
        self.chipsecLogger.info(f'{console_colors.CYAN}{text}{console_colors.ENDC}')
        if self.toLogFile:
            self.chipsecFileLogger.info(text)

    # -------------------------------------------------------
    # End deprecated logger methods
    # -------------------------------------------------------

    def start_test(self, test_name: str) -> None:
        """Logs the start point of a Test"""
        text = '[x][ =======================================================================\n'
        text = f'{text}[x][ Module: {test_name}\n'
        text = f'{text}[x][ ======================================================================='
        self.log_heading(text)


    def _write_log(self, text, filename):
        """Write text to defined log file"""
        self.chipsecLogger.log(level.INFO.value, text)
        if self.ALWAYS_FLUSH:
            try:
                self.logfile.close()
                self.logfile = open(self.LOG_FILE_NAME, 'a+')
            except Exception:
                self.disable()

    def _save_to_log_file(self, text):
        if self.LOG_TO_FILE:
            self._write_log(text, self.LOG_FILE_NAME)

    VERBOSE: bool = False
    UTIL_TRACE: bool = False
    HAL: bool = False
    DEBUG: bool = False

    LOG_TO_STATUS_FILE: bool = False
    LOG_STATUS_FILE_NAME: str = ''
    LOG_TO_FILE: bool = False
    LOG_FILE_NAME: str = ''


_logger = Logger()


def logger() -> Logger:
    """Returns a Logger instance."""
    return _logger


def aligned_column_spacing(table_data: List[Tuple[str, Dict[str, str]]]) -> Tuple[int, ...]:
    clean_data = clean_data_table(table_data)
    all_column_widths = get_column_widths(clean_data)
    required_widths = find_required_col_widths(all_column_widths)
    return tuple(required_widths)


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


def find_required_col_widths(col_data: List[List[int]], minimum_width=2) -> List[int]:
    columns_per_row = len(col_data[0])
    max_widths = ([(max(rows[i] for rows in col_data)) for i in range(columns_per_row)])
    for i in range(len(max_widths)):
        max_widths[i] = max_widths[i] if max_widths[i] > minimum_width else minimum_width
    return max_widths

##################################################################################
# Hex dump functions
##################################################################################


def hex_to_text(value):
    '''Generate text string based on bytestrings'''
    text = binascii.unhexlify(f'{value:x}')[::-1]
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
        num_string += [f'{ord(c):02X} ']
        if not (c in string.printable) or (c in string.whitespace):
            ascii_string += [' ']
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
        num_string += [f'{c:02X} ']
        if not (chr(c) in string.printable) or (chr(c) in string.whitespace):
            ascii_string += [' ']
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
        _str += [f'{n:02X}__']
    for n in range(len(arr)):
        if (n % length) == 0:
            _str += [f'\n{n:02X} | ']
        _str += [f'{arr[n]:02X}  ']
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
