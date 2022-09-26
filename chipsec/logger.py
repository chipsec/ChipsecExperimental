# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2022, Intel Corporation

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
Logging functions
"""
import os
import logging as pyLogging
import platform
import sys
import atexit


try:
    # See https://pypi.org/project/WConio2/ for more details.
    import WConio2 as WConio
    has_WConio = True
except ImportError:
    has_WConio = False


class chipsecrecordfactory(pyLogging.LogRecord):
    if sys.stdout.isatty() and os.getenv('NO_COLOR') is None and\
        (("windows" == platform.system().lower() and has_WConio) or "linux" == platform.system().lower()):
        if "windows" == platform.system().lower() and has_WConio:
            colors = {
                'BLACK': WConio.BLACK,
                'RED': WConio.LIGHTRED,
                'GREEN': WConio.LIGHTGREEN,
                'YELLOW': WConio.YELLOW,
                'BLUE': WConio.LIGHTBLUE,
                'PURPLE': WConio.MAGENTA,
                'CYAN': WConio.CYAN,
                'WHITE': WConio.WHITE,
                'LIGHT_GRAY': WConio.LIGHTGRAY,
            }

            def getMessage(self) -> str:
                color = None
                msg = str(self.msg)
                if self.args:
                    color = self.args[0]
                if color in self.colors:
                    WConio.textcolor(self.colors[color])
                    return msg

            old_setting = WConio.gettextinfo()[4] & 0x00FF
            atexit.register(WConio.textcolor, old_setting)

        elif "linux" == platform.system().lower():
            ENDC = '\033[0m'
            BOLD = '\033[1m'
            UNDERLINE = '\033[4m'
            csi = '\x1b['
            reset = '\x1b[0m'
            colors = {
                'END': 0,
                'LIGHT': 90,
                'DARK': 30,
                'BACKGROUND': 40,
                'LIGHT_BACKGROUND': 100,
                'GRAY': 0,
                'RED': 1,
                'GREEN': 2,
                'YELLOW': 3,
                'BLUE': 4,
                'PURPLE': 5,
                'CYAN': 6,
                'LIGHT_GRAY': 7,
                'NORMAL': 8,
                'WHITE': 9,
            }

            def getMessage(self) -> str:
                color = None
                msg = str(self.msg)
                if self.args:
                    color = self.args[0]
                if color in self.colors:
                    params = []
                    params.append(str(self.colors[color] + 30))
                    msg = ''.join((self.csi, ';'.join(params),
                                'm', msg, self.reset))
                return msg
    else:
        def getMessage(self) -> str:
                msg = str(self.msg)
                return msg


class Logger:
    """Class for logging to console, text file, XML."""

    def __init__(self):
        """The Constructor."""
        self.logfile = None
        self.rootLogger = pyLogging.getLogger(__name__)
        self.rootLogger.setLevel(pyLogging.INFO)
        self.ALWAYS_FLUSH = False
        pyLogging.addLevelName(19, "verbose")
        pyLogging.addLevelName(18, "hal")
        self.logstream = pyLogging.StreamHandler(sys.stdout)
        # Respect https://no-color.org/ convention, and disable colorization
        # when the output is not a terminal (eg. redirection to a file)
        #if sys.stdout.isatty() and os.getenv('NO_COLOR') is None:
        #    log_Color = True
        pyLogging.setLogRecordFactory(chipsecrecordfactory)  # applies colorization to output
        self.rootLogger.addHandler(self.logstream)  # adds streamhandler to root logger
        self.VERBOSE = False
        self.HAL = False
        self.DEBUG = False
        self.LOG_FILE_NAME = None

    def setlevel(self):
        if self.DEBUG:
            self.rootLogger.setLevel(pyLogging.DEBUG)
        elif self.HAL:
            self.rootLogger.setLevel(pyLogging.getLevelName("hal"))
        elif self.VERBOSE:
            self.rootLogger.setLevel(pyLogging.getLevelName("verbose"))
        else:
            self.rootLogger.setLevel(pyLogging.INFO)

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
                self.logfile = pyLogging.FileHandler(filename=self.LOG_FILE_NAME, mode='w')
                self.rootLogger.addHandler(self.logfile)  # adds filehandler to root logger

            except Exception:
                print("WARNING: Could not open log file '{}'".format(self.LOG_FILE_NAME))
            self.rootLogger.removeHandler(self.logstream)
        else:
            try:
                self.rootLogger.addHandler(self.logstream)
            except Exception:
                pass

    def close(self):
        """Closes the log file."""
        if self.logfile:
            try:
                self.rootLogger.removeHandler(self.logfile)
                self.rootLogger.removeHandler(self.logstream)
                self.logfile.close()
                self.logstream.flush()
            except Exception:
                print("WARNING: Could not close log file")
            finally:
                self.logfile = None

    def disable(self):
        """Disables the logging to file and closes the file if any."""
        self.LOG_FILE_NAME = None
        self.close()

    ######################################################################
    # Logging functions
    ######################################################################

    def flush(self):
        sys.stdout.flush()
        if self.logfile is not None:
            # flush should work with new python logging
            try:
                self.rootLogger.removeHandler(self.logfile)
                self.logfile.flush()
                self.rootLogger.addHandler(self.logfile)
            except Exception:
                self.disable()

    def set_always_flush(self, val):
        self.ALWAYS_FLUSH = val

    def _log(self, text, level=pyLogging.INFO, color=None):
        """Sends plain text to logging."""
        try:
            self.rootLogger.log(level, text, color)
            if self.ALWAYS_FLUSH:
                self.flush()
        except BaseException:
            print(text)

    def log(self, text):
        """Plain Log message"""
        self._log(text, pyLogging.INFO, "WHITE")

    def error(self, text):
        """Logs an Error message"""
        text = "ERROR: " + text
        self._log(text, pyLogging.ERROR, "PURPLE")

    def log_warning(self, text):
        """Logs an Warning message"""
        text = "WARNING: " + text
        self._log(text, pyLogging.INFO, "YELLOW")

    def log_verbose(self, text):
        """Logs an Verbose message"""
        self._log(text, pyLogging.getLevelName("verbose"), "LIGHT_GRAY")

    def log_hal(self, text):
        """Logs an Verbose message"""
        self._log(text, pyLogging.getLevelName("hal"), "LIGHT_GRAY")

    def log_debug(self, text):
        """Logs an Verbose message"""
        self._log(text, pyLogging.DEBUG, "LIGHT_GRAY")

    def log_passed(self, text):
        """Logs a passed message."""
        text = "[+] PASSED: " + text
        self._log(text, pyLogging.INFO, "GREEN")

    def log_failed(self, text):
        """Logs a failed message."""
        text = "[-] FAILED: " + text
        self._log(text, pyLogging.INFO, "RED")

    def log_error(self, text):
        """Logs an Error message"""
        text = "[-] ERROR: " + text
        self._log(text, pyLogging.ERROR, "PURPLE")

    def log_skipped(self, text):
        """Logs a NOT IMPLEMENTED message."""
        text = "[*] NOT IMPLEMENTED: " + text
        self._log(text, pyLogging.INFO, "YELLOW")

    def log_not_applicable(self, text):
        """Logs a NOT APPLICABLE message."""
        text = "[*] NOT APPLICABLE: " + text
        self._log(text, pyLogging.INFO, "YELLOW")

    def log_heading(self, text):
        """Logs a heading message."""
        self._log(text, pyLogging.INFO, "BLUE")

    def log_important(self, text):
        """Logs a important message."""
        text = "[!] " + text
        self._log(text, pyLogging.INFO, "RED")

    def log_result(self, text):
        """Logs a result message."""
        text = "[+] " + text
        self._log(text, pyLogging.INFO, "WHITE")

    def log_bad(self, text):
        """Logs a bad message, so it calls attention in the information displayed."""
        text = "[-] " + text
        self._log(text, pyLogging.INFO, "RED")

    def log_good(self, text):
        """Logs a message, if colors available, displays in green."""
        text = "[+] " + text
        self._log(text, pyLogging.INFO, "GREEN")

    def log_unknown(self, text):
        """Logs a message with a question mark."""
        text = "[?] " + text
        self._log(text, pyLogging.INFO, "WHITE")

    def log_information(self, text):
        """Logs a message with information message"""
        text = "[#] INFORMATION: " + text
        self._log(text, pyLogging.INFO, "WHITE")

    def start_test(self, test_name):
        """Logs the start point of a Test"""
        text = "[x][ =======================================================================\n"
        text = text + "[x][ Module: " + test_name + "\n"
        text = text + "[x][ ======================================================================="
        self._log(text, pyLogging.INFO, "BLUE")


_logger = Logger()


def logger():
    """Returns a Logger instance."""
    return _logger
