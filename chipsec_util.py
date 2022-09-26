#!/usr/bin/env python3
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
Standalone utility
"""

import os
import sys
import importlib
import argparse
from time import time

from chipsec.helper.oshelper import helper
from chipsec.defines import ExitCode
from chipsec.logger import logger
from chipsec.exceptions import UnknownChipsetError
from chipsec.chipset import cs
from chipsec.file import get_main_dir
from chipsec.lib.display import chipsec_properties, print_banner


class ChipsecUtil:

    def __init__(self, argv):
        self.global_usage = "All numeric values are in hex\n" + \
            "<width> is in {1, byte, 2, word, 4, dword}\n\n"
        self.commands = {}
        self.argv = argv
        self.import_cmds()
        self._cs = cs()
        self.parse_args()
        if self._show_banner:
            print_banner(self.argv)

    def parse_args(self):
        parser = argparse.ArgumentParser(usage='%(prog)s [options] <command>', add_help=False)
        options = parser.add_argument_group('Options')
        options.add_argument('-h', '--help', dest='show_help', help="show this message and exit", action='store_true')
        options.add_argument('-v', '--verbose', help='verbose mode', action='store_true')
        options.add_argument('--hal', help='HAL mode', action='store_true')
        options.add_argument('-d', '--debug', help='debug mode', action='store_true')
        options.add_argument('-vv', '--vverbose', help='very verbose HAL debug mode', action='store_true')
        options.add_argument('-l', '--log', help='output to log file')
        options.add_argument('-p', '--platform', dest='_platform', help='explicitly specify platform code')
        options.add_argument('--pch', dest='_pch', help='explicitly specify PCH code')
        options.add_argument('--helper', dest='_helper', help='specify OS Helper',
                             choices=helper().getAvailableHelpers())
        options.add_argument('_cmd', metavar='Command', nargs='?', choices=sorted(self.commands.keys()),
                             type=str.lower, default="help",
                             help="Util command to run: {{{}}}".format(','.join(sorted(self.commands.keys()))))
        options.add_argument('_cmd_args', metavar='Command Args', nargs=argparse.REMAINDER, help=self.global_usage)
        options.add_argument('-nb', '--no_banner', dest='_show_banner', help="chipsec won't display banner information",
                             action='store_false')
        options.add_argument('--skip_config', dest='_load_config', help='skip configuration and driver loading',
                             action='store_false')

        parser.parse_args(self.argv, namespace=ChipsecUtil)
        if self.show_help or self._cmd == "help":
            parser.print_help()
        if self.verbose:
            logger().VERBOSE = True
            logger().setlevel()
        if self.hal:
            logger().HAL = True
            logger().setlevel()
        if self.debug:
            logger().DEBUG = True
            logger().setlevel()
        if self.vverbose:
            logger().VERBOSE = True
            logger().HAL = True
            logger().DEBUG = True
            logger().setlevel()
        if self.log:
            logger().set_log_file(self.log)
        if not self._cmd_args:
            self._cmd_args = ["--help"]

    def import_cmds(self):
        cmds_dir = os.path.join(get_main_dir(), "chipsec", "utilcmd")
        cmds = [i[:-3] for i in os.listdir(cmds_dir) if i.endswith(".py") and not i.startswith("__")]

        logger().log_debug('[CHIPSEC] Loaded command-line extensions:')
        logger().log_debug('   {}'.format(cmds))
        module = None
        for cmd in cmds:
            try:
                cmd_path = 'chipsec.utilcmd.' + cmd
                module = importlib.import_module(cmd_path)
                cu = module.commands
                self.commands.update(cu)
            except ImportError as msg:
                # Display the import error and continue to import commands
                logger().log_debug("Exception occurred during import of {}: '{}'".format(cmd, str(msg)))
                continue
        self.commands.update({"help": ""})

    ##################################################################################
    # Entry point
    ##################################################################################

    def main(self):
        """
        Receives and executes the commands
        """
        if self.show_help or self._cmd == "help":
            return ExitCode.OK

        comm = self.commands[self._cmd](self._cmd_args, cs=self._cs)
        toLoad = comm.requires_driver()

        try:
            self._cs.init(self._platform, self._pch, self._helper, toLoad.load_driver(), toLoad.load_config())

        except UnknownChipsetError as msg:
            logger().log_warning("*******************************************************************")
            logger().log_warning("* Unknown platform!")
            logger().log_warning("* Platform dependent functionality will likely be incorrect")
            logger().log_warning("* Error Message: \"{}\"".format(str(msg)))
            logger().log_warning("*******************************************************************")
            logger().error('To run anyways please specify a cpu and pch (if necessary)\n\n')
            sys.exit(ExitCode.OK)
        except Exception as msg:
            logger().error(str(msg))
            sys.exit(ExitCode.EXCEPTION)

        chipsec_properties()

        logger().log("[CHIPSEC] Executing command '{}' with args {}\n".format(self._cmd, self._cmd_args))
        t = time()
        comm.run()
        logger().log("[CHIPSEC] Time elapsed {:.3f}".format(time() - t))
        if toLoad.load_driver():
            self._cs.destroyHelper(True)
        return comm.ExitCode


def main(argv=None):
    chipsecUtil = ChipsecUtil(argv if argv else sys.argv[1:])
    return chipsecUtil.main()


if __name__ == "__main__":
    sys.exit(main())
