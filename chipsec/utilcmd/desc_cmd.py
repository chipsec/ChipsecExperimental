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
The idt, gdt and ldt commands print the IDT, GDT and LDT, respectively.

IDT command:

>>> chipsec_util idt [cpu_id]

Examples:

>>> chipsec_util idt 0
>>> chipsec_util idt

GDT command:

>>> chipsec_util gdt [cpu_id]

Examples:

>>> chipsec_util gdt 0
>>> chipsec_util gdt

LDT command:

>>> chipsec_util ldt [cpu_id]

Examples:

>>> chipsec_util ldt 0
>>> chipsec_util ldt
"""

from argparse import ArgumentParser
from chipsec.command import BaseCommand, toLoad


# CPU descriptor tables
class IDTCommand(BaseCommand):
    """
    >>> chipsec_util idt thread [cpu_id]
    >>> chipsec_util idt all

    Examples:

    >>> chipsec_util idt thread 0
    >>> chipsec_util idt all
    """
    def requires_driver(self):
        parser = ArgumentParser(usage=IDTCommand.__doc__)
        subparsers = parser.add_subparsers()

        parser_all = subparsers.add_parser('all')
        parser_all.set_defaults(func=self.idt_all)

        parser_thread = subparsers.add_parser('thread')
        parser_thread.add_argument('thread', type=lambda x: int(x, 0), help="thread")
        parser_thread.set_defaults(func=self.idt_thread)
        parser.parse_args(self.argv, namespace=IDTCommand)

        return toLoad.All

    def idt_all(self):
        num_threads = self.cs.msr.get_cpu_thread_count()
        self.logger.log("[CHIPSEC] Dumping IDT of {:d} CPU threads".format(num_threads))
        self.cs.cpu.IDT_all(4)

    def idt_thread(self):
        num_threads = self.cs.msr.get_cpu_thread_count()
        if self.thread < num_threads:
            self.logger.log("[CHIPSEC] Dumping IDT of CPU thread {:d}".format(self.thread))
            self.cs.cpu.IDT(self.thread, 4)
        else:
            self.logger.log('Improper thread must be between 0 and {:d}'.format(num_threads))


class GDTCommand(BaseCommand):
    """
    >>> chipsec_util gdt thread [cpu_id]
    >>> chipsec_util gdt all

    Examples:

    >>> chipsec_util gdt thread 0
    >>> chipsec_util gdt all
    """
    def requires_driver(self):
        parser = ArgumentParser(usage=GDTCommand.__doc__)
        subparsers = parser.add_subparsers()

        parser_all = subparsers.add_parser('all')
        parser_all.set_defaults(func=self.gdt_all)

        parser_thread = subparsers.add_parser('thread')
        parser_thread.add_argument('thread', type=lambda x: int(x, 0), help="thread")
        parser_thread.set_defaults(func=self.gdt_thread)
        parser.parse_args(self.argv, namespace=GDTCommand)
        return True

    def gdt_all(self):
        num_threads = self.cs.msr.get_cpu_thread_count()
        self.logger.log("[CHIPSEC] Dumping IDT of {:d} CPU threads".format(num_threads))
        self.cs.cpu.GDT_all(4)

    def gdt_thread(self):
        num_threads = self.cs.msr.get_cpu_thread_count()
        if self.thread < num_threads:
            self.logger.log("[CHIPSEC] Dumping IDT of CPU thread {:d}".format(self.thread))
            self.cs.cpu.GDT(self.thread, 4)
        else:
            self.logger.log('Improper thread must be between 0 and {:d}'.format(num_threads))


class LDTCommand(BaseCommand):
    """
    >>> chipsec_util ldt [cpu_id]

    Examples:

    >>> chipsec_util ldt 0
    >>> chipsec_util ldt
    """
    def requires_driver(self):
        return False

    def run(self):
        self.logger.log_error("[CHIPSEC] ldt not implemented")


commands = {'idt': IDTCommand, 'gdt': GDTCommand}
