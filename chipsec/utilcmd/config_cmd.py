# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2021, Intel Corporation
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

# Contact information:
# chipsec@intel.com

"""
>>> chipsec_util config show [config] <name>

Examples:

>>> chipsec_util config show ALL
>>> chipsec_util config show [CONFIG_PCI|MEMORY_RANGES|MM_MSGBUS|MSGBUS|IO|MSR]
"""

from argparse import ArgumentParser

from chipsec.command import BaseCommand, toLoad


class CONFIGCommand(BaseCommand):

    def requires_driver(self):
        self.skip_list = ["LOCKS", "CONTROLS", "ALL"]
        self.all_options = self.cs.Cfg.parent_keys + self.skip_list
        parser = ArgumentParser(usage='chipsec_util config')

        subparsers = parser.add_subparsers()

        # show
        parser_show = subparsers.add_parser('show')
        parser_show.add_argument('config', choices=self.all_options, default="ALL")
        parser_show.add_argument('-c', '--child-details', action='store_true',
                                 help='Include child details')
        parser_show.set_defaults(func=self.show, config="ALL")

        parser.parse_args(self.argv, namespace=self)

        return toLoad.All

    def show(self):
        if self.config == "ALL":
            config = self.all_options
        else:
            config = [self.config]
        for mconfig in config:
            if mconfig in self.skip_list:
                continue
            cfg = getattr(self.cs.Cfg, mconfig)
            self.logger.log("\n{}".format(mconfig))
            for vid in cfg.keys():
                self.logger.log("{}:".format(vid))
                for name in cfg[vid].keys():
                    if mconfig in ["CONFIG_PCI_RAW", "CONFIG_PCI"]:
                        self.logger.log('\t{} - {}'.format(name, self.pci_details(cfg[vid][name])))
                    elif mconfig == "MEMORY_RANGES":
                        self.logger.log('\t{} - {}'.format(name, self.memory_details(cfg[vid][name])))
                    elif mconfig in ["MM_MSGBUS", "MSGBUS", "IO"]:
                        self.logger.log('\t{} - {}'.format(name, self.get_port_details(cfg[vid][name])))
                    elif mconfig == "MSR":
                        self.logger.log('\t{} - {}'.format(name, self.msr_details(cfg[vid][name])))
                    if self.child_details and mconfig not in ["CONFIG_PCI_RAW"]:
                        self.get_child_details(vid, name)
        if set(config).intersection({"LOCKS", "ALL"}):
            self.lock_details()
        if set(config).intersection({"CONTROLS", "ALL"}):
            self.control_details()

    def msr_details(self, regi):
        ret = "config: {}".format(regi['config'])
        return ret

    def memory_details(self, regi):
        ret = "access: {}, address: {}, size: {}, config: {}".format(
            regi['access'], regi['address'], regi['size'], regi['config'])
        return ret

    def get_port_details(self, regi):
        ret = "port: {}, config: {}".format(regi['port'], regi['config'])
        return ret

    def get_child_details(self, vid, dev):
        config = self.cs.Cfg.child_keys
        for mconfig in config:
            if mconfig in ["CONTROLS", "LOCKS", "LOCKEDBY"]:
                continue
            cfg = getattr(self.cs.Cfg, mconfig)
            self.logger.log("\t{}:".format(mconfig))
            if mconfig == "MMIO_BARS":
                if dev in cfg[vid]:
                    for name in cfg[vid][dev].keys():
                        self.logger.log('\t\t{} - {}'.format(name, self.mmio_details(cfg[vid][dev][name])))
            elif mconfig == "IO_BARS":
                if dev in cfg[vid]:
                    for name in cfg[vid][dev].keys():
                        self.logger.log('\t\t{} - {}'.format(name, self.io_details(cfg[vid][dev][name])))
            elif mconfig == "IMA_REGISTERS":
                if dev in cfg[vid]:
                    for name in cfg[vid][dev].keys():
                        self.logger.log('\t\t{} - {}'.format(name, self.ima_details(cfg[vid][dev][name])))
            elif mconfig == "REGISTERS":
                for name in cfg[vid][dev].keys():
                    self.logger.log('\t\t{} - {}'.format(name, self.register_details(cfg[vid][dev][name])))
        self.logger.log("")

    def ima_details(self, regi):
        ret = "index: {}, data: {}, base: {}".format(
            regi['index'], regi['data'], regi['base'] if 'base' in regi.keys() else None)
        return ret

    def register_details(self, regi):
        if regi['type'] == 'pcicfg' or regi['type'] == 'mmcfg':
            ret = "device: {}, offset: {}, size: {}".format(regi['device'], regi['offset'], regi['size'])
        elif regi['type'] == 'mmio':
            ret = "bar: {}, offset: {}, size: {}".format(regi['bar'], regi['offset'], regi['size'])
        elif regi['type'] == 'mm_msgbus':
            ret = "offset: {}, size: {}".format(regi['offset'], regi['size'])
        elif regi['type'] == 'io':
            ret = "size: {}".format(regi['size'])
        elif regi['type'] == 'iobar':
            ret = "bar: {}, offset: {}, size: {}".format(regi['bar'], regi['offset'], regi['size'])
        elif regi['type'] == 'msr':
            if 'size' in regi:
                ret = "msr: {}, size:{}".format(regi['msr'], regi['size'])
            else:
                ret = "msr: {}".format(regi['msr'])
        elif regi['type'] == 'R Byte':
            if 'size' in regi:
                ret = "offset: {}, size: {}".format(regi['offset'], regi['size'])
            else:
                ret = "offset: {}".format(regi['offset'])
        elif regi['type'] == 'memory':
            ret = "access: {}, offset: {}, size: {}".format(regi['access'], regi['offset'], regi['size'])
        if 'FIELDS' in regi:
            for key in regi['FIELDS']:
                ret += ('\n\t\t\t{} - bit {}:{}'.format(
                    key, regi['FIELDS'][key]['bit'],
                    regi['FIELDS'][key]['size'] + regi['FIELDS'][key]['bit'] - 1))
        return ret

    def pci_details(self, regi):
        ret = "bus: {}, dev: {}, func: {}".format(regi['bus'], regi['dev'], regi['fun'])
        ret += ', did: {}'.format(regi['did'] if 'did' in regi else None)
        if 'config' in regi:
            ret += ', config: {}'.format(regi['config'])
        return ret

    def mmio_details(self, regi):
        if 'register' in regi:
            ret = "register: {}, base_field: {}, size: {}, fixed_address: {}".format(
                regi['register'], regi['base_field'], regi['size'],
                regi['fixed_address'] if 'fixed_address' in regi.keys() else None)
        else:
            ret = "bus: {}, dev: {}, func: {}, mask: {}, width: {}, size: {}, fixed_address: {}".format(
                regi['bus'], regi['dev'], regi['fun'], regi['mask'], regi['width'],
                regi['size'] if 'size' in regi.keys() else None,
                regi['fixed_address'] if 'fixed_address' in regi.keys() else None)
        return ret

    def io_details(self, regi):
        if 'register' in regi:
            ret = "register: {}, base_field: {}, size: {}, fixed_address: {}".format(
                regi['register'], regi['base_field'], regi['size'],
                regi['fixed_address'] if 'fixed_address' in regi.keys() else None)
        else:
            ret = "bus: {}, dev: {}, func: {}, reg: {}, mask: {}, size: {}, fixed_address: {}".format(
                regi['bus'], regi['dev'], regi['fun'], regi["reg"], regi['mask'],
                regi['size'] if 'size' in regi.keys() else None,
                regi['fixed_address'] if 'fixed_address' in regi.keys() else None)
        return ret

    def mem_details(self, regi):
        ret = "access: {}, address: {}, size: {}".format(regi['access'], regi['address'], regi['size'])
        return ret

    def control_details(self):
        self.logger.log("\nCONTROLS")
        cfg = getattr(self.cs.Cfg, "CONTROLS")
        for regi in cfg.keys():
            try:
                self.logger.log("\t{}\n\t\tregister: {}, field: {}\n".format(
                    regi, cfg[regi]['register'], cfg[regi]['field']))
            except KeyError:
                continue
        return

    def lock_details(self):
        self.logger.log("\nLOCKS")
        cfg = getattr(self.cs.Cfg, "LOCKS")
        for name in cfg:
            lock_str = "register: {}, field: {}, value: {}".format(
                cfg[name]['register'], cfg[name]['field'], cfg[name]['value'])
            self.logger.log('\t{}\n\t\t{}\n'.format(name, lock_str))
        return

    def bus_details(self, regi):
        ret = "bus: {}".format(regi)
        return ret


commands = {'config': CONFIGCommand}
