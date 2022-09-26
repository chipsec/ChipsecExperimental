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
#
# Contact information:
# chipsec@intel.com
#

from collections import namedtuple
from fnmatch import fnmatch
import importlib
import os
import re
import xml.etree.ElementTree as ET
from chipsec.defines import is_hex
from chipsec.exceptions import CSConfigError
from chipsec.file import get_main_dir
from chipsec.logger import logger
from chipsec.exceptions import DeviceNotFoundError
from chipsec.parsers import Stage
from chipsec.parsers import stage_info, config_data

scope_name = namedtuple("scope_name", ["vid", "parent", "name", "fields"])


CHIPSET_CODE_UNKNOWN = ''

PROC_FAMILY = {}


class Cfg:
    def __init__(self):
        self.logger = logger()
        self.parent_keys = ["CONFIG_PCI_RAW", "CONFIG_PCI", "MEMORY_RANGES", "MM_MSGBUS", "MSGBUS", "IO", "MSR"]
        self.child_keys = ["MMIO_BARS", "IO_BARS", "IMA_REGISTERS", "REGISTERS", "CONTROLS", "LOCKS", "LOCKEDBY"]
        for key in self.parent_keys + self.child_keys:
            setattr(self, key, {})
        self.proc_dictionary = {}
        self.proc_codes = set()
        self.pch_dictionary = {}
        self.pch_codes = set()
        self.device_dictionary = {}
        self.platform_xml_files = {}
        self.load_list = []
        self.load_extra = []
        self.scope = {None: ''}
        self.parsers = []

        # Initialize CPU and PCH artifacts
        self.vid = 0xFFFF
        self.did = 0xFFFF
        self.rid = 0xFF
        self.code = CHIPSET_CODE_UNKNOWN
        self.longname = "Unrecognized Platform"
        self.pch_vid = 0xFFFF
        self.pch_did = 0xFFFF
        self.pch_rid = 0xFF
        self.pch_code = CHIPSET_CODE_UNKNOWN
        self.pch_longname = 'Unrecognized PCH'
        self.req_pch = False

    ###
    # Private functions
    ###
    def _get_vid_from_filename(self, fname):
        search_string = re.compile(r'cfg.[0-9a-fA-F]+')
        match = search_string.search(fname)
        vid = match.group(0)[4:]
        return vid

    def _make_hex_key_str(self, int_val):
        str_val = '{:04X}'.format(int_val)
        return str_val

    def _create_vid(self, vid_str):
        key_list = self.parent_keys + self.child_keys
        key_list.remove("LOCKS")
        if vid_str not in self.CONFIG_PCI:
            for key in key_list:
                mdict = getattr(self, key)
                mdict[vid_str] = {}

    ###
    # PCI device tree enumeration
    ###
    def set_pci_data(self, enum_devices):
        if not hasattr(self, 'CONFIG_PCI_RAW'):
            setattr(self, 'CONFIG_PCI_RAW', {})
        for b, d, f, vid, did, rid in enum_devices:
            vid_str = self._make_hex_key_str(vid)
            did_str = self._make_hex_key_str(did)
            pci_data = {
                'bus': [b],
                'dev': d,
                'fun': f,
                'vid': vid,
                'did': did,
                'rid': rid}
            if vid_str not in self.CONFIG_PCI_RAW:
                self._create_vid(vid_str)
            if did_str not in self.CONFIG_PCI_RAW[vid_str]:
                self.CONFIG_PCI_RAW[vid_str][did_str] = pci_data
            elif b not in self.CONFIG_PCI_RAW[vid_str][did_str]['bus']:
                self.CONFIG_PCI_RAW[vid_str][did_str]['bus'].append(b)

    ###
    # Private config functions
    ###
    def _get_stage_parsers(self, stage):
        handlers = {}
        for parser in self.parsers:
            if parser.get_stage() != stage:
                continue
            handlers.update(parser.get_metadata())
        return handlers

    def _update_supported_platforms(self, conf_data, data):
        if not data:
            return
        if data.family and data.proc_code:
            fam = data.family.lower()
            if fam not in PROC_FAMILY:
                PROC_FAMILY[fam] = []
            PROC_FAMILY[fam].append(data.proc_code)
        if data.proc_code:
            dest = self.proc_dictionary
            self.proc_codes.add(data.proc_code)
            if data.proc_code not in self.platform_xml_files:
                self.platform_xml_files[data.proc_code] = []
            self.platform_xml_files[data.proc_code].append(conf_data)
        elif data.pch_code:
            dest = self.pch_dictionary
            self.pch_codes.add(data.pch_code)
            if data.pch_code not in self.platform_xml_files:
                self.platform_xml_files[data.pch_code] = []
            self.platform_xml_files[data.pch_code].append(conf_data)
        else:
            dest = self.device_dictionary
            if 'devices' not in self.platform_xml_files:
                self.platform_xml_files['devices'] = []
            self.platform_xml_files['devices'].append(conf_data)
        if data.vid_str not in dest:
            dest[data.vid_str] = {}
        for sku in data.sku_list:
            did_str = self._make_hex_key_str(sku['did'])
            if did_str not in dest[data.vid_str]:
                dest[data.vid_str][did_str] = []
            sku['req_pch'] = data.req_pch
            sku['detect'] = data.detect_vals
            dest[data.vid_str][did_str].append(sku)

    def _find_sku_data(self, dict_ref, code, detect_val=None):
        for vid_str in dict_ref:
            for did_str in dict_ref[vid_str]:
                for sku in dict_ref[vid_str][did_str]:
                    if code and sku['code'] != code.upper():
                        continue
                    if not code:
                        if vid_str not in self.CONFIG_PCI_RAW:
                            continue
                        if did_str not in self.CONFIG_PCI_RAW[vid_str]:
                            continue
                        if sku['detect'] and detect_val and detect_val not in sku['detect']:
                            continue
                    return sku
        return None

    def _get_config_iter(self, fxml):
        tree = ET.parse(fxml.xml_file)
        root = tree.getroot()
        return root.iter('configuration')

    def _load_sec_configs(self, load_list, stage):
        stage_str = 'core' if stage == Stage.CORE_SUPPORT else 'custom'
        tag_handlers = self._get_stage_parsers(stage)
        if not load_list or not tag_handlers:
            return
        for fxml in load_list:
            self.logger.log_debug('[*] Loading {} config data: [{}] - {}'.format(stage_str,
                                                                                 fxml.dev_name,
                                                                                 fxml.xml_file))
            if not os.path.isfile(fxml.xml_file):
                self.logger.log_debug('[-] File not found: {}'.format(fxml.xml_file))
                continue
            for config_root in self._get_config_iter(fxml):
                for tag in tag_handlers:
                    self.logger.log_debug('[*] Loading {} data...'.format(tag))
                    for node in config_root.iter(tag):
                        tag_handlers[tag](node, fxml)

    ###
    # Config loading functions
    ###
    def load_parsers(self):
        parser_path = os.path.join(get_main_dir(), 'chipsec', 'cfg', 'parsers')
        if not os.path.isdir(parser_path):
            raise CSConfigError('Unable to locate configuration parsers: {}'.format(parser_path))
        parser_files = [f.name for f in sorted(os.scandir(parser_path), key=lambda x: x.name)
                        if fnmatch(f.name, '*.py') and not fnmatch(f.name, '__init__.py')]
        for parser in parser_files:
            parser_name = '.'.join(['chipsec', 'cfg', 'parsers', os.path.splitext(parser)[0]])
            self.logger.log_debug('[*] Importing parser: {}'.format(parser_name))
            try:
                module = importlib.import_module(parser_name)
            except Exception:
                self.logger.log_debug('[*] Failed to import {}'.format(parser_name))
                continue
            if not hasattr(module, 'parsers'):
                self.logger.log_debug('[*] Missing parsers variable: {}'.format(parser))
                continue
            for obj in module.parsers:
                try:
                    parser_obj = obj(self)
                except Exception:
                    self.logger.log_debug('[*] Failed to create object: {}'.format(parser))
                    continue
                parser_obj.startup()
                self.parsers.append(parser_obj)

    def add_extra_configs(self, path, filename=None, loadnow=False):
        config_path = os.path.join(get_main_dir(), 'chipsec', 'cfg', path)
        if os.path.isdir(config_path) and filename is None:
            self.load_extra = [config_data(None, None, f.path) for f in sorted(os.scandir(config_path), key=lambda x: x.name)
                            if fnmatch(f.name, '*.xml')]
        elif os.path.isdir(config_path) and filename:
            self.load_extra = [config_data(None, None, f.path) for f in sorted(os.scandir(config_path), key=lambda x: x.name)
                            if fnmatch(f.name, '*.xml') and fnmatch(f.name, filename)]
        else:
            raise CSConfigError('Unable to locate configuration file(s): {}'.format(config_path.xml_file))
        if loadnow and self.load_extra:
            self._load_sec_configs(self.load_extra, Stage.EXTRA)

    def load_platform_info(self):
        tag_handlers = self._get_stage_parsers(Stage.GET_INFO)
        cfg_path = os.path.join(get_main_dir(), 'chipsec', 'cfg')

        # Locate all root configuration files
        cfg_files = []
        cfg_vids = [f.name for f in os.scandir(cfg_path) if f.is_dir() and is_hex(f.name)]
        for vid_str in cfg_vids:
            root_path = os.path.join(cfg_path, vid_str)
            cfg_files.extend([config_data(vid_str, None, f.path)
                             for f in sorted(os.scandir(root_path), key=lambda x: x.name)
                             if fnmatch(f.name, '*.xml')])

        # Process platform info data and generate lookup tables
        for fxml in cfg_files:
            self.logger.log_debug('[*] Processing platform config information: {}'.format(fxml.xml_file))
            for config_root in self._get_config_iter(fxml):
                stage_data = stage_info(fxml.vid_str, config_root)
                for tag in tag_handlers:
                    for node in config_root.iter(tag):
                        data = tag_handlers[tag](node, stage_data)
                        if not data:
                            continue
                        self._update_supported_platforms(fxml, data)

        # Create platform global data
        for cc in self.proc_codes:
            globals()["CHIPSET_CODE_{}".format(cc.upper())] = cc.upper()
        for pc in self.pch_codes:
            globals()["PCH_CODE_{}".format(pc[4:].upper())] = pc.upper()

    def platform_detection(self, proc_code, pch_code, cpuid):
        # Detect processor files
        sku = self._find_sku_data(self.proc_dictionary, proc_code, cpuid)
        if sku:
            self.vid = sku['vid']
            self.did = sku['did']
            self.code = sku['code']
            if not proc_code:
                vid_str = self._make_hex_key_str(self.vid)
                did_str = self._make_hex_key_str(self.did)
                self.rid = self.CONFIG_PCI_RAW[vid_str][did_str]['rid']
            self.longname = sku['longname']
            self.req_pch = sku['req_pch']

        # Detect PCH files
        sku = self._find_sku_data(self.pch_dictionary, pch_code)
        if sku:
            self.pch_vid = sku['vid']
            self.pch_did = sku['did']
            self.pch_code = sku['code']
            if not pch_code:
                vid_str = self._make_hex_key_str(self.pch_vid)
                did_str = self._make_hex_key_str(self.pch_did)
                self.pch_rid = self.CONFIG_PCI_RAW[vid_str][did_str]['rid']
            self.pch_longname = sku['longname']

        # Create XML file load list
        if self.code:
            self.load_list.extend(self.platform_xml_files[self.code])
        if self.pch_code:
            self.load_list.extend(self.platform_xml_files[self.pch_code])
        if 'devices' in self.platform_xml_files:
            self.load_list.extend(self.platform_xml_files['devices'])

    def load_platform_config(self):
        sec_load_list = []
        tag_handlers = self._get_stage_parsers(Stage.DEVICE_CFG)
        for fxml in self.load_list:
            self.logger.log_debug('[*] Loading primary config data: {}'.format(fxml.xml_file))
            for config_root in self._get_config_iter(fxml):
                for tag in tag_handlers:
                    self.logger.log_debug('[*] Collecting {} configuration data...'.format(tag))
                    for node in config_root.iter(tag):
                        sec_load_list.extend(tag_handlers[tag](node, fxml))
        self._load_sec_configs(sec_load_list, Stage.CORE_SUPPORT)
        self._load_sec_configs(sec_load_list, Stage.CUST_SUPPORT)
        if self.load_extra:
            self._load_sec_configs(self.load_extra, Stage.EXTRA)

    ###
    # Platform detection functions
    ###
    def get_pch_code(self):
        return self.pch_code

    def is_pch_req(self):
        return self.req_pch

    def print_platform_info(self):
        self.logger.log("Platform: {}".format(self.longname))
        self.logger.log("\tVID: {:04X}".format(self.vid))
        self.logger.log("\tDID: {:04X}".format(self.did))
        self.logger.log("\tRID: {:02X}".format(self.rid))

    def print_pch_info(self):
        self.logger.log("Platform: {}".format(self.pch_longname))
        self.logger.log("\tVID: {:04X}".format(self.pch_vid))
        self.logger.log("\tDID: {:04X}".format(self.pch_did))
        self.logger.log("\tRID: {:02X}".format(self.pch_rid))

    ###
    # Scoping functions
    ###
    def set_scope(self, scope):
        self.scope.update(scope)

    def get_scope(self, name):
        if name.count('.') > 0:
            return ''
        elif name in self.scope:
            return self.scope[name]
        else:
            return self.scope[None]

    def clear_scope(self):
        self.scope = {None: ''}

    def convert_internal_scope(self, scope, name):
        if scope:
            sname = scope + '.' + name
        else:
            sname = name
        return scope_name(*(sname.split('.', 3) + [None] * (4 - len(sname.split('.', 3)))))

    def get_control_def(self, control_name):
        return self.CONTROLS[control_name]

    def is_control_defined(self, control_name):
        return True if control_name in self.CONTROLS else False

    ###
    # Register Functions
    ###
    def get_register_def(self, reg_name):
        scope = self.get_scope(reg_name)
        vid, dev_name, register, _ = self.convert_internal_scope(scope, reg_name)
        reg_def = self.REGISTERS[vid][dev_name][register]
        if reg_def["type"] in ["pcicfg", "mmcfg"]:
            dev = self.CONFIG_PCI[vid][dev_name]
            reg_def['bus'] = dev['bus']
            reg_def['dev'] = dev['dev']
            reg_def['fun'] = dev['fun']
        elif reg_def["type"] == "memory":
            dev = self.MEMORY_RANGES[vid][dev_name]
            reg_def['address'] = dev['address']
            reg_def['access'] = dev['access']
        elif reg_def["type"] == "mm_msgbus":
            dev = self.MM_MSGBUS[vid][dev_name]
            reg_def['port'] = dev['port']
        elif reg_def["type"] == "indirect":
            dev = self.IMA_REGISTERS[vid][dev_name]
            if ('base' in dev):
                reg_def['base'] = dev['base']
            else:
                reg_def['base'] = "0"
            if (dev['index'] in self.REGISTERS[vid][dev_name]):
                reg_def['index'] = dev['index']
            else:
                logger().error("Index register {} not found".format(dev['index']))
            if (dev['data'] in self.REGISTERS[vid][dev_name]):
                reg_def['data'] = dev['data']
            else:
                logger().error("Data register {} not found".format(dev['data']))
        return reg_def

    def get_mmio_def(self, bar_name):
        ret = None
        scope = self.get_scope(bar_name)
        vid, device, bar, _ = self.convert_internal_scope(scope, bar_name)
        if vid in self.MMIO_BARS and device in self.MMIO_BARS[vid]:
            if bar in self.MMIO_BARS[vid][device]:
                ret = self.MMIO_BARS[vid][device][bar]
        return ret

    def get_io_def(self, bar_name):
        scope = self.get_scope(bar_name)
        vid, device, bar, _ = self.convert_internal_scope(scope, bar_name)
        if bar in self.IO_BARS[vid][device]:
            return self.IO_BARS[vid][device][bar]
        else:
            return None

    def get_mem_def(self, range_name):
        scope = self.get_scope(range_name)
        vid, range, _, _ = self.convert_internal_scope(scope, range_name)
        if range in self.MEMORY_RANGES[vid]:
            return self.MEMORY_RANGES[vid][range]
        else:
            return None

    def get_device_bus(self, dev_name):
        scope = self.get_scope(dev_name)
        vid, device, _, _ = self.convert_internal_scope(scope, dev_name)
        if vid in self.CONFIG_PCI and device in self.CONFIG_PCI[vid]:
            return self.CONFIG_PCI[vid][device]["bus"]
        else:
            return None

    def is_register_defined(self, reg_name):
        scope = self.get_scope(reg_name)
        vid, device, register, _ = self.convert_internal_scope(scope, reg_name)
        try:
            return (self.REGISTERS[vid][device].get(register, None) is not None)
        except KeyError:
            return False

    def is_device_defined(self, dev_name):
        scope = self.get_scope(dev_name)
        vid, device, _, _ = self.convert_internal_scope(scope, dev_name)
        if self.CONFIG_PCI[vid].get(device, None) is None:
            return False
        else:
            return True

    def get_device_BDF(self, device_name):
        scope = self.get_scope(device_name)
        vid, device, _, _ = self.convert_internal_scope(scope, device_name)
        try:
            device = self.CONFIG_PCI[vid][device]
        except KeyError:
            device = None
        if device is None or device == {}:
            raise DeviceNotFoundError('DeviceNotFound: {}'.format(device_name))
        b = device['bus']
        d = device['dev']
        f = device['fun']
        return (b, d, f)

    def register_has_field(self, reg_name, field_name):
        scope = self.get_scope(reg_name)
        vid, device, register, _ = self.convert_internal_scope(scope, reg_name)
        try:
            reg_def = self.REGISTERS[vid][device][register]
        except KeyError:
            return False
        if 'FIELDS' not in reg_def:
            return False
        return (field_name in reg_def['FIELDS'])

    def get_REGISTERS_match(self, name):
        vid, device, register, field = self.convert_internal_scope("", name)
        ret = []
        if vid is None or vid == '*':
            vid = self.REGISTERS.keys()
        else:
            vid = [vid]
        for v in vid:
            if v in self.REGISTERS:
                if device is None or device == "*":
                    dev = self.REGISTERS[v].keys()
                else:
                    dev = [device]
                for d in dev:
                    if d in self.REGISTERS[v]:
                        if register is None or register == "*":
                            reg = self.REGISTERS[v][d].keys()
                        else:
                            reg = [register]
                        for r in reg:
                            if r in self.REGISTERS[v][d]:
                                if field is None or field == "*":
                                    fld = self.REGISTERS[v][d][r]['FIELDS'].keys()
                                else:
                                    if field in self.REGISTERS[v][d][r]['FIELDS']:
                                        fld = [field]
                                    else:
                                        fld = []
                                for f in fld:
                                    ret.append("{}.{}.{}.{}".format(v, d, r, f))
        return ret

    def get_MMIO_match(self, name):
        vid, device, inbar, _ = self.convert_internal_scope("", name)
        ret = []
        if vid is None or vid == '*':
            vid = self.REGISTERS.keys()
        else:
            vid = [vid]
        for v in vid:
            if v in self.MMIO_BARS:
                if device is None or device == '*':
                    dev = self.MMIO_BARS[v].keys()
                else:
                    dev = [device]
                for d in dev:
                    if d in self.MMIO_BARS[v]:
                        if inbar is None or inbar == '*':
                            bar = self.MMIO_BARS[v][d]
                        else:
                            bar = [inbar]
                        for b in bar:
                            if b in self.MMIO_BARS[v][d]:
                                ret.append("{}.{}.{}".format(v, d, b))
        return ret

    ###
    # Locks functions
    ###
    def get_lock_list(self):
        return self.LOCKS.keys()

    def is_lock_defined(self, lock_name):
        return lock_name in self.LOCKS.keys()

    def get_locked_value(self, lock_name):
        logger().log_debug('Retrieve value for lock {}'.format(lock_name))
        return self.LOCKS[lock_name]['value']

    def get_lock_desc(self, lock_name):
        return self.LOCKS[lock_name]['desc']

    def get_lock_type(self, lock_name):
        if 'type' in self.LOCKS[lock_name]:
            mtype = self.LOCKS[lock_name]['type']
        else:
            mtype = "RW/L"
        return mtype

    def get_lockedby(self, lock_name):
        if lock_name in self.LOCKEDBY:
            return self.LOCKEDBY[lock_name]
        else:
            return None
