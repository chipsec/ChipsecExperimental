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

import traceback

LOAD_COMMON = True

CHIPSET_ID_UNKNOWN = 0

CHIPSET_CODE_UNKNOWN = ''

CHIPSET_FAMILY = {}

PCH_CODE_PREFIX = 'PCH_'

PROC_FAMILY = {}


class Cfg:
    def __init__(self):
        self.logger = logger()
        self.CONFIG_PCI = {}
        self.REGISTERS = {}
        self.MMIO_BARS = {}
        self.IO_BARS = {}
        self.IMA_REGISTERS = {}
        self.MEMORY_RANGES = {}
        self.CONTROLS = {}
        self.BUS = {}
        self.LOCKS = {}
        self.LOCKEDBY = {}
        self.XML_CONFIG_LOADED = False

        self.proc_dictionary = {}
        self.proc_codes = set()
        self.pch_dictionary = {}
        self.pch_codes = set()
        self.device_dictionary = {}
        self.platform_xml_files = {}
        self.load_list = []
        self.load_extra = []
        self.parsers = []

        self.detection_dictionary = {}

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
    def _make_hex_key_str(self, int_val):
        str_val = '{:04X}'.format(int_val)
        return str_val

    def platform_detection(self, platform_code, req_pch_code, cpuid, vid, did, rid, pch_vid, pch_did, pch_rid):
        # initialize chipset values to unknown
        self.cpuid = cpuid
        _unknown_platform = True
        self.longname = 'UnknownPlatform'
        self.vid = 0xFFFF
        self.did = 0xFFFF
        self.rid = 0xFF
        # initialize pch values to unknown/default
        _unknown_pch = True
        self.pch_longname = 'Default PCH'
        self.pch_vid = 0xFFFF
        self.pch_did = 0xFFFF
        self.pch_rid = 0xFF

        if platform_code is None:
            # platform code was not passed in try to determine based upon cpu id
            vid_found = vid in self.proc_dictionary
            did_found = did in self.proc_dictionary[vid]
            # check if multiple platform found by [vid][did]
            multiple_found = len(self.proc_dictionary[vid][did]) > 1
            logger().log_debug("read out cpuid:{}, platforms found per vid & did:{}, multiple:{}".format(cpuid, self.proc_dictionary[vid][did], multiple_found))
            for i in self.detection_dictionary.keys():
                logger().log_debug("cpuid detection val:{}, plat:{}".format(i, self.detection_dictionary[i]))
            cpuid_found = cpuid in self.detection_dictionary.keys()
            if vid_found and did_found and multiple_found and cpuid_found:
                for item in self.proc_dictionary[vid][did]:
                    if self.detection_dictionary[cpuid] == item['code']:
                        # matched processor with detection value, cpuid used to decide the correct platform
                        _unknown_platform = False
                        data_dict = item
                        self.code = data_dict['code'].upper()
                        self.longname = data_dict['longname']
                        self.vid = vid
                        self.did = did
                        self.rid = rid
                        break
            elif vid_found and did_found:
                _unknown_platform = False
                data_dict = self.proc_dictionary[vid][did][0]
                self.code = data_dict['code'].upper()
                self.longname = data_dict['longname']
                self.vid = vid
                self.did = did
                self.rid = rid
            elif cpuid_found:
                _unknown_platform = False
                self.code = self.detection_dictionary[cpuid]
                self.longname = self.detection_dictionary[cpuid]
                self.vid = vid
                self.did = did
                self.rid = rid

        elif platform_code in self.proc_codes:
            # Check if platform code passed in is valid and override configuration
            _unknown_platform = False
            #self.vid = self.proc_codes[platform_code]['vid']
            #self.did = self.proc_codes[platform_code]['did']
            self.rid = 0x00
            self.code = platform_code
            self.longname = platform_code
            msg = 'Platform: Actual values: VID = 0x{:04X}, DID = 0x{:04X}, RID = 0x{:02X}'.format(vid, did, rid)
            if cpuid:
                msg += ', CPUID = 0x{}'.format(cpuid)
            logger().log("[CHIPSEC] {}".format(msg))

        if req_pch_code is not None:
            # Check if pch code passed in is valid
            if req_pch_code in self.pch_codes:
                #self.pch_vid = self.pch_codes[req_pch_code]['vid']
                #self.pch_did = self.pch_codes[req_pch_code]['did']
                self.pch_rid = 0x00
                self.pch_code = req_pch_code
                self.pch_longname = req_pch_code
                _unknown_pch = False
                msg = 'PCH     : Actual values: VID = 0x{:04X}, DID = 0x{:04X}, RID = 0x{:02X}'.format(pch_vid, pch_did, pch_rid)
                logger().log("[CHIPSEC] {}".format(msg))
        elif (pch_vid in self.pch_dictionary.keys()) and (pch_did in self.pch_dictionary[pch_vid].keys()):
            # Check if pch did for device is in configuration
            self.pch_vid = pch_vid
            self.pch_did = pch_did
            self.pch_rid = pch_rid
            pch_list = self.pch_dictionary[self.pch_vid][self.pch_did]
            if len(pch_list) > 1:
                logger().log("[!]       Multiple PCHs contain the same DID. Using first in the list.")
            data_dict = pch_list[0]
            self.pch_code = data_dict['code']
            self.pch_longname = data_dict['longname']
            _unknown_pch = False
        else:
            self.pch_vid = pch_vid
            self.pch_did = pch_did
            self.pch_rid = pch_rid

        if not self.req_pch:
            self.pch_longname = self.longname
            _unknown_pch = False

        return (_unknown_platform, _unknown_pch)

    ###
    # Platform detection functions
    ###
    def get_chipset_code(self):
        return self.code

    def get_pch_code(self):
        return self.pch_code

    def is_pch_req(self):
        return self.req_pch

    def print_platform_info(self):
        self.logger.log("Platform: {}".format(self.longname))
        self.logger.log(f'\tCPUID: {self.cpuid}')
        self.logger.log("\tVID: {:04X}".format(self.vid))
        self.logger.log("\tDID: {:04X}".format(self.did))
        self.logger.log("\tRID: {:02X}".format(self.rid))

    def print_pch_info(self):
        self.logger.log("Platform: {}".format(self.pch_longname))
        self.logger.log("\tVID: {:04X}".format(self.pch_vid))
        self.logger.log("\tDID: {:04X}".format(self.pch_did))
        self.logger.log("\tRID: {:02X}".format(self.pch_rid))

    def print_supported_chipsets(self):
        logger().log("\nSupported platforms:\n")
        logger().log("VID     | DID     | Name           | Code   | Long Name")
        logger().log("-------------------------------------------------------------------------------------")
        for _vid in sorted(self.proc_dictionary.keys()):
            for _did in sorted(self.proc_dictionary[_vid]):
                for item in self.proc_dictionary[_vid][_did]:
                    logger().log(" {:-#06x} | {:-#06x} | {:14} | {:6} | {:40}".format(_vid, _did, item['name'], item['code'].lower(), item['longname']))

    #
    # Load chipsec/cfg/<code>.py configuration file for platform <code>
    #

    def init_cfg(self):
        if self.code and '' != self.code:
            try:
                module_path = 'chipsec.cfg.' + self.code
                module = importlib.import_module(module_path)
                logger().log_good("imported platform specific configuration: chipsec.cfg.{}".format(self.code))
                self.Cfg = getattr(module, self.code)()
            except ImportError as msg:
                if logger().DEBUG:
                    logger().log("[*] Couldn't import chipsec.cfg.{}\n{}".format(self.code, str(msg)))

        #
        # Initialize platform configuration from XML files
        #
        try:
            self.load_xml_configuration()
        except:
            if logger().DEBUG:
                logger().log_bad(traceback.format_exc())
            pass

    ##################################################################################
    #
    # Loading platform configuration from XML files in chipsec/cfg/
    #
    ##################################################################################

    def load_xml_configuration(self):
        # Create a sorted config file list (xml only)
        _cfg_files = []
        _cfg_path = os.path.join(get_main_dir(), 'chipsec/cfg', "{:04X}".format(self.vid))
        for root, subdirs, files in os.walk(_cfg_path):
            _cfg_files.extend([os.path.join(root, x) for x in files if fnmatch.fnmatch(x, '*.xml')])
        _cfg_files.sort()
        if logger().DEBUG:
            logger().log("[*] Configuration Files:")
            for _xml in _cfg_files:
                logger().log("[*] - {}".format(_xml))

        # Locate common (chipsec/cfg/{vid}/common*.xml) configuration XML files.
        loaded_files = []
        if LOAD_COMMON:
            for _xml in _cfg_files:
                if fnmatch.fnmatch(os.path.basename(_xml), 'common*.xml'):
                    loaded_files.append(_xml)

        # Locate configuration files from all other XML files recursively (if any) excluding other platform configuration files.
            platform_files = []
            for plat in [c.lower() for c in self.proc_codes]:
                platform_files.extend([x for x in _cfg_files if fnmatch.fnmatch(os.path.basename(x), '{}*.xml'.format(plat)) or os.path.basename(x).startswith(PCH_CODE_PREFIX.lower())])
            loaded_files.extend([x for x in _cfg_files if x not in loaded_files and x not in platform_files])

        # Locate platform specific (chipsec/cfg/{vid}/<code>*.xml) configuration XML files.
        if self.code and CHIPSET_CODE_UNKNOWN != self.code:
            for _xml in _cfg_files:
                if fnmatch.fnmatch(os.path.basename(_xml), '{}*.xml'.format(self.code.lower())):
                    loaded_files.append(_xml)

        # Locate PCH specific (chipsec/cfg/{vid}/pch_<code>*.xml) configuration XML files.
        if self.pch_code and CHIPSET_CODE_UNKNOWN != self.pch_code:
            for _xml in _cfg_files:
                if fnmatch.fnmatch(os.path.basename(_xml).lower(), '{}*.xml'.format(self.pch_code.lower())):
                    loaded_files.append(_xml)

        # Load all configuration files for this platform.
        if logger().DEBUG:
            logger().log("[*] Loading Configuration Files:")
        for _xml in loaded_files:
            self.init_cfg_xml(_xml, self.code.lower(), self.pch_code.lower())

        self.Cfg.XML_CONFIG_LOADED = True

    def populate_cfg_type(self, xml_cfg, type, config_to_modify, item_name):
        for _item in xml_cfg.iter(type):
            for _named_item in _item.iter(item_name):
                _name = _named_item.attrib['name']
                del _named_item.attrib['name']
                if 'undef' in _named_item.attrib:
                    if _name in config_to_modify:
                        if logger().DEBUG:
                            logger().log("    - {:16}: {}".format(_name, _named_item.attrib['undef']))
                        config_to_modify.pop(_name, None)
                    continue
                if type == 'registers':
                    if 'size' not in _named_item.attrib:
                        _named_item.attrib['size'] = "0x4"
                    if 'desc' not in _named_item.attrib:
                        _named_item.attrib['desc'] = ''
                fields = {}
                if _named_item.find('field') is not None:
                    for _field in _named_item.iter('field'):
                        _field_name = _field.attrib['name']
                        if 'lockedby' in _field.attrib:
                            _lockedby = _field.attrib['lockedby']
                            if _lockedby in self.Cfg.LOCKEDBY.keys():
                                self.Cfg.LOCKEDBY[_lockedby].append((_name, _field_name))
                            else:
                                self.Cfg.LOCKEDBY[_lockedby] = [(_name, _field_name)]
                        del _field.attrib['name']
                        if 'desc' not in _field.attrib:
                            _field.attrib['desc'] = ''
                        fields[_field_name] = _field.attrib
                    _named_item.attrib['FIELDS'] = fields

                config_to_modify[_name] = _named_item.attrib
                if logger().DEBUG:
                    logger().log("    + {:16}: {}".format(_name, _named_item.attrib))

    def init_cfg_xml(self, fxml, code, pch_code):
        if not os.path.exists(fxml):
            return
        if logger().DEBUG:
            logger().log("[*] looking for platform config in '{}'..".format(fxml))
        tree = ET.parse(fxml)
        root = tree.getroot()
        for _cfg in root.iter('configuration'):
            if 'platform' not in _cfg.attrib:
                if logger().DEBUG:
                    logger().log("[*] loading common platform config from '{}'..".format(fxml))
            elif code == _cfg.attrib['platform'].lower():
                if logger().DEBUG:
                    logger().log("[*] loading '{}' platform config from '{}'..".format(code, fxml))
                if 'req_pch' in _cfg.attrib:
                    if 'true' == _cfg.attrib['req_pch'].lower():
                        self.req_pch = True
                    if 'false' == _cfg.attrib['req_pch'].lower():
                        self.req_pch = False
            elif pch_code == _cfg.attrib['platform'].lower():
                if logger().DEBUG:
                    logger().log("[*] loading '{}' PCH config from '{}'..".format(pch_code, fxml))
            else:
                continue

            if logger().DEBUG:
                logger().log("[*] loading integrated devices/controllers..")
            self.populate_cfg_type(_cfg, 'pci', self.Cfg.CONFIG_PCI, 'device')

            if logger().DEBUG:
                logger().log("[*] loading MMIO BARs..")
            self.populate_cfg_type(_cfg, 'mmio', self.Cfg.MMIO_BARS, 'bar')

            if logger().DEBUG:
                logger().log("[*] loading I/O BARs..")
            self.populate_cfg_type(_cfg, 'io', self.Cfg.IO_BARS, 'bar')

            if logger().DEBUG:
                logger().log("[*] loading indirect memory accesses definitions..")
            self.populate_cfg_type(_cfg, 'ima', self.Cfg.IO_BARS, 'indirect')

            if logger().DEBUG:
                logger().log("[*] loading memory ranges..")
            self.populate_cfg_type(_cfg, 'memory', self.Cfg.MEMORY_RANGES, 'range')

            if logger().DEBUG:
                logger().log("[*] loading configuration registers..")
            self.populate_cfg_type(_cfg, 'registers', self.Cfg.REGISTERS, 'register')

            if logger().DEBUG:
                logger().log("[*] loading controls..")
            self.populate_cfg_type(_cfg, 'controls', self.Cfg.CONTROLS, 'control')

            if logger().DEBUG:
                logger().log("[*] loading locks..")
            self.populate_cfg_type(_cfg, 'locks', self.Cfg.LOCKS, 'lock')

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
