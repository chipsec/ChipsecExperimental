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

import collections
import os
import xml.etree.ElementTree as ET
from chipsec.logger import logger

from chipsec.defines import is_hex
import chipsec.file

import importlib
import traceback
import fnmatch

LOAD_COMMON = True

CHIPSET_ID_UNKNOWN = 0

CHIPSET_CODE_UNKNOWN = ''

CHIPSET_FAMILY = {}

PCH_CODE_PREFIX = 'PCH_'


class Cfg:
    def __init__(self):
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

    def init_xml_configuration(self):
        # CAVEAT: this method may be called before command-line flags have been
        # parsed. In that case, logger().DEBUG will be False even if `-d` is
        # used. Switch it to True in logger.py directly if you need to debug
        # this function.
        self.pch_dictionary = {}
        self.chipset_dictionary = {}
        self.device_dictionary = {}
        self.chipset_codes = {}
        self.pch_codes = {}
        self.device_code = []
        self.detection_dictionary = {}

        # find VID
        _cfg_path = os.path.join(chipsec.file.get_main_dir(), 'chipsec', 'cfg')
        VID = [f for f in os.listdir(_cfg_path) if os.path.isdir(os.path.join(_cfg_path, f)) and is_hex(f)]
        # create dictionaries
        for vid in VID:
            if logger().DEBUG:
                logger().log("[*] Entering directory '{}'..".format(os.path.join(_cfg_path, vid)))
            self.chipset_dictionary[int(vid, 16)] = collections.defaultdict(list)
            self.pch_dictionary[int(vid, 16)] = collections.defaultdict(list)
            self.device_dictionary[int(vid, 16)] = collections.defaultdict(list)
            for fxml in os.listdir(os.path.join(_cfg_path, vid)):
                if logger().DEBUG:
                    logger().log("[*] looking for platform config in '{}'..".format(fxml))
                tree = ET.parse(os.path.join(_cfg_path, vid, fxml))
                root = tree.getroot()
                for _cfg in root.iter('configuration'):
                    if 'platform' not in _cfg.attrib:
                        if logger().DEBUG:
                            logger().log("[*] skipping common platform config '{}'..".format(fxml))
                        continue
                    elif _cfg.attrib['platform'].lower().startswith('pch'):
                        if logger().DEBUG:
                            logger().log("[*] found PCH config at '{}'..".format(fxml))
                        if not _cfg.attrib['platform'].upper() in self.pch_codes.keys():
                            self.pch_codes[_cfg.attrib['platform'].upper()] = {}
                            self.pch_codes[_cfg.attrib['platform'].upper()]['vid'] = int(vid, 16)
                        mdict = self.pch_dictionary[int(vid, 16)]
                        cdict = self.pch_codes[_cfg.attrib['platform'].upper()]
                    elif _cfg.attrib['platform'].upper():
                        if logger().DEBUG:
                            logger().log("[*] found platform config from '{}'..".format(fxml))
                        if not _cfg.attrib['platform'].upper() in self.chipset_codes.keys():
                            self.chipset_codes[_cfg.attrib['platform'].upper()] = {}
                            self.chipset_codes[_cfg.attrib['platform'].upper()]['vid'] = int(vid, 16)
                        mdict = self.chipset_dictionary[int(vid, 16)]
                        cdict = self.chipset_codes[_cfg.attrib['platform'].upper()]
                    else:
                        continue
                    if logger().DEBUG:
                        logger().log("[*] Populating configuration dictionary..")
                    for _info in _cfg.iter('info'):
                        if 'family' in _info.attrib:
                            family = _info.attrib['family'].lower()
                            if family not in CHIPSET_FAMILY:
                                CHIPSET_FAMILY[family] = []
                            CHIPSET_FAMILY[family].append(_cfg.attrib['platform'].upper())
                        if 'detection_value' in _info.attrib:
                            for dv in list(_info.attrib['detection_value'].split(',')):
                                if dv[-1].upper() == 'X':
                                    rdv = int(dv[:-1], 16) << 4  # Assume valid hex value with last nibble removed
                                    for rdv_value in range(rdv, rdv + 0x10):
                                        self.detection_dictionary[format(rdv_value, 'X')] = _cfg.attrib['platform'].upper()
                                elif '-' in dv:
                                    rdv = dv.split('-')
                                    for rdv_value in range(int(rdv[0], 16), int(rdv[1], 16) + 1):  # Assume valid hex values
                                        self.detection_dictionary[format(rdv_value, 'X')] = _cfg.attrib['platform'].upper()
                                else:
                                    self.detection_dictionary[dv.strip().upper()] = _cfg.attrib['platform'].upper()
                        if _info.find('sku') is not None:
                            _det = ""
                            _did = ""
                            for _sku in _info.iter('sku'):
                                _did = int(_sku.attrib['did'], 16)
                                del _sku.attrib['did']
                                mdict[_did].append(_sku.attrib)
                                if "detection_value" in _sku.attrib.keys():
                                    _det = _sku.attrib['detection_value']
                            if _did == "":
                                if logger().DEBUG:
                                    logger().log_warning("No SKU found in configuration")
                            cdict['did'] = _did
                            cdict['detection_value'] = _det
            for cc in self.chipset_codes:
                globals()["CHIPSET_CODE_{}".format(cc.upper())] = cc.upper()
            for pc in self.pch_codes:
                globals()["PCH_CODE_{}".format(pc[4:].upper())] = pc.upper()

    def platform_detection(self, platform_code, req_pch_code, cpuid, vid, did, rid, pch_vid, pch_did, pch_rid):
        # initialize chipset values to unknown
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
            vid_found = vid in self.chipset_dictionary
            did_found = did in self.chipset_dictionary[vid]
            #check if multiple platform found by [vid][did]
            multiple_found = len(self.chipset_dictionary[vid][did]) > 1
            logger().log_debug("read out cpuid:{}, platforms found per vid & did:{}, multiple:{}".format(cpuid, self.chipset_dictionary[vid][did], multiple_found))
            for i in self.detection_dictionary.keys():
                logger().log_debug("cpuid detection val:{}, plat:{}".format(i, self.detection_dictionary[i]))
            cpuid_found = cpuid in self.detection_dictionary.keys()
            if vid_found and did_found and multiple_found and cpuid_found:
                for item in self.chipset_dictionary[vid][did]:
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
                data_dict = self.chipset_dictionary[vid][did][0]
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

        elif platform_code in self.chipset_codes:
            # Check if platform code passed in is valid and override configuration
            _unknown_platform = False
            self.vid = self.chipset_codes[platform_code]['vid']
            self.did = self.chipset_codes[platform_code]['did']
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
                self.pch_vid = self.pch_codes[req_pch_code]['vid']
                self.pch_did = self.pch_codes[req_pch_code]['did']
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

        if self.req_pch == False:
            self.pch_longname = self.longname
            _unknown_pch = False

        return (_unknown_platform, _unknown_pch)

    ###
    # Platform detection functions
    ###
    def get_pch_code(self):
        return self.pch_code

    def is_pch_req(self):
        return self.req_pch

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
        _cfg_path = os.path.join(chipsec.file.get_main_dir(), 'chipsec/cfg', "{:04X}".format(self.vid))
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
            for plat in [c.lower() for c in self.chipset_codes]:
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
