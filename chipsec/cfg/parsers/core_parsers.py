# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2022, Intel Corporation
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

import copy
import os
from chipsec.parsers import BaseConfigParser
from chipsec.parsers import Stage
from chipsec.parsers import info_data, config_data

CONFIG_TAG = 'configuration'


def _get_range_data(xml_node, attr):
    int_items = []
    for item in xml_node.attrib[attr].split(','):
        item = item.strip()
        if item.upper().endswith('*'):
            x = int(item.replace('*', '0'), 0)
            int_items.extend(range(x, x + 0x10))
        elif '-' in item:
            item_min, item_max = item.split('-', 1)
            int_items.extend(range(int(item_min, 0), int(item_max, 0) + 1))
        else:
            int_items.append(int(item, 0))
    return int_items


def _config_convert_data(xml_node, did_is_range=False):
    INT_KEYS = ['dev', 'fun', 'vid', 'did', 'rid', 'offset',
                'bit', 'size', 'port', 'msr', 'value', 'address',
                'fixed_address', 'base_align', 'align_bits', 'mask',
                'reg_align', 'limit_align', 'regh_align']
    BOOL_KEYS = ['req_pch']
    INT_LIST_KEYS = ['bus']
    STR_LIST_KEYS = ['config']
    RANGE_LIST_KEYS = ['detection_value']
    if did_is_range:
        INT_KEYS.remove('did')
        RANGE_LIST_KEYS.append('did')
    node_data = {}
    for key in xml_node.attrib:
        if key in INT_KEYS:
            node_data[key] = int(xml_node.attrib[key], 0)
        elif key in INT_LIST_KEYS:
            node_data[key] = [int(xml_node.attrib[key], 0)]
        elif key in STR_LIST_KEYS:
            node_data[key] = [x.strip() for x in xml_node.attrib[key].split(',')]
        elif key in RANGE_LIST_KEYS:
            node_data[key] = _get_range_data(xml_node, key)
        elif key in BOOL_KEYS:
            node_data[key] = xml_node.attrib[key].lower() == 'true'
        else:
            node_data[key] = xml_node.attrib[key]
    return node_data


class PlatformInfo(BaseConfigParser):
    def get_metadata(self):
        return {'info': self.handle_info}

    def get_stage(self):
        return Stage.GET_INFO

    def handle_info(self, et_node, stage_data):
        platform = ''
        req_pch = False
        family = None
        proc_code = None
        pch_code = None
        detect_vals = []
        sku_data = []
        vid_int = int(stage_data.vid_str, 16)

        # Extract platform information. If no platform found it is just a device entry.
        cfg_info = _config_convert_data(stage_data.configuration)
        if 'platform' in cfg_info:
            platform = cfg_info['platform']
        if 'req_pch' in cfg_info:
            req_pch = cfg_info['req_pch']
        if platform and platform.lower().startswith('pch'):
            pch_code = platform.upper()
        else:
            proc_code = platform.upper()

        # Start processing the <info> tag
        for info in et_node.iter('info'):
            cfg_info = _config_convert_data(info)
            if 'family' in cfg_info:
                family = cfg_info['family']
            if 'detection_value' in cfg_info:
                detect_vals = cfg_info['detection_value']
            for sku in info.iter('sku'):
                sku_info = _config_convert_data(sku)
                if 'code' not in sku_info or sku_info['code'] != platform.upper():
                    sku_info['code'] = platform.upper()
                if 'vid' not in sku_info:
                    sku_info['vid'] = vid_int
                sku_data.append(sku_info)

        return info_data(family, proc_code, pch_code, detect_vals, req_pch, stage_data.vid_str, sku_data)


class DevConfig(BaseConfigParser):
    def get_metadata(self):
        return {'pci': self.handle_pci,
                'memory': self.handle_memory,
                'mm_msgbus': self.handle_mm_msgbus,
                'msgbus': self.handle_msgbus,
                'io': self.handle_io,
                'msr': self.handle_msr}

    def get_stage(self):
        return Stage.DEVICE_CFG

    def _process_pci_dev(self, vid_str, dev_name, dev_attr):
        if 'did' in dev_attr:
            for did in dev_attr['did']:
                did_str = self.cfg._make_hex_key_str(did)
                if did_str in self.cfg.CONFIG_PCI_RAW[vid_str]:
                    pci_data = self.cfg.CONFIG_PCI_RAW[vid_str][did_str]
                    self._add_dev(vid_str, dev_name, pci_data, dev_attr)
                    break
        else:
            for did_str in self.cfg.CONFIG_PCI_RAW[vid_str]:
                pci_data = self.cfg.CONFIG_PCI_RAW[vid_str][did_str]
                if dev_attr['bus'] == pci_data['bus'] and dev_attr['dev'] == pci_data['dev'] and \
                   dev_attr['fun'] == pci_data['fun']:
                    self._add_dev(vid_str, dev_name, pci_data, dev_attr)
                    break
        if dev_name not in self.cfg.CONFIG_PCI[vid_str]:
            self._add_dev(vid_str, dev_name, None, dev_attr)

    def _add_dev(self, vid_str, name, pci_info, dev_attr):
        if name not in self.cfg.CONFIG_PCI[vid_str]:
            for key in ['MMIO_BARS', 'IO_BARS', 'REGISTERS']:
                node = getattr(self.cfg, key)
                if name not in node[vid_str]:
                    node[vid_str][name] = {}
            if pci_info:
                self.cfg.CONFIG_PCI[vid_str][name] = copy.copy(pci_info)
            else:
                self.cfg.CONFIG_PCI[vid_str][name] = copy.deepcopy(dev_attr)
                self.cfg.CONFIG_PCI[vid_str][name]['bus'] = []
                if 'did' in dev_attr:
                    self.cfg.CONFIG_PCI[vid_str][name]['did'] = dev_attr['did'][0]
            self.cfg.CONFIG_PCI[vid_str][name]['config'] = []
        if 'config' in dev_attr:
            self.cfg.CONFIG_PCI[vid_str][name]['config'].extend(dev_attr['config'])

    def _process_def(self, dest, et_node, tag, stage_data):
        ret_val = []
        vid_str = stage_data.vid_str

        for node in et_node.iter(tag):
            node_attr = _config_convert_data(node)
            if 'name' not in node_attr or 'config' not in node_attr:
                continue
            dev_name = node_attr['name']
            if dev_name not in dest[vid_str]:
                dest[vid_str][dev_name] = copy.deepcopy(node_attr)
            else:
                dest[vid_str][dev_name]['config'].extend(node_attr['config'])
            ret_val.extend(self._process_config(stage_data, dev_name, node_attr))
            self.logger.log_debug('    + {:16}: {}'.format(node_attr['name'], node_attr))

        return ret_val

    def _process_config(self, stage_data, dev_name, dev_attr):
        ret_val = []

        if 'config' in dev_attr:
            for fxml in dev_attr['config']:
                cfg_file = fxml.replace('.', os.path.sep, fxml.count('.') - 1)
                cfg_path = os.path.join(os.path.dirname(stage_data.xml_file), cfg_file)
                ret_val.append(config_data(stage_data.vid_str, dev_name, cfg_path))

        return ret_val

    def handle_pci(self, et_node, stage_data):
        ret_val = []

        for dev in et_node.iter('device'):
            dev_attr = _config_convert_data(dev, True)
            if 'name' not in dev_attr:
                continue
            dev_name = dev_attr['name']
            self._process_pci_dev(stage_data.vid_str, dev_name, dev_attr)
            ret_val.extend(self._process_config(stage_data, dev_name, dev_attr))
            self.logger.log_debug('    + {:16}: {}'.format(dev_attr['name'], dev_attr))

        return ret_val

    def handle_memory(self, et_node, stage_data):
        return self._process_def(self.cfg.MEMORY_RANGES, et_node, 'range', stage_data)

    def handle_mm_msgbus(self, et_node, stage_data):
        return self._process_def(self.cfg.MM_MSGBUS, et_node, 'definition', stage_data)

    def handle_msgbus(self, et_node, stage_data):
        return self._process_def(self.cfg.MSGBUS, et_node, 'definition', stage_data)

    def handle_io(self, et_node, stage_data):
        return self._process_def(self.cfg.IO, et_node, 'definition', stage_data)

    def handle_msr(self, et_node, stage_data):
        return self._process_def(self.cfg.MSR, et_node, 'definition', stage_data)


class CoreConfig(BaseConfigParser):
    def get_metadata(self):
        return {'mmio': self.handle_mmio,
                'io': self.handle_io,
                'ima': self.handle_ima,
                'registers': self.handle_registers,
                'controls': self.handle_controls,
                'locks': self.handle_locks}

    def get_stage(self):
        return Stage.CORE_SUPPORT

    def _make_reg_name(self, stage_data, reg_name):
        return '.'.join([stage_data.vid_str, stage_data.dev_name, reg_name])

    def _add_entry_simple(self, dest, stage_data, et_node, node_name):
        flat_storage = ['control']
        index_data = ['ima']
        for node in et_node.iter(node_name):
            attrs = _config_convert_data(node)

            # Update storage information
            if node_name in index_data:
                attrs['index'] = self._make_reg_name(stage_data, attrs['index'])
                attrs['data'] = self._make_reg_name(stage_data, attrs['data'])
            else:
                attrs['register'] = self._make_reg_name(stage_data, attrs['register'])

            if 'base_reg' in attrs:
                attrs['base_reg'] = self._make_reg_name(stage_data, attrs['base_reg'])

            if 'mmio_base' in attrs:
                attrs['mmio_base'] = self._make_reg_name(stage_data, attrs['mmio_base'])
            if 'limit_register' in attrs:
                attrs['limit_register'] = self._make_reg_name(stage_data, attrs['limit_register'])

            # Update storage location with new data
            if node_name in flat_storage:
                dest[attrs['name']] = attrs
            else:
                if stage_data.vid_str not in dest:
                    dest[stage_data.vid_str] = {}
                if stage_data.dev_name not in dest[stage_data.vid_str]:
                    dest[stage_data.vid_str][stage_data.dev_name] = {}
                dest[stage_data.vid_str][stage_data.dev_name][attrs['name']] = attrs
            self.logger.log_debug('    + {:16}: {}'.format(attrs['name'], attrs))

    def handle_mmio(self, et_node, stage_data):
        self._add_entry_simple(self.cfg.MMIO_BARS, stage_data, et_node, 'bar')

    def handle_io(self, et_node, stage_data):
        self._add_entry_simple(self.cfg.IO_BARS, stage_data, et_node, 'bar')

    def handle_ima(self, et_node, stage_data):
        self._add_entry_simple(self.cfg.IMA_REGISTERS, stage_data, et_node, 'ima')

    def handle_registers(self, et_node, stage_data):
        for reg in et_node.iter('register'):
            reg_attr = _config_convert_data(reg)
            reg_name = reg_attr['name']

            # Create register storage location if needed and store data
            if stage_data.vid_str not in self.cfg.REGISTERS:
                self.cfg.REGISTERS[stage_data.vid_str] = {}
            if stage_data.dev_name not in self.cfg.REGISTERS[stage_data.vid_str]:
                self.cfg.REGISTERS[stage_data.vid_str][stage_data.dev_name] = {}

            # Patch missing or incorrect data
            if 'desc' not in reg_attr:
                reg_attr['desc'] = reg_name
            if reg_attr['type'] in ['pcicfg', 'mmcfg', 'mm_msg_bus']:
                reg_attr['device'] = stage_data.dev_name
            elif reg_attr['type'] in ['memory']:
                reg_attr['range'] = stage_data.dev_name
            elif reg_attr['type'] in ['mmio', 'iobar']:
                reg_attr['bar'] = self._make_reg_name(stage_data, reg_attr['bar'])

            # Get existing field data
            if reg_name in self.cfg.REGISTERS[stage_data.vid_str][stage_data.dev_name]:
                reg_fields = self.cfg.REGISTERS[stage_data.vid_str][stage_data.dev_name][reg_name]['FIELDS']
            else:
                reg_fields = {}

            for field in reg.iter('field'):
                field_attr = _config_convert_data(field)
                field_name = field_attr['name']

                # Locked by attributes need to be handled here due to embedding information in field data
                if 'lockedby' in field_attr:
                    if field_attr['lockedby'].count('.') == 3:
                        lockedby = field_attr['lockedby']
                    elif field_attr['lockedby'].count('.') <= 1:
                        lockedby = self._make_reg_name(stage_data, field_attr['lockedby'])
                    else:
                        self.logger.log_debug('[*] Invalid locked by reference: {}'.format(field_attr['lockedby']))
                        lockedby = None
                    if lockedby:
                        if lockedby in self.cfg.LOCKEDBY[stage_data.vid_str]:
                            self.cfg.LOCKEDBY[stage_data.vid_str][lockedby].append({reg_name, field_name})
                        else:
                            self.cfg.LOCKEDBY[stage_data.vid_str][lockedby] = [{reg_name, field_name}]

                # Handle rest of field data here
                if 'desc' not in field_attr:
                    field_attr['desc'] = field_name
                reg_fields[field_name] = field_attr

            # Store all register data
            reg_attr['FIELDS'] = reg_fields
            self.cfg.REGISTERS[stage_data.vid_str][stage_data.dev_name][reg_name] = reg_attr
            self.logger.log_debug('    + {:16}: {}'.format(reg_name, reg_attr))

    def handle_controls(self, et_node, stage_data):
        self._add_entry_simple(self.cfg.CONTROLS, stage_data, et_node, 'control')

    def handle_locks(self, et_node, stage_data):
        for node in et_node.iter('lock'):
            attrs = _config_convert_data(node)
            attrs['register'] = self._make_reg_name(stage_data, attrs['register'])
            dest_name = attrs['register']
            if 'field' in attrs:
                dest_name = '.'.join([dest_name, attrs['field']])
            self.cfg.LOCKS[dest_name] = attrs
            self.logger.log_debug('    + {:16}: {}'.format(dest_name, attrs))


parsers = [PlatformInfo, DevConfig, CoreConfig]
