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

parsers = [PlatformInfo]
