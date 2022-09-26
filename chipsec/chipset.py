# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2022, Intel Corporation
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
Contains platform identification functions
"""
import errno
import traceback
import typing
from chipsec.helper.oshelper import helper as os_helper
from chipsec.config import CHIPSET_CODE_UNKNOWN, PROC_FAMILY
from chipsec.hal import pci, cpuid, mmio, msr, mmcfg, iobar, io, msgbus, cpu, mm_msgbus, physmem
from chipsec.exceptions import CSReadError, OsHelperError, UnknownChipsetError, RegisterTypeNotFoundError
from chipsec.logger import logger
from chipsec.config import Cfg
from chipsec.helper.basehelper import Helper
from chipsec.defines import RegData
from chipsec.options import Options

# DEBUG Flags
QUIET_PCI_ENUM = True


class RegisterType:
    PCICFG = 'pcicfg'
    MMCFG = 'mmcfg'
    MMIO = 'mmio'
    MSR = 'msr'
    PORTIO = 'io'
    IOBAR = 'iobar'
    MSGBUS = 'msgbus'
    MM_MSGBUS = 'mm_msgbus'
    MEMORY = 'memory'
    IMA = 'indirect'


class Chipset:

    def __init__(self):

        # Initialize configuration and scope
        self.Cfg = Cfg()
        self.options = Options()
        self.logger = logger()

        # Initialize the Helper
        self.helper = Helper()

        # Initialize HAL instanaces to None
        self.set_hal_objects()

    ##################################################################################
    #
    # Initialization
    #
    ##################################################################################

    def set_hal_objects(self):
        self.pci = pci.Pci(self)
        self.mmio = mmio.MMIO(self)
        self.msr = msr.Msr(self)
        self.mmcfg = mmcfg.MMCFG(self)
        self.iobar = iobar.IOBAR(self)
        self.io = io.PortIO(self)
        self.msgbus = msgbus.MsgBus(self)
        self.cpu = cpu.CPU(self)
        self.mm_msgbus = mm_msgbus.MMMsgBus(self)
        self.mem = physmem.Memory(self)

    def get_cpuid_info(self):
        # Get processor version information
        _cpuid = cpuid.CpuID(self)
        return int(_cpuid.get_proc_info(), 16)

    def init(self, platform_code, req_pch_code, helper_name=None, start_helper='True', load_config="True"):
        # Start Helper
        cpuid = None
        # load helper if helper name is in list
        self.loadHelper(helper_name)

        # start the helper
        if start_helper:
            self.startHelper()

        self.Cfg.load_parsers()
        self.Cfg.load_platform_info()
        if load_config:
            self.init_cfg_bus()
            try:
                cpuid = self.get_cpuid_info()
            except Exception:
                cpuid = None

            self.Cfg.platform_detection(platform_code, req_pch_code, cpuid)
            if self.get_chipset_code == CHIPSET_CODE_UNKNOWN:
                raise UnknownChipsetError('Did not identify CPU')
            if self.Cfg.is_pch_req() and self.Cfg.get_pch_code() == CHIPSET_CODE_UNKNOWN:
                raise UnknownChipsetError('Did not identify PCH')

            self.Cfg.load_platform_config()

        # ReInitialize HAL instances with helper
        self.set_hal_objects()

    def loadHelper(self, helper_name):
        if helper_name:
            self.helper = os_helper().getHelper(helper_name)
            if self.helper is None:
                raise OsHelperError('Helper named {} not found in available helpers'.format(helper_name))
        else:
            self.helper = os_helper().getDefaultHelper()

    def startHelper(self):
        try:
            if not self.helper.create():
                raise OsHelperError("failed to create OS helper", 1)
            if not self.helper.start():
                raise OsHelperError("failed to start OS helper", 1)
        except Exception as msg:
            logger().log_debug(traceback.format_exc())
            error_no = errno.ENXIO
            if hasattr(msg, 'errorcode'):
                error_no = msg.errorcode
            raise OsHelperError("Message: \"{}\"".format(msg), error_no)

    def switchHelper(self, helper_name):
        oldName = self.helper.name
        self.destroyHelper(True)
        self.loadHelper(helper_name)
        self.startHelper()
        return oldName

    def destroyHelper(self, start_driver):
        if not self.helper.stop(start_driver):
            logger().log_warning("failed to stop OS helper")
        else:
            if not self.helper.delete(start_driver):
                logger().log_warning("failed to delete OS helper")

    def get_chipset_code(self):
        return self.Cfg.code

    def is_core(self):
        if 'core' in PROC_FAMILY:
            return self.get_chipset_code() in PROC_FAMILY["core"]
        else:
            return False

    def is_server(self):
        if 'xeon' in PROC_FAMILY:
            return self.get_chipset_code() in PROC_FAMILY["xeon"]
        else:
            return False

    def is_atom(self):
        if 'atom' in PROC_FAMILY:
            return self.get_chipset_code() in PROC_FAMILY["atom"]
        else:
            return False

    def print_supported_chipsets(self):
        fmtStr = " {:4} | {:4} | {:14} | {:6} | {:40}"
        self.logger.log("\nSupported platforms:\n")
        self.logger.log(fmtStr.format("VID", "DID", "Name", "Code", "Long Name"))
        self.logger.log("-" * 85)
        for _vid in sorted(self.Cfg.proc_dictionary):
            for _did in sorted(self.Cfg.proc_dictionary[_vid]):
                for item in self.Cfg.proc_dictionary[_vid][_did]:
                    self.logger.log(fmtStr.format(_vid, _did, item['name'], item['code'].lower(), item['longname'][:40]))

    def init_cfg_bus(self):
        _pci = pci.Pci(self)
        self.logger.log_debug('[*] Loading device buses..')
        if QUIET_PCI_ENUM:
            old_log_state = (self.logger.HAL, self.logger.DEBUG, self.logger.VERBOSE)
            self.logger.HAL, self.logger.DEBUG, self.logger.VERBOSE = (False, False, False)
            self.logger.setlevel()
        try:
            enum_devices = _pci.enumerate_devices()
        except Exception:
            self.logger.log_debug('[*] Unable to enumerate PCI devices.')
            enum_devices = []
        if QUIET_PCI_ENUM:
            self.logger.HAL, self.logger.DEBUG, self.logger.VERBOSE = old_log_state
            self.logger.setlevel()
        self.Cfg.set_pci_data(enum_devices)

##################################################################################
#
# Main functionality to read/write configuration registers
# based on their XML configuration
##################################################################################
    def is_device_enabled(self, dev_name: str, instance: int) -> bool:
        if self.Cfg.is_device_defined(dev_name):
            (_, d, f) = self.Cfg.get_device_BDF(dev_name)
            return not self.pci.get_DIDVID(instance, d, f) == (0xFFFF, 0xFFFF)
        return False

    def is_register_valid(self, reg_name: str, instance: typing.Optional[int] = None) -> bool:
        is_valid = False
        # HACK @TODO should check for valid bus and that's all
        try:
            _ = self.read_register(reg_name, instance)
            is_valid = True
        except CSReadError:
            pass
        return is_valid

    # Return a list of (register values read, instance)
    # If instance is not decleared will return values for each instance that can be found on the system
    def read_register(self, reg_name: str, instance: typing.Optional[int] = None) -> typing.List[typing.Type[RegData]]:
        reg = self.Cfg.get_register_def(reg_name)
        rtype = reg['type']
        reg_value = []
        if rtype in [RegisterType.MMCFG, RegisterType.PCICFG]:
            if instance is not None and instance in reg['bus']:
                _bus = [instance]
            elif instance is None and len(reg['bus']) > 0:
                _bus = reg['bus']
            elif instance is not None and instance not in reg['bus']:
                raise CSReadError('Bus {} is not active. Please specify another device {}'.format(instance, reg['bus']))
            else:
                raise CSReadError('Device has no active Buses')
            for b in _bus:
                d = reg['dev']
                f = reg['fun']
                o = reg['offset']
                size = reg['size']
                if self.pci.get_DIDVID(b, d, f) == (0xFFFF, 0xFFFF):
                    raise CSReadError("PCI Device is not available ({}:{}.{})".format(b, d, f))
                if RegisterType.PCICFG == rtype:
                    if 1 == size:
                        reg_value.append(RegData(self.pci.read_byte(b, d, f, o), b))
                    elif 2 == size:
                        reg_value.append(RegData(self.pci.read_word(b, d, f, o), b))
                    elif 4 == size:
                        reg_value.append(RegData(self.pci.read_dword(b, d, f, o), b))
                    elif 8 == size:
                        reg_value.append(RegData((self.pci.read_dword(b, d, f, o + 4) << 32) | self.pci.read_dword(b, d, f, o), b))
                elif RegisterType.MMCFG == rtype:
                    reg_value.append(RegData(self.mmcfg.read_mmcfg_reg(b, d, f, o, size), b))
        elif rtype in [RegisterType.MMIO, RegisterType.IOBAR]:
            if instance is None:
                _bus = self.Cfg.get_device_bus(reg['bar'])
                if not _bus:
                    # need to check for fixed address
                    _bus = [None]
            else:
                _bus = [instance]
            if RegisterType.MMIO == rtype:
                for b in _bus:
                    (bar_base, bar_size) = self.mmio.get_MMIO_BAR_base_address(reg['bar'], b)
                    if bar_base != 0:
                        reg_value.append(RegData(self.mmio.read_MMIO_reg(bar_base, reg['offset'],
                                         reg['size'], bar_size), b))
                    else:
                        raise CSReadError("MMIO Bar ({}) base address is 0".format(reg['bar']))
            elif RegisterType.IOBAR == rtype:
                for b in _bus:
                    (bar_base, bar_size) = self.iobar.get_IO_BAR_base_address(reg['bar'], b)
                    if bar_base != 0:
                        io_port = bar_base + reg['offset']
                        if reg['offset'] > bar_size:
                            self.logger.log_hal('offset 0x{:X} is outside {} size (0x{:X})'.format(
                                reg['offset'], reg_name, reg['size']))
                        reg_value.append(RegData(self.io.read_port(io_port, reg['size']), b))
                    else:
                        raise CSReadError("IO Bar ({}) base address is 0".format(reg['bar']))
        elif RegisterType.MSR == rtype:
            if instance is None:
                threads_to_use = self.msr.get_threads_from_scope(reg['scope'] if 'scope' in reg else None)
            else:
                threads_to_use = [instance]
            for thread in threads_to_use:
                (eax, edx) = self.msr.read_msr(thread, reg['msr'])
                reg_value.append(RegData((edx << 32) | eax, thread))
        elif RegisterType.PORTIO == rtype:
            port = reg['port']
            size = reg['size']
            reg_value.append(RegData(self.io.read_port(port, size), None))
        elif RegisterType.MSGBUS == rtype:
            reg_value.append(RegData(self.msgbus.msgbus_reg_read(reg['port'], reg['offset']), None))
        elif RegisterType.MM_MSGBUS == rtype:
            reg_value.append(RegData(self.mm_msgbus.reg_read(reg['port'], reg['offset']), None))
        elif RegisterType.MEMORY == rtype:
            if reg['access'] == 'dram':
                size = reg['size']
                if 1 == size:
                    reg_value.append(RegData(self.mem.read_physical_mem_byte(reg['address']), None))
                elif 2 == size:
                    reg_value.append(RegData(self.mem.read_physical_mem_word(reg['address']), None))
                elif 4 == size:
                    reg_value.append(RegData(self.mem.read_physical_mem_dword(reg['address']), None))
                elif 8 == size:
                    reg_value.append(RegData(self.mem.read_physical_mem_qword(reg['address']), None))
            elif reg['access'] == 'mmio':
                reg_value.append(RegData(self.mmio.read_MMIO_reg(
                    reg['address'], reg['offset'], reg['size']), None))
        # @TODO FIXUP
        elif RegisterType.IMA == rtype:
            self.write_register(reg['index'], reg['offset'] + reg['base'])
            reg_value = self.read_register(reg['data'])
        else:
            raise RegisterTypeNotFoundError("Register type not found: {}".format(rtype))
        return reg_value

    def write_register(self, reg_name: str, reg_value: typing.List[int], instance: typing.Optional[int] = None) -> bool:
        if not isinstance(reg_value, list):
            raise CSReadError("reg_value needs to be a list")
        reg = self.Cfg.get_register_def(reg_name)
        rtype = reg['type']
        if rtype in [RegisterType.MMCFG, RegisterType.PCICFG]:
            if instance is not None and instance in reg['bus']:
                _bus = [instance]
            elif instance is None and len(reg['bus']) > 0:
                _bus = reg['bus']
            elif instance is not None and instance not in reg['bus']:
                raise CSReadError('Bus {} is not active. Please specify another device {}'.format(instance, reg['bus']))
            else:
                raise CSReadError('Device has no active Buses')
            if len(reg_value) == 1 or len(reg_value) == len(_bus):
                for index, b in enumerate(_bus):
                    rv = reg_value[0] if len(reg_value) == 1 else reg_value[index]
                    d = reg['dev']
                    f = reg['fun']
                    o = reg['offset']
                    size = reg['size']
                    if RegisterType.PCICFG == rtype:
                        if 1 == size:
                            self.pci.write_byte(b, d, f, o, rv)
                        elif 2 == size:
                            self.pci.write_word(b, d, f, o, rv)
                        elif 4 == size:
                            self.pci.write_dword(b, d, f, o, rv)
                        elif 8 == size:
                            self.pci.write_dword(b, d, f, o, (rv & 0xFFFFFFFF))
                            self.pci.write_dword(b, d, f, o + 4, (rv >> 32 & 0xFFFFFFFF))
                    elif RegisterType.MMCFG == rtype:
                        self.mmcfg.write_mmcfg_reg(b, d, f, o, size, rv)
            else:
                raise CSReadError("For {}, reg value must be a list of size 1 or size {}".format(reg_name, len(_bus)))
        elif rtype in [RegisterType.MMIO, RegisterType.IOBAR]:
            if instance is None:
                _bus = self.Cfg.get_device_bus(reg['bar'])
                if not _bus:
                    # need to check for fixed address
                    _bus = [None]
            else:
                _bus = [instance]
            if len(reg_value) == 1 or len(reg_value) == len(_bus):
                if RegisterType.MMIO == rtype:
                    for index, b in enumerate(_bus):
                        rv = reg_value[0] if len(reg_value) == 1 else reg_value[index]
                        (bar_base, bar_size) = self.mmio.get_MMIO_BAR_base_address(reg['bar'], b)
                        if bar_base != 0:
                            self.mmio.write_MMIO_reg(bar_base, reg['offset'], rv, reg['size'], bar_size)
                        else:
                            raise CSReadError("MMIO Bar ({}) base address is 0".format(reg['bar']))
                elif RegisterType.IOBAR == rtype:
                    for index, b in enumerate(_bus):
                        rv = reg_value[0] if len(reg_value) == 1 else reg_value[index]
                        (bar_base, bar_size) = self.iobar.get_IO_BAR_base_address(reg['bar'], b)
                        if bar_base != 0:
                            io_port = bar_base + reg['offset']
                            if reg['offset'] > bar_size:
                                self.logger.log_hal('offset 0x{:X} is outside {} size (0x{:X})'.format(
                                    reg['offset'], reg_name, reg['size']))
                            reg_value.append(self.io.write_port(io_port, rv, reg['size']))
                        else:
                            raise CSReadError("IO Bar ({}) base address is 0".format(reg['bar']))
            else:
                raise CSReadError("For {}, reg value must be a list of size 1 or size {}".format(reg_name, len(_bus)))
        elif RegisterType.MSR == rtype:
            if instance is None:
                threads_to_use = self.msr.get_threads_from_scope(reg['scope'] if 'scope' in reg.keys() else None)
            else:
                threads_to_use = [instance]
            if len(reg_value) == 1 or len(reg_value) == len(threads_to_use):
                for index, thread in enumerate(threads_to_use):
                    rv = reg_value[0] if len(reg_value) == 1 else reg_value[index]
                    eax = (rv & 0xFFFFFFFF)
                    edx = ((rv >> 32) & 0xFFFFFFFF)
                    self.msr.write_msr(thread, reg['msr'], eax, edx)
            else:
                raise CSReadError("For {}, reg value must be a list of size 1 or size {}".format(reg_name, len(threads_to_use)))
        elif RegisterType.PORTIO == rtype:
            if len(reg_value) == 1:
                port = reg['port']
                size = reg['size']
                self.io.write_port(port, reg_value[0], size)
            else:
                raise CSReadError("For {}, reg value must be a list of size 1".format(reg_name))
        elif RegisterType.IOBAR == rtype:
            if len(reg_value) == 1:
                self.iobar.write_IO_BAR_reg(reg['bar'], reg['offset'], reg['size'], reg_value[0])
            else:
                raise CSReadError("For {}, reg value must be a list of size 1".format(reg_name))
        elif RegisterType.MSGBUS == rtype:
            if len(reg_value) == 1:
                self.msgbus.msgbus_reg_write(reg['port'], reg['offset'], reg_value[0])
            else:
                raise CSReadError("For {}, reg value must be a list of size 1".format(reg_name))
        elif RegisterType.MM_MSGBUS == rtype:
            if len(reg_value) == 1:
                self.mm_msgbus.reg_write(reg['port'], reg['offset'], reg_value[0])
            else:
                raise CSReadError("For {}, reg value must be a list of size 1".format(reg_name))
        elif RegisterType.MEMORY == rtype:
            if len(reg_value) == 1:
                if reg['access'] == 'dram':
                    self.mem.write_physical_mem(reg['address'], reg['size'], reg_value[0])
                elif reg['access'] == 'mmio':
                    self.mmio.write_MMIO_reg(reg['address'],
                                             reg['offset'], reg_value[0], reg['size'])
            else:
                raise CSReadError("For {}, reg value must be a list of size 1".format(reg_name))
        # @TODO FIXUP
        elif RegisterType.IMA == rtype:
            self.write_register(reg['index'], reg['offset'] + reg['base'])
            self.write_register(reg['data'], reg_value)
        else:
            raise RegisterTypeNotFoundError("Register type not found: {}".format(rtype))
        return True

    def set_register_field(self, reg_name: str, reg_value: int, field_name: str,
                           field_value: int, preserve_field_position: typing.Optional[bool] = False) -> int:
        field_attrs = self.Cfg.get_register_def(reg_name)['FIELDS'][field_name]
        field_bit = field_attrs['bit']
        field_mask = (1 << field_attrs['size']) - 1
        reg_value &= ~(field_mask << field_bit)  # keep other fields
        if preserve_field_position:
            reg_value |= (field_value & (field_mask << field_bit))
        else:
            reg_value |= ((field_value & field_mask) << field_bit)
        return reg_value

    def write_register_field(self, reg_name: str, field_name: str, field_value: int, preserve_field_position: typing.Optional[bool] = False, instance: typing.Optional[int] = None) -> bool:
        try:
            reg_value = self.read_register(reg_name, instance)
            reg_value_new = []
            for regdata in reg_value:
                reg_value_new.append(self.set_register_field(reg_name, regdata.value, field_name, field_value, preserve_field_position))
            ret = self.write_register(reg_name, reg_value_new, instance)
        except Exception:
            ret = None
        return ret

    def print_register(self, reg_name: str, reg_data: typing.Type[RegData]) -> None:
        reg = self.Cfg.get_register_def(reg_name)
        rtype = reg['type']
        reg_str = ''
        if 'size' in reg:
            reg_val_str = "0x{:0{width}X}".format(reg_data.value, width=(reg['size'] * 2))
        else:
            reg_val_str = "0x{:08X}".format(reg_data.value)
        if RegisterType.PCICFG == rtype or RegisterType.MMCFG == rtype:
            b = reg_data.instance
            d = reg['dev']
            f = reg['fun']
            o = reg['offset']
            mmcfg_off_str = ''
            if RegisterType.MMCFG == rtype:
                mmcfg_off_str += ", MMCFG + 0x{:X}".format((b * 32 * 8 + d * 8 + f) * 0x1000 + o)
            reg_str = "[*] {} = {} << {} (b:d.f {:02d}:{:02d}.{:d} + 0x{:X}{})".format(
                reg_name, reg_val_str, reg['desc'], b, d, f, o, mmcfg_off_str)
        elif RegisterType.MMIO == rtype:
            reg_str = "[*] {} = {} << {} ({} + 0x{:X} Bus 0x{:X})".format(
                reg_name, reg_val_str, reg['desc'], reg['bar'], reg['offset'], reg_data.instance)
        elif RegisterType.MSR == rtype:
            reg_str = "[*] {} = {} << {} (MSR 0x{:X} Thread 0x{:X})".format(
                reg_name, reg_val_str, reg['desc'], reg['msr'], reg_data.instance)
        elif RegisterType.PORTIO == rtype:
            reg_str = "[*] {} = {} << {} (I/O port 0x{:X})".format(reg_name, reg_val_str, reg['desc'], reg['port'])
        elif RegisterType.IOBAR == rtype:
            reg_str = "[*] {} = {} << {} (I/O {} + 0x{:X}) Bus 0x{:X}".format(
                reg_name, reg_val_str, reg['desc'], reg['bar'], reg['offset'], reg_data.instance)
        elif RegisterType.MSGBUS == rtype or RegisterType.MM_MSGBUS == rtype:
            reg_str = "[*] {} = {} << {} (msgbus port 0x{:X}, off 0x{:X})".format(
                reg_name, reg_val_str, reg['desc'], reg['port'], reg['offset'])
        elif RegisterType.IMA == rtype:
            reg_str = "[*] {} = {} << {} (indirect access via {}/{}, base 0x{:X}, off 0x{:X})".format(
                reg_name, reg_val_str, reg['desc'], reg['index'], reg['data'], reg['base'], reg['offset'])
        elif RegisterType.MEMORY == rtype:
            reg_str = "[*] {} = {} << {} ({} + {})".format(reg_name, reg_val_str, reg['desc'], reg['address'], reg['offset'])
        else:
            reg_str = "[*] {} = {} << {}".format(reg_name, reg_val_str, reg['desc'])

        reg_str += self._register_fields_str(reg, reg_data.value)
        self.logger.log(reg_str)
        return reg_str

    def _register_fields_str(self, reg_def: str, reg_val: typing.Type[RegData]) -> str:
        reg_fields_str = ''
        if 'FIELDS' in reg_def:
            reg_fields_str += '\n'
            # sort fields by their bit position in the register
            sorted_fields = sorted(reg_def['FIELDS'].items(), key=lambda field: field[1]['bit'])
            for f in sorted_fields:
                field_attrs = f[1]
                field_bit = field_attrs['bit']
                field_size = field_attrs['size']
                field_mask = 0
                for _ in range(field_size):
                    field_mask = (field_mask << 1) | 1
                field_value = (reg_val >> field_bit) & field_mask
                field_desc = (' << ' + field_attrs['desc'] + ' ') if (field_attrs['desc'] != '') else ''
                reg_fields_str += ("    [{:02d}] {:16} = {:X}{}\n".format(field_bit, f[0], field_value, field_desc))

        if '' != reg_fields_str:
            reg_fields_str = reg_fields_str[:-1]
        return reg_fields_str

    def get_register_field(self, reg_name: str, reg_value: int, field_name: str,
                           preserve_field_position: typing.Optional[bool] = False) -> int:
        field_attrs = self.Cfg.get_register_def(reg_name)['FIELDS'][field_name]
        field_bit = field_attrs['bit']
        field_mask = (1 << field_attrs['size']) - 1
        if preserve_field_position:
            return reg_value & (field_mask << field_bit)
        else:
            return (reg_value >> field_bit) & field_mask

    def get_register_field_mask(self, reg_name: str, reg_field: typing.Optional[str] = None,
                                preserve_field_position: typing.Optional[bool] = False) -> int:
        reg_def = self.Cfg.get_register_def(reg_name)
        if reg_field is not None:
            field_attrs = reg_def['FIELDS'][reg_field]
            mask_start = field_attrs['bit']
            mask = (1 << field_attrs['size']) - 1
        else:
            mask_start = 0
            mask = (1 << (reg_def['size'] * 8)) - 1
        if preserve_field_position:
            return mask << mask_start
        else:
            return mask

    def read_register_field(self, reg_name: str, field_name: str, preserve_field_position: typing.Optional[bool] = False, instance: typing.Optional[int] = None) -> typing.List[typing.Type[RegData]]:
        reg_value = self.read_register(reg_name, instance)
        field_value = []
        for rv in reg_value:
            field_value.append(RegData(self.get_register_field(reg_name, rv.value, field_name, preserve_field_position), rv.instance))
        return field_value

    def get_control(self, control_name: str, instance: typing.Optional[int] = None, with_print: typing.Optional[bool] = False) -> typing.List[typing.Type[RegData]]:
        control = self.Cfg.get_control_def(control_name)
        reg = control['register']
        field = control['field']
        desc = control['desc']
        reg_data = self.read_register(reg, instance)
        ctrl_data = []
        for regdata in reg_data:
            value = self.get_register_field(reg, regdata.value, field)
            ctrl_data.append(RegData(value, regdata.instance))
            if self.logger.VERBOSE or with_print:
                self.logger.log("    {}: {}".format(desc, value))
        return ctrl_data

    def set_control(self, control_name: str, control_value: typing.List[int], instance: typing.Optional[int] = None) -> bool:
        control = self.Cfg.get_control_def(control_name)
        reg = control['register']
        field = control['field']
        return self.write_register_field(reg, field, control_value, instance)

    def is_control_valid(self, control_name: str) -> bool:
        control = self.Cfg.get_control_def(control_name)
        reg = control['register']
        return self.is_register_valid(reg)

    def is_all_value(self, regdata: typing.Type[RegData], value: int, mask: typing.Optional[int] = None) -> bool:
        if mask is None:
            return all(n.value == value for n in regdata)
        else:
            newvalue = value & mask
            return all((n.value & mask) == newvalue for n in regdata)

    def is_any_value(self, regdata: typing.Type[RegData], value: int, mask: typing.Optional[int] = None) -> bool:
        if mask is None:
            return any(n.value == value for n in regdata)
        else:
            newvalue = value & mask
            return any((n.value & mask) == newvalue for n in regdata)

    def get_lock(self, lock_name, instance=None, with_print=False):
        lock = self.Cfg.LOCKS[lock_name]
        reg = lock['register']
        field = lock['field']
        reg_data = self.read_register_field(reg, field, False, instance)
        return reg_data

    def set_lock(self, lock_name, lock_value, instance=None):
        ret = True
        lock = self.Cfg.LOCKS[lock_name]
        reg = lock['register']
        field = lock['field']
        reg_data_list = self.read_register(reg, instance)
        for reg_data in reg_data_list:
            new_data = self.set_register_field(reg, reg_data.value, field, lock_value)
            ret = ret and self.write_register(reg, [new_data], reg_data.instance)
        return ret

    def get_lock_mask(self, lock_name):
        lock = self.Cfg.LOCKS[lock_name]
        reg = lock['register']
        field = lock['field']
        return(self.get_register_field_mask(reg, field))

    #####
    # Scoping functions
    #####
    def set_scope(self, scope):
        self.Cfg.set_scope(scope)

    def clear_scope(self):
        self.Cfg.clear_scope()


_chipset = None


def cs():
    global _chipset
    if _chipset is None:
        _chipset = Chipset()
    return _chipset
