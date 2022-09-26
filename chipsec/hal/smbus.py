# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2019-2022, Intel Corporation

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
Access to SMBus Controller
"""

from chipsec.hal import hal_base
from chipsec.exceptions import IOBARNotFoundError, RegisterNotFoundError

SMBUS_COMMAND_QUICK = 0
SMBUS_COMMAND_BYTE = 1
SMBUS_COMMAND_BYTE_DATA = 2
SMBUS_COMMAND_WORD_DATA = 3
SMBUS_COMMAND_PROCESS_CALL = 4
SMBUS_COMMAND_BLOCK = 5
SMBUS_COMMAND_I2C_READ = 6
SMBUS_COMMAND_BLOCK_PROCESS = 7

SMBUS_POLL_COUNT = 3

SMBUS_COMMAND_WRITE = 0
SMBUS_COMMAND_READ = 1


class SMBus(hal_base.HALBase):

    def __init__(self, cs, i2c_mode=False):
        super(SMBus, self).__init__(cs)
        self.smb_reg_status = '8086.SMBUS.SMBUS_HST_STS'
        self.smb_reg_control = '8086.SMBUS.SMBUS_HST_CNT'
        self.smb_reg_command = '8086.SMBUS.SMBUS_HST_CMD'
        self.smb_reg_address = '8086.SMBUS.SMBUS_HST_SLVA'
        self.smb_reg_data0 = '8086.SMBUS.SMBUS_HST_D0'
        self.smb_reg_data1 = '8086.SMBUS.SMBUS_HST_D1'
        self.smb_reg_aux_ctl = '8086.SMBUS.SMBUS_HST_AUX_CTL'
        self.smb_reg_block_db = '8086.SMBUS.SMBUS_HST_BLOCK_DB'
        self.i2c_mode = i2c_mode
        self.instance = None

    def get_instances(self):
        _bus = self.cs.Cfg.get_device_bus('8086.SMBUS')
        return _bus

    def set_instance(self, instance=None):
        _bus = self.cs.Cfg.get_device_bus('8086.SMBUS')
        if instance is None:
            self.instance = _bus[0]
        elif instance in _bus:
            self.instance = instance
        else:
            raise RegisterNotFoundError('Instance {} is not within supported list {}'.format(instance, _bus))

    def enable(self):
        if not self.is_SMBus_host_controller_enabled():
            self.logger.log_debug("SMBus disabled; enabling...")
            self.enable_SMBus_host_controller()
        if self.i2c_mode is True:
            self.logger.log_debug("i2c mode is selected")
            if not self.is_pch_i2c_enabled():
                print("Intel PCH is not enabled to communicate with i2c devices; enabling...")
                self.enable_pch_i2c_comm()
        else:
            self.logger.log_debug("SMBUS mode is selected. disabling i2c mode")
            if self.is_pch_i2c_enabled():
                print("Intel PCH is enabled to communicate with i2c devices; disabling...")
                self.disable_pch_i2c_comm()
        if not self.is_SMBus_io_mem_space_enabled():
            self.logger.log("SMBus io/mem space disabled; enabling...")
            self.enable_SMBus_io_mem_space()

        if not self.is_SMBus_host_controller_enabled():
            self.logger.log("SMBus disabled; enabling...")
            self.enable_SMBus_host_controller()

    def get_SMBus_Base_Address(self):
        if self.cs.iobar.is_IO_BAR_defined('8086.SMBUS.SMBUS_BASE'):
            (sba_base, _) = self.cs.iobar.get_IO_BAR_base_address('8086.SMBUS.SMBUS_BASE', self.instance)
            return sba_base
        else:
            raise IOBARNotFoundError('IOBARAccessError: SMBUS_BASE')

    def get_SMBus_HCFG(self):
        if self.cs.Cfg.is_register_defined('8086.SMBUS.SMBUS_HCFG'):
            reg_value = self.cs.read_register('8086.SMBUS.SMBUS_HCFG', self.instance)[0]
            if self.logger.HAL:
                self.cs.print_register('8086.SMBUS.SMBUS_HCFG', reg_value)
            return reg_value
        else:
            raise RegisterNotFoundError('RegisterNotFound: SMBUS_HCFG')

    def display_SMBus_info(self):
        self.logger.log("[smbus] SMBus Base Address: 0x{:04X}".format(self.get_SMBus_Base_Address()))
        self.cs.print_register('8086.SMBUS.SMBUS_HCFG', self.get_SMBus_HCFG())

    def is_SMBus_enabled(self):
        return self.cs.is_device_enabled('8086.SMBUS')

    def is_SMBus_supported(self):
        if self.cs.is_device_enabled('8086.SMBUS', self.instance):
            return True
        else:
            return False

    def is_SMBus_host_controller_enabled(self):
        hcfg = self.get_SMBus_HCFG()
        return self.cs.get_register_field("8086.SMBUS.SMBUS_HCFG", hcfg.value, "HST_EN") == 1

    def is_pch_i2c_enabled(self):
        hcfg = self.get_SMBus_HCFG()
        return ((hcfg.value & 4) >> 2) == 1

    def is_SMBus_io_mem_space_enabled(self):
        cmd = self.cs.read_register('8086.SMBUS.SMBUS_CMD', self.instance)[0]
        if self.logger.HAL:
            self.cs.print_register('8086.SMBUS.SMBUS_CMD', cmd)
        return (cmd.value & 0x3) == 0x3

    def enable_SMBus_host_controller(self):
        # Enable SMBus Host Controller Interface in HCFG
        reg_value = self.get_SMBus_HCFG()
        if 0 == (reg_value.value & 0x1):
            self.cs.write_register('8086.SMBUS.SMBUS_HCFG', [(reg_value.value | 0x1)], self.instance)

    def disable_pch_i2c_comm(self):
        # Disable PCH connection to I2c devices
        reg_value = self.cs.read_register('8086.SMBUS.SMBUS_HCFG', self.instance)[0]
        if not 0 == (reg_value.value & 0x04):
            self.cs.write_register('8086.SMBUS.SMBUS_HCFG', [(reg_value.value & ~ 0x4)], self.instance)
        reg_value = self.cs.read_register('8086.SMBUS.SMBUS_HCFG', self.instance)[0]
        if not 0 == (reg_value.value & 0x04):
            self.logger.log("PCH is enabled to connect with i2c devices")
        else:
            self.logger.log("PCH is disabled to connect with i2c devices")

    def enable_pch_i2c_comm(self):
        # Enable PCH connection to I2c devices
        reg_value = self.cs.read_register('8086.SMBUS.SMBUS_HCFG', self.instance)[0]
        if 0 == (reg_value.value & 0x04):
            self.cs.write_register('8086.SMBUS.SMBUS_HCFG', [(reg_value.value | 0x05)], self.instance)
        reg_value = self.cs.read_register('8086.SMBUS.SMBUS_HCFG', self.instance)[0]
        if not 0 == (reg_value.value & 0x04):
            self.logger.log("PCH is enabled to connect with i2c devices")
        else:
            self.logger.log("PCH is not enabled to connect with i2c devices")

    def enable_SMBus_io_mem_space(self):
        # @TODO: check SBA is programmed
        sba = self.get_SMBus_Base_Address()
        # Enable SMBus I/O Space
        cmd = self.cs.read_register('8086.SMBUS.SMBUS_CMD', self.instance)[0]
        if 0 == (cmd.value & 0x1):
            self.cs.write_register('8086.SMBUS.SMBUS_CMD', [(cmd.value | 0x1)], self.instance)

    def reset_SMBus_controller(self):
        reg_value = self.cs.read_register('8086.SMBUS.SMBUS_HCFG', self.instance)[0]
        self.cs.write_register('8086.SMBUS.SMBUS_HCFG', [reg_value.value | 0x08], self.instance)
        for i in range(SMBUS_POLL_COUNT):
            if (self.cs.read_register('8086.SMBUS.SMBUS_HCFG', self.instance)[0].value & 0x08) == 0:
                return True
        return False

    def _show_register(self, register):
        if self.logger.HAL:
            reg_data = self.cs.read_register(register, self.instance)[0]
            self.cs.print_register(register, reg_data)

    # waits for SMBus to become ready
    def _is_smbus_ready(self):
        for i in range(SMBUS_POLL_COUNT):
            if self.logger.HAL:
                reg = self.cs.read_register(self.smb_reg_status, self.instance)[0]
                self.logger.log("reg {0}".format(reg.value))
            busy = self.cs.read_register_field(self.smb_reg_status, 'BUSY', instance=self.instance)[0]
            if 1 == busy.value:
                self.logger.log_hal("SMBus busy, waiting...")
                continue
            self.cs.write_register(self.smb_reg_status, [0xFF], self.instance)
            break
        return 0 == busy.value

    # waits for SMBus transaction to complete
    def _wait_for_cycle(self):
        for i in range(SMBUS_POLL_COUNT):
            sts = self.cs.read_register(self.smb_reg_status, self.instance)[0]
            busy = self.cs.get_register_field(self.smb_reg_status, sts.value, 'BUSY')
            failed = self.cs.get_register_field(self.smb_reg_status, sts.value, 'FAILED')
            if 1 == busy:
                self.logger.log_hal("SMBus busy, waiting...")
                continue
            elif 1 == failed:
                self.logger.log_hal("SMBus transaction failed (FAILED/ERROR bit = 1)")
                reg_value = self.cs.read_register('8086.SMBUS.SMBUS_HCFG', self.instance)[0]
                self.cs.write_register('SMBUS_HCFG', [(reg_value.value | 0x08)], self.instance)
                return False

            if self.cs.Cfg.register_has_field(self.smb_reg_status, 'DEV_ERR'):
                if 1 == self.cs.get_register_field(self.smb_reg_status, sts.value, 'DEV_ERR'):
                    self.logger.log_hal("SMBus device error (invalid cmd, unclaimed cycle or time-out error)")
                    reg_value = self.cs.read_register('8086.SMBUS.SMBUS_HCFG', self.instance)[0]
                    self.cs.write_register('8086.SMBUS.SMBUS_HCFG', [(reg_value.value | 0x08)], self.instance)
                    return False
            if self.cs.Cfg.register_has_field(self.smb_reg_status, 'BUS_ERR'):
                if 1 == self.cs.get_register_field(self.smb_reg_status, sts.value, 'BUS_ERR'):
                    self.logger.log_hal("SMBus bus error")
                    reg_value = self.cs.read_register('8086.SMBUS.SMBUS_HCFG', self.instance)[0]
                    self.cs.write_register('SMBUS_HCFG', [(reg_value.value | 0x08)], self.instance)
                    return False
            break
        return (0 == busy)

    #
    # SMBus commands
    #
    def quick_write(self, target_address):
        ret_code = False
        if not self._is_smbus_ready():
            return ret_code

        if self.logger.VERBOSE:
            self.logger.log("[smbus] quick write to device {:X}".format(target_address))

        # clear status bits
        self.cs.write_register(self.smb_reg_status, [0xFF], self.instance)
        # SMBus txn RW direction = Write, SMBus slave address = target_address
        hst_sa = 0x0
        hst_sa = self.cs.set_register_field(self.smb_reg_address, hst_sa, 'RW', SMBUS_COMMAND_WRITE)
        hst_sa = self.cs.set_register_field(self.smb_reg_address, hst_sa, 'Address', target_address)
        self.cs.write_register(self.smb_reg_address, [hst_sa], self.instance)

        # command = Byte Data
        self.cs.write_register_field(self.smb_reg_control, 'SMB_CMD', SMBUS_COMMAND_QUICK, instance=self.instance)
        self.cs.read_register(self.smb_reg_control, self.instance)

        # send SMBus txn
        self.cs.write_register_field(self.smb_reg_control, 'START', 1, instance=self.instance)
        self.cs.read_register(self.smb_reg_control, self.instance)

        # wait for cycle to complete
        ret_code = self._wait_for_cycle()
        # clear status bits
        self.cs.write_register(self.smb_reg_data0, [0x00], self.instance)
        self.cs.read_register(self.smb_reg_data0, self.instance)
        if self.logger.HAL:
            self.logger.log("[smbus] quick write to device {:X} returned {:s}".format(target_address, str(ret_code)))
        return ret_code

    def read_byte(self, target_address, offset):
        if not self._is_smbus_ready():
            self.logger.log("[smbus] controller is not read {:X}".format(target_address))
            return False

        # clear status bits
        self.cs.write_register(self.smb_reg_status, [0xFF], self.instance)

        # SMBus txn RW direction = Read, SMBus slave address = target_address
        hst_sa = 0x0
        hst_sa = self.cs.set_register_field(self.smb_reg_address, hst_sa, 'RW', SMBUS_COMMAND_READ)
        hst_sa = self.cs.set_register_field(self.smb_reg_address, hst_sa, 'Address', target_address)
        self.cs.write_register(self.smb_reg_address, [hst_sa], self.instance)
        self.cs.read_register(self.smb_reg_address, self.instance)
        self._show_register(self.smb_reg_address)

        # command data = byte offset (bus txn address)
        self.cs.write_register_field(self.smb_reg_command, 'DataOffset', offset, instance=self.instance)
        self.cs.read_register(self.smb_reg_command, self.instance)
        if self.logger.HAL:
            self._show_register(self.smb_reg_command)

        # command = Byte Data
        self.cs.write_register_field(self.smb_reg_control, 'SMB_CMD', SMBUS_COMMAND_BYTE_DATA, instance=self.instance)
        self.cs.read_register(self.smb_reg_control, self.instance)

        # send SMBus txn
        self.cs.write_register_field(self.smb_reg_control, 'START', 1, instance=self.instance)
        if self.logger.HAL:
            self._show_register(self.smb_reg_control)
        self.cs.read_register(self.smb_reg_control, self.instance)

        # wait for cycle to complete
        if not self._wait_for_cycle():
            return False

        # read the data
        value = self.cs.read_register(self.smb_reg_data0, self.instance)[0].value
        if self.logger.HAL:
            self._show_register(self.smb_reg_data0)
        self.cs.write_register(self.smb_reg_data0, [0x00], self.instance)
        self.cs.read_register(self.smb_reg_data0, self.instance)

        # clear status bits
        # self.cs.write_register(self.smb_reg_status, 0xFF)

        if self.logger.HAL:
            self.logger.log("[smbus] read device {:X} off {:X} = {:X}".format(target_address, offset, value))
        return [value]

    def read_word(self, target_address, offset):
        if not self._is_smbus_ready():
            return False

        # clear status bits
        self.cs.write_register(self.smb_reg_status, [0xFF], self.instance)
        self.cs.read_register(self.smb_reg_status, self.instance)

        # SMBus txn RW direction = Read, SMBus slave address = target_address
        hst_sa = 0x0
        hst_sa = self.cs.set_register_field(self.smb_reg_address, hst_sa, 'RW', SMBUS_COMMAND_READ)
        hst_sa = self.cs.set_register_field(self.smb_reg_address, hst_sa, 'Address', target_address)
        self.cs.write_register(self.smb_reg_address, [hst_sa], self.instance)
        self.cs.read_register(self.smb_reg_address, self.instance)
        if self.logger.HAL:
            self._show_register(self.smb_reg_address)

        # command data = byte offset (bus txn address)
        self.cs.write_register_field(self.smb_reg_command, 'DataOffset', offset, instance=self.instance)
        self.cs.read_register(self.smb_reg_command, self.instance)
        if self.logger.HAL:
            self._show_register(self.smb_reg_command)

        # command = Byte Data
        self.cs.write_register_field(self.smb_reg_control, 'SMB_CMD', SMBUS_COMMAND_WORD_DATA, instance=self.instance)
        self.cs.read_register(self.smb_reg_control, self.instance)

        # send SMBus txn
        self.cs.write_register_field(self.smb_reg_control, 'START', 1, instance=self.instance)
        self.cs.read_register(self.smb_reg_control, self.instance)
        if self.logger.HAL:
            self._show_register(self.smb_reg_control)

        # wait for cycle to complete
        if not self._wait_for_cycle():
            return False

        # read the data
        valueL = self.cs.read_register(self.smb_reg_data0, self.instance)[0].value
        if self.logger.HAL:
            self._show_register(self.smb_reg_data0)
        self.cs.write_register(self.smb_reg_data0, [0x00], self.instance)
        self.cs.read_register(self.smb_reg_data0, self.instance)
        valueH = self.cs.read_register(self.smb_reg_data1, self.instance)[0].value
        if self.logger.HAL:
            self._show_register(self.smb_reg_data1)
        self.cs.write_register(self.smb_reg_data1, [0x00], self.instance)
        self.cs.read_register(self.smb_reg_data1, self.instance)

        # clear status bits
        # self.cs.write_register(self.smb_reg_status, 0xFF)

        self.logger.log_verbose("[smbus] read device {:X} off {:X} = {:X} {:X}".format(
            target_address, offset, valueH, valueL))
        return [valueL, valueH]

    def read_block(self, target_address, command):
        if not self._is_smbus_ready():
            return False

        # clear status bits
        self.cs.write_register(self.smb_reg_status, [0xFF], self.instance)
        self.cs.write_register_field(self.smb_reg_control, 'LAST_BYTE', 0, instance=self.instance)
        self.cs.read_register(self.smb_reg_control, self.instance)

        # SMBus txn RW direction = Read, SMBus slave address = target_address
        hst_sa = 0x0
        hst_sa = self.cs.set_register_field(self.smb_reg_address, hst_sa, 'RW', SMBUS_COMMAND_READ)
        hst_sa = self.cs.set_register_field(self.smb_reg_address, hst_sa, 'Address', target_address)
        self.cs.write_register(self.smb_reg_address, [hst_sa], self.instance)
        self.cs.read_register(self.smb_reg_address, self.instance)
        if self.logger.HAL:
            self._show_register(self.smb_reg_address)

        # auxiliary control reg
        self.cs.write_register_field(self.smb_reg_aux_ctl, 'E32B', 1, instance=self.instance)
        self.cs.read_register(self.smb_reg_aux_ctl, self.instance)
        if self.logger.HAL:
            self._show_register(self.smb_reg_aux_ctl)

        # command data = byte offset (bus txn address)
        self.cs.write_register_field(self.smb_reg_command, 'DataOffset', command, instance=self.instance)
        self.cs.read_register(self.smb_reg_command, self.instance)
        if self.logger.HAL:
            self._show_register(self.smb_reg_command)

        # command = Byte Data
        self.cs.write_register_field(self.smb_reg_control, 'SMB_CMD', SMBUS_COMMAND_BLOCK, instance=self.instance)
        self.cs.read_register(self.smb_reg_control, self.instance)
        if self.logger.HAL:
            self._show_register(self.smb_reg_control)

        # send SMBus txn
        self.cs.write_register_field(self.smb_reg_control, 'START', 1, instance=self.instance)
        self.cs.read_register(self.smb_reg_control, self.instance)
        if self.logger.HAL:
            self._show_register(self.smb_reg_control)

        # wait for cycle to complete
        if not self._wait_for_cycle():
            return False
        read_list = []
        to_read = self.cs.read_register(self.smb_reg_data0, self.instance)[0].value
        if to_read <= 0 or to_read > 32:
            return False

        while to_read:
            read_list.append(self.cs.read_register(self.smb_reg_block_db, self.instance)[0].value)
            to_read -= 1
        self.cs.write_register_field(self.smb_reg_control, 'LAST_BYTE', 1, instance=self.instance)
        self.cs.read_register(self.smb_reg_control, self.instance)

        self.cs.write_register(self.smb_reg_data0, [0x00], self.instance)
        self.cs.read_register(self.smb_reg_data0, self.instance)

        # clear status bits
        # self.cs.write_register(self.smb_reg_status, 0xFF)

        self.logger.log_verbose(
            "[smbus] block read device 0x{0:x} off 0x{1:x} = {2}".format(
                target_address, command, " 0x".join("{:02x}".format(c) for c in read_list)))
        return read_list

    def write_byte(self, target_address, offset, value):
        if not self._is_smbus_ready():
            return False

        # clear status bits
        self.cs.write_register(self.smb_reg_status, [0xFF], self.instance)
        self.cs.read_register(self.smb_reg_status, self.instance)

        # SMBus txn RW direction = Write, SMBus slave address = target_address
        hst_sa = 0x0
        hst_sa = self.cs.set_register_field(self.smb_reg_address, hst_sa, 'RW', SMBUS_COMMAND_WRITE)
        hst_sa = self.cs.set_register_field(self.smb_reg_address, hst_sa, 'Address', target_address)
        self.cs.write_register(self.smb_reg_address, [hst_sa], self.instance)
        self.cs.read_register(self.smb_reg_address, self.instance)

        # command data = byte offset (bus txn address)
        self.cs.write_register_field(self.smb_reg_command, 'DataOffset', offset, instance=self.instance)
        self.cs.read_register(self.smb_reg_command, self.instance)

        # write the data
        self.cs.write_register_field(self.smb_reg_data0, 'Data', value, instance=self.instance)
        self.cs.read_register(self.smb_reg_data0, self.instance)

        # command = Byte Data
        self.cs.write_register_field(self.smb_reg_control, 'SMB_CMD', SMBUS_COMMAND_BYTE_DATA, instance=self.instance)
        self.cs.read_register(self.smb_reg_control, self.instance)

        # send SMBus txn
        self.cs.write_register_field(self.smb_reg_control, 'START', 1, instance=self.instance)
        self.cs.read_register(self.smb_reg_control, self.instance)

        # wait for cycle to complete
        if not self._wait_for_cycle():
            return False

        # clear status bits
        # self.cs.write_register(self.smb_reg_status, 0xFF)
        self.cs.write_register(self.smb_reg_data0, [0x00], self.instance)
        self.cs.read_register(self.smb_reg_data0, self.instance)

        self.logger.log_verbose("[smbus] write to device %X off %X = %X" % (target_address, offset, value))
        return True

    def write_word(self, target_address, offset, valueH, valueL):
        if not self._is_smbus_ready():
            return False

        # clear status bits
        self.cs.write_register(self.smb_reg_status, [0xFF], self.instance)

        # SMBus txn RW direction = Write, SMBus slave address = target_address
        hst_sa = 0x0
        hst_sa = self.cs.set_register_field(self.smb_reg_address, hst_sa, 'RW', SMBUS_COMMAND_WRITE)
        hst_sa = self.cs.set_register_field(self.smb_reg_address, hst_sa, 'Address', target_address)
        self.cs.write_register(self.smb_reg_address, [hst_sa], self.instance)
        self.cs.read_register(self.smb_reg_address, self.instance)

        # command data = byte offset (bus txn address)
        self.cs.write_register_field(self.smb_reg_command, 'DataOffset', offset, instance=self.instance)
        self.cs.read_register(self.smb_reg_command, self.instance)

        # write the data
        self.cs.write_register_field(self.smb_reg_data0, 'Data', valueL, instance=self.instance)
        self.cs.read_register(self.smb_reg_data0, self.instance)
        self.cs.write_register_field(self.smb_reg_data1, 'Data', valueH, instance=self.instance)
        self.cs.read_register(self.smb_reg_data1, self.instance)

        # command = Byte Data
        self.cs.write_register_field(self.smb_reg_control, 'SMB_CMD', SMBUS_COMMAND_WORD_DATA, instance=self.instance)
        self.cs.read_register(self.smb_reg_control, self.instance)

        # send SMBus txn
        self.cs.write_register_field(self.smb_reg_control, 'START', 1, instance=self.instance)
        self.cs.read_register(self.smb_reg_control, self.instance)

        # wait for cycle to complete
        if not self._wait_for_cycle():
            return False

        # clear status bits
        self.cs.write_register(self.smb_reg_data0, [0x00], self.instance)
        self.cs.read_register(self.smb_reg_data0, self.instance)
        self.cs.write_register(self.smb_reg_data1, [0x00], self.instance)
        self.cs.read_register(self.smb_reg_data1, self.instance)

        self.logger.log_verbose("[smbus] write to device %X off %X = %X %X" % (target_address, offset, valueH, valueL))
        return True

    def process_call(self, target_address, offset, valueH, valueL):
        if not self._is_smbus_ready():
            return False

        # clear status bits
        self.cs.write_register(self.smb_reg_status, [0xFF], self.instance)

        # SMBus txn RW direction = Write, SMBus slave address = target_address
        hst_sa = 0x0
        hst_sa = self.cs.set_register_field(self.smb_reg_address, hst_sa, 'RW', SMBUS_COMMAND_WRITE)
        hst_sa = self.cs.set_register_field(self.smb_reg_address, hst_sa, 'Address', target_address)
        self.cs.write_register(self.smb_reg_address, [hst_sa], self.instance)
        self.cs.read_register(self.smb_reg_address, self.instance)

        # command data = byte offset (bus txn address)
        self.cs.write_register_field(self.smb_reg_command, 'DataOffset', offset, instance=self.instance)
        self.cs.read_register(self.smb_reg_command, self.instance)

        # write the data
        self.cs.write_register(self.smb_reg_data0, [valueL], self.instance)
        self.cs.read_register(self.smb_reg_data0, self.instance)
        self._show_register(self.smb_reg_data0)
        self.cs.write_register(self.smb_reg_data1, [valueH], self.instance)
        self.cs.read_register(self.smb_reg_data1, self.instance)
        self._show_register(self.smb_reg_data1)

        # command = Byte Data
        self.cs.write_register_field(self.smb_reg_control, 'SMB_CMD', SMBUS_COMMAND_PROCESS_CALL, instance=self.instance)
        self.cs.read_register(self.smb_reg_control, self.instance)

        # send SMBus txn
        self.cs.write_register_field(self.smb_reg_control, 'START', 1, instance=self.instance)
        self.cs.read_register(self.smb_reg_control, self.instance)

        # wait for cycle to complete
        if not self._wait_for_cycle():
            return False

        # read the data
        valueL_R = self.cs.read_register(self.smb_reg_data0, self.instance)[0].value
        self._show_register(self.smb_reg_data0)
        valueH_R = self.cs.read_register(self.smb_reg_data1, self.instance)[0].value
        self._show_register(self.smb_reg_data1)

        # clear status bits
        # self.cs.write_register(self.smb_reg_status, 0xFF)
        self.cs.write_register(self.smb_reg_data0, [0x00], self.instance)
        self.cs.read_register(self.smb_reg_data0, self.instance)
        self.cs.write_register(self.smb_reg_data1, [0x00], self.instance)
        self.cs.read_register(self.smb_reg_data1, self.instance)
        self.logger.log_debug("[smbus] read device {:X} off {:X} = {:X} {:X}".format(target_address, offset, valueH_R, valueL_R))
        return [valueL_R, valueH_R]


class SMBus_MMIO(SMBus):
    def __init__(self, cs, i2c_mode=False):
        super(SMBus_MMIO, self).__init__(cs)
        self.smb_reg_status = '8086.SMBUS.SMBUS_HST_STS_MMIO'
        self.smb_reg_control = '8086.SMBUS.SMBUS_HST_CNT_MMIO'
        self.smb_reg_command = '8086.SMBUS.SMBUS_HST_CMD_MMIO'
        self.smb_reg_address = '8086.SMBUS.SMBUS_HST_SLVA_MMIO'
        self.smb_reg_data0 = '8086.SMBUS.SMBUS_HST_D0_MMIO'
        self.smb_reg_data1 = '8086.SMBUS.SMBUS_HST_D1_MMIO'
        self.smb_reg_aux_ctl = '8086.SMBUS.SMBUS_HST_AUX_CTL_MMIO'
        self.smb_reg_block_db = '8086.SMBUS.SMBUS_HST_BLOCK_DB_MMIO'
        self.i2c_mode = i2c_mode

    def enable(self):
        if not self.is_SMBus_mmio_mem_space_enabled():
            if self.logger.HAL:
                self.logger.log("SMBus mmio space disabled; enabling...")
            self.enable_SMBus_mmio_mem_space()
        else:
            if self.logger.HAL:
                self.logger.log("SMBus mmio space enabled...")
        if not self.is_SMBus_host_controller_enabled():
            if self.logger.HAL:
                self.logger.log("SMBus disabled; enabling...")
            self.enable_SMBus_host_controller()
        if self.i2c_mode is True:
            if self.logger.HAL:
                self.logger.log("i2c mode is selected")
            if not self.is_pch_i2c_enabled():
                if self.logger.HAL:
                    self.logger.log("Intel PCH is not enabled to communicate with i2c devices; enabling...")
                self.enable_pch_i2c_comm()
        else:
            if self.logger.HAL:
                self.logger.log("SMBUS mode is selected. disabling i2c mode")
            if self.is_pch_i2c_enabled():
                if self.logger.HAL:
                    self.logger.log("Intel PCH is enabled to communicate with i2c devices; disabling...")
                self.disable_pch_i2c_comm()
        if not self.is_SMBus_io_mem_space_enabled():
            self.logger.log("SMBus io/mem space disabled; enabling...")
            self.enable_SMBus_io_mem_space()

        if not self.is_SMBus_host_controller_enabled():
            self.logger.log("SMBus disabled; enabling...")
            self.enable_SMBus_host_controller()

    def is_SMBus_mmio_mem_space_enabled(self):
        cmd = self.cs.read_register('8086.SMBUS.SMBUS_CMD', self.instance)[0]
        if self.logger.HAL:
            self.cs.print_register('8086.SMBUS.SMBUS_CMD', cmd)
        return (cmd.value & 0x3) == 0x3

    def get_SMBus_mmio_Base_Address(self):
        if self.cs.mmio.is_MMIO_BAR_defined('8086.SMBUS.SMBUS_MMIOBAR'):
            (smb_mmio_base, _) = self.cs.mmio.get_MMIO_BAR_base_address('8086.SMBUS.SMBUS_MMIOBAR', self.instance)
            if self.logger.HAL:
                self.logger.log("SMBUS MMIO base: 0x{:016X} (assuming below 4GB)".format(smb_mmio_base))
            return smb_mmio_base
        else:
            return False

    def enable_SMBus_mmio_mem_space(self):
        # @TODO: check SBA is programmed
        sba = self.get_SMBus_mmio_Base_Address()
        # Enable SMBus I/O Space
        cmd = self.cs.read_register('8086.SMBUS.SMBUS_CMD', self.instance)[0]
        if 0 == (cmd.value & 0x2):
            self.cs.write_register('8086.SMBUS.SMBUS_CMD', [(cmd.value | 0x2)], self.instance)
