# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation

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
Access to SPI Flash parts

usage:
    >>> read_spi(spi_fla, length)
    >>> write_spi(spi_fla, buf)
    >>> erase_spi_block(spi_fla)
    >>> get_SPI_JEDEC_ID()
    >>> get_SPI_JEDEC_ID_decoded()

.. note::
    !! IMPORTANT:
    Size of the data chunk used in SPI read cycle (in bytes)
    default = maximum 64 bytes (remainder is read in 4 byte chunks)

    If you want to change logic to read SPI Flash in 4 byte chunks:
    SPI_READ_WRITE_MAX_DBC = 4

    @TBD: SPI write cycles operate on 4 byte chunks (not optimized yet)

    Approximate performance (on 2-core SMT Intel Core i5-4300U (Haswell) CPU 1.9GHz):
    SPI read: ~7 sec per 1MB (with DBC=64)
"""

import struct
import time

from chipsec.defines import ALIGNED_4KB, BIT0, BIT1, BIT2, BIT5
from chipsec.file import write_file, read_file
from chipsec.lib.display_format import print_buffer, print_buffer_bytes
from chipsec.hal import hal_base
from chipsec.lib.spi_jedec_ids import JEDEC_ID
from chipsec.exceptions import SpiRuntimeError
from chipsec.defines import RegData

SPI_READ_WRITE_MAX_DBC = 64
SPI_READ_WRITE_DEF_DBC = 4
SFDP_HEADER = 0x50444653

SPI_MAX_PR_COUNT = 5
SPI_FLA_SHIFT = 12
SPI_FLA_PAGE_MASK = ALIGNED_4KB

SPI_MMIO_BASE_LENGTH = 0x200
PCH_RCBA_SPI_HSFSTS_SCIP = BIT5   # SPI cycle in progress
PCH_RCBA_SPI_HSFSTS_AEL = BIT2   # Access Error Log
PCH_RCBA_SPI_HSFSTS_FCERR = BIT1   # Flash Cycle Error
PCH_RCBA_SPI_HSFSTS_FDONE = BIT0   # Flash Cycle Done

PCH_RCBA_SPI_HSFCTL_FCYCLE_READ = 0  # Flash Cycle Read
PCH_RCBA_SPI_HSFCTL_FCYCLE_WRITE = 2  # Flash Cycle Write
PCH_RCBA_SPI_HSFCTL_FCYCLE_ERASE = 3  # Flash Cycle Block Erase
PCH_RCBA_SPI_HSFCTL_FCYCLE_SFDP = 5
PCH_RCBA_SPI_HSFCTL_FCYCLE_JEDEC = 6  # Flash Cycle Read JEDEC ID
PCH_RCBA_SPI_HSFCTL_FCYCLE_FGO = BIT0  # Flash Cycle GO

PCH_RCBA_SPI_FADDR_MASK = 0x07FFFFFF  # SPI Flash Address Mask [0:26]

PCH_RCBA_SPI_FREGx_LIMIT_MASK = 0x7FFF0000  # Size
PCH_RCBA_SPI_FREGx_BASE_MASK = 0x00007FFF  # Base

PCH_RCBA_SPI_OPTYPE_RDNOADDR = 0x00
PCH_RCBA_SPI_OPTYPE_WRNOADDR = 0x01
PCH_RCBA_SPI_OPTYPE_RDADDR = 0x02
PCH_RCBA_SPI_OPTYPE_WRADDR = 0x03

PCH_RCBA_SPI_FDOC_FDSS_FSDM = 0x0000  # Flash Signature and Descriptor Map
PCH_RCBA_SPI_FDOC_FDSS_COMP = 0x1000  # Component
PCH_RCBA_SPI_FDOC_FDSS_REGN = 0x2000  # Region
PCH_RCBA_SPI_FDOC_FDSS_MSTR = 0x3000  # Master
PCH_RCBA_SPI_FDOC_FDSI_MASK = 0x0FFC  # Flash Descriptor Section Index

# agregated SPI Flash commands
HSFCTL_READ_CYCLE = ((PCH_RCBA_SPI_HSFCTL_FCYCLE_READ << 1) | PCH_RCBA_SPI_HSFCTL_FCYCLE_FGO)
HSFCTL_WRITE_CYCLE = ((PCH_RCBA_SPI_HSFCTL_FCYCLE_WRITE << 1) | PCH_RCBA_SPI_HSFCTL_FCYCLE_FGO)
HSFCTL_ERASE_CYCLE = ((PCH_RCBA_SPI_HSFCTL_FCYCLE_ERASE << 1) | PCH_RCBA_SPI_HSFCTL_FCYCLE_FGO)
HSFCTL_JEDEC_CYCLE = ((PCH_RCBA_SPI_HSFCTL_FCYCLE_JEDEC << 1) | PCH_RCBA_SPI_HSFCTL_FCYCLE_FGO)
HSFCTL_SFDP_CYCLE = ((PCH_RCBA_SPI_HSFCTL_FCYCLE_SFDP << 1) | PCH_RCBA_SPI_HSFCTL_FCYCLE_FGO)

HSFSTS_CLEAR = (PCH_RCBA_SPI_HSFSTS_AEL | PCH_RCBA_SPI_HSFSTS_FCERR | PCH_RCBA_SPI_HSFSTS_FDONE)

#
# Hardware Sequencing Flash Status (HSFSTS)
#
SPI_HSFSTS_OFFSET = 0x04
# HSFSTS bit masks
SPI_HSFSTS_FLOCKDN_MASK = (1 << 15)
SPI_HSFSTS_FDOPSS_MASK = (1 << 13)

#
# Flash Regions
#

SPI_REGION_NUMBER_IN_FD = 12

FLASH_DESCRIPTOR = 0
BIOS = 1
ME = 2
GBE = 3
PLATFORM_DATA = 4
FREG5 = 5
FREG6 = 6
FREG7 = 7
EMBEDDED_CONTROLLER = 8
FREG9 = 9
FREG10 = 10
FREG11 = 11

SPI_REGION = {
    FLASH_DESCRIPTOR: '8086.SPI.FREG0_FLASHD',
    BIOS: '8086.SPI.FREG1_BIOS',
    ME: '8086.SPI.FREG2_ME',
    GBE: '8086.SPI.FREG3_GBE',
    PLATFORM_DATA: '8086.SPI.FREG4_PD',
    FREG5: '8086.SPI.FREG5',
    FREG6: '8086.SPI.FREG6',
    FREG7: '8086.SPI.FREG7',
    EMBEDDED_CONTROLLER: '8086.SPI.FREG8_EC',
    FREG9: '8086.SPI.FREG9',
    FREG10: '8086.SPI.FREG10',
    FREG11: '8086.SPI.FREG11'
}

SPI_REGION_NAMES = {
    FLASH_DESCRIPTOR: 'Flash Descriptor',
    BIOS: 'BIOS',
    ME: 'Intel ME',
    GBE: 'GBe',
    PLATFORM_DATA: 'Platform Data',
    FREG5: 'Flash Region 5',
    FREG6: 'Flash Region 6',
    FREG7: 'Flash Region 7',
    EMBEDDED_CONTROLLER: 'Embedded Controller',
    FREG9: 'Flash Region 9',
    FREG10: 'Flash Region 10',
    FREG11: 'Flash Region 11'
}

#
# Flash Descriptor Master Defines
#

MASTER_HOST_CPU_BIOS = 0
MASTER_ME = 1
MASTER_GBE = 2
MASTER_EC = 3

SPI_MASTER_NAMES = {
    MASTER_HOST_CPU_BIOS: 'CPU',
    MASTER_ME: 'ME',
    MASTER_GBE: 'GBe',
    MASTER_EC: 'EC'
}

SPI_FLASH_DESCRIPTOR_SIGNATURE = struct.pack('=I', 0x0FF0A55A)
SPI_FLASH_DESCRIPTOR_SIZE = 0x1000


class SPI(hal_base.HALBase):

    def __init__(self, cs):
        super(SPI, self).__init__(cs)

        self.rcba_spi_base = self.get_SPI_MMIO_base()

        # Reading definitions of SPI flash controller registers
        # which are required to send SPI cycles once for performance reasons
        self.logger.log_hal("[spi] Reading SPI flash controller registers definitions:")
        self.hsfs_off = self.cs.Cfg.get_register_def("8086.SPI.HSFS")['offset']
        self.logger.log_hal("      HSFS   offset = 0x{:04X}".format(self.hsfs_off))
        self.hsfc_off = self.cs.Cfg.get_register_def("8086.SPI.HSFC")['offset']
        self.logger.log_hal("      HSFC   offset = 0x{:04X}".format(self.hsfc_off))
        self.faddr_off = self.cs.Cfg.get_register_def("8086.SPI.FADDR")['offset']
        self.logger.log_hal("      FADDR  offset = 0x{:04X}".format(self.faddr_off))
        self.fdata0_off = self.cs.Cfg.get_register_def("8086.SPI.FDATA0")['offset']
        self.logger.log_hal("      FDATA0 offset = 0x{:04X}".format(self.fdata0_off))

    def get_SPI_MMIO_base(self):
        _bus = self.cs.Cfg.get_device_bus('8086.SPI.SPIBAR')
        base = {}
        if not _bus:
            _bus = None
        for bus in _bus:
            spi_base, _ = self.cs.mmio.get_MMIO_BAR_base_address('8086.SPI.SPIBAR', bus)
            base[bus] = spi_base
            self.logger.log_hal("[spi] SPI MMIO base: 0x{:016X} (assuming below 4GB)".format(spi_base))
        return base

    def spi_reg_read(self, reg, bus, size=4):
        return self.cs.mmio.read_MMIO_reg(self.rcba_spi_base[bus], reg, size)

    def spi_reg_write(self, reg, value, bus, size=4):
        return self.cs.mmio.write_MMIO_reg(self.rcba_spi_base[bus], reg, value, size)

    def get_SPI_region(self, spi_region_id, bus):
        freg_name = SPI_REGION[spi_region_id]
        if not self.cs.Cfg.is_register_defined(freg_name):
            return (None, None, None)
        freg = self.cs.read_register(freg_name, bus)[0].value
        # Region Base corresponds to FLA bits 24:12
        range_base = self.cs.get_register_field(freg_name, freg, 'RB') << SPI_FLA_SHIFT
        # Region Limit corresponds to FLA bits 24:12
        range_limit = self.cs.get_register_field(freg_name, freg, 'RL') << SPI_FLA_SHIFT
        # FLA bits 11:0 are assumed to be FFFh for the limit comparison
        range_limit |= SPI_FLA_PAGE_MASK
        return (range_base, range_limit, freg)

    # all_regions = True : return all SPI regions
    # all_regions = False: return only available SPI regions (limit >= base)
    def get_SPI_regions(self, bus=None, all_regions=True):
        _bus = self.cs.Cfg.get_device_bus('8086.SPI')
        if bus is None:
            if not _bus:
                _bus.append(None)
        else:
            if bus in _bus:
                _bus = [bus]
            else:
                raise SpiRuntimeError("Unspecified bus {:02X} was called".format(bus))
        regions = []
        for bus in _bus:
            spi_regions = {}
            for r in SPI_REGION:
                (range_base, range_limit, freg) = self.get_SPI_region(r, bus)
                if range_base is None:
                    continue
                if all_regions or (range_limit >= range_base):
                    range_size = range_limit - range_base + 1
                    spi_regions[r] = (range_base, range_limit, range_size, SPI_REGION_NAMES[r], freg)
            regions.append((spi_regions, bus))
        return regions

    def get_SPI_Protected_Range(self, pr_num, bus):
        if pr_num > SPI_MAX_PR_COUNT:
            return None

        pr_name = '8086.SPI.PR{:x}'.format(pr_num)
        pr_j_reg = self.cs.Cfg.get_register_def(pr_name)['offset']
        pr_j = self.cs.read_register(pr_name, bus)[0].value

        # Protected Range Base corresponds to FLA bits 24:12
        base = self.cs.get_register_field(pr_name, pr_j, 'PRB') << SPI_FLA_SHIFT
        # Protected Range Limit corresponds to FLA bits 24:12
        limit = self.cs.get_register_field(pr_name, pr_j, 'PRL') << SPI_FLA_SHIFT

        wpe = (0 != self.cs.get_register_field(pr_name, pr_j, 'WPE'))
        rpe = (0 != self.cs.get_register_field(pr_name, pr_j, 'RPE'))

        # Check if this is a valid PRx config
        if wpe or rpe:
            # FLA bits 11:0 are assumed to be FFFh for the limit comparison
            limit |= SPI_FLA_PAGE_MASK

        return (base, limit, wpe, rpe, pr_j_reg, pr_j)

    ##############################################################################################################
    # SPI configuration
    ##############################################################################################################

    def display_SPI_Flash_Descriptor(self):
        _bus = self.cs.Cfg.get_device_bus('8086.SPI')
        if not _bus:
            _bus.append(None)
        for bus in _bus:
            self.logger.log("============================================================")
            self.logger.log("SPI Flash Descriptor  (bus {:02X})".format(bus))
            self.logger.log("------------------------------------------------------------")
            self.logger.log("\nFlash Signature and Descriptor Map:")
            for j in range(5):
                self.cs.write_register('8086.SPI.FDOC', [(PCH_RCBA_SPI_FDOC_FDSS_FSDM | (j << 2))], bus)
                fdod = self.cs.read_register('8086.SPI.FDOD', bus)[0].value
                self.logger.log("{:08X}".format(fdod))

            self.logger.log("\nComponents:")
            for j in range(3):
                self.cs.write_register('8086.SPI.FDOC', [(PCH_RCBA_SPI_FDOC_FDSS_COMP | (j << 2))], bus)
                fdod = self.cs.read_register('8086.SPI.FDOD', bus)[0].value
                self.logger.log("{:08X}".format(fdod))

            self.logger.log("\nRegions:")
            for j in range(5):
                self.cs.write_register('8086.SPI.FDOC', [(PCH_RCBA_SPI_FDOC_FDSS_REGN | (j << 2))], bus)
                fdod = self.cs.read_register('8086.SPI.FDOD', bus)[0].value
                self.logger.log("{:08X}".format(fdod))

            self.logger.log("\nMasters:")
            for j in range(3):
                self.cs.write_register('8086.SPI.FDOC', [(PCH_RCBA_SPI_FDOC_FDSS_MSTR | (j << 2))], bus)
                fdod = self.cs.read_register('8086.SPI.FDOD')[0].value
                self.logger.log("{:08X}".format(fdod))

    def display_SPI_opcode_info(self):
        _bus = self.cs.Cfg.get_device_bus('8086.SPI')
        if not _bus:
            _bus.append(None)
        for bus in _bus:
            self.logger.log("============================================================")
            self.logger.log("SPI Opcode Info  (bus {:02X})".format(bus))
            self.logger.log("------------------------------------------------------------")
            if self.cs.Cfg.is_register_defined('8086.SPI.PREOP'):
                preop = self.cs.read_register('8086.SPI.PREOP', bus)[0].value
                self.logger.log("PREOP : 0x{:04X}".format(preop))
            else:
                preop = None
            if self.cs.Cfg.is_register_defined('8086.SPI.OPTYPE'):
                optype = self.cs.read_register('8086.SPI.OPTYPE', bus)[0].value
                self.logger.log("OPTYPE: 0x{:04X}".format(optype))
            if self.cs.Cfg.is_register_defined('8086.SPI.OPMENU_LO') and self.cs.Cfg.is_register_defined('8086.SPI.OPMENU_HI'):
                opmenu_lo = self.cs.read_register('8086.SPI.OPMENU_LO', bus)[0].value
                opmenu_hi = self.cs.read_register('8086.SPI.OPMENU_HI', bus)[0].value
                opmenu = ((opmenu_hi << 32) | opmenu_lo)
                self.logger.log("OPMENU: 0x{:016X}".format(opmenu))
                self.logger.log('')
            else:
                opmenu = None
            if preop is not None:
                preop0 = preop & 0xFF
                preop1 = (preop >> 8) & 0xFF
                self.logger.log("Prefix Opcode 0 = 0x{:02X}".format(preop0))
                self.logger.log("Prefix Opcode 1 = 0x{:02X}".format(preop1))

            if opmenu:
                self.logger.log("------------------------------------------------------------")
                self.logger.log("Opcode # | Opcode | Optype | Description")
                self.logger.log("------------------------------------------------------------")
                for j in range(8):
                    optype_j = ((optype >> j * 2) & 0x3)
                    if (PCH_RCBA_SPI_OPTYPE_RDNOADDR == optype_j):
                        desc = 'SPI read cycle without address'
                    elif (PCH_RCBA_SPI_OPTYPE_WRNOADDR == optype_j):
                        desc = 'SPI write cycle without address'
                    elif (PCH_RCBA_SPI_OPTYPE_RDADDR == optype_j):
                        desc = 'SPI read cycle with address'
                    elif (PCH_RCBA_SPI_OPTYPE_WRADDR == optype_j):
                        desc = 'SPI write cycle with address'
                    self.logger.log("Opcode{:d}  | 0x{:02X}   | {:x}      | {} ".format(
                        j, ((opmenu >> j * 8) & 0xFF), optype_j, desc))

    def display_SPI_Flash_Regions(self):
        regions = self.get_SPI_regions()
        for tregion, bus in regions:
            self.logger.log("------------------------------------------------------------")
            self.logger.log("Flash Region  (bus {:2X})   | FREGx Reg | Base     | Limit     ".format(bus))
            self.logger.log("------------------------------------------------------------")
            for (region_id, region) in tregion.items():
                base, limit, size, name, freg = region
                self.logger.log('{:d} {:22} | {:08X}  | {:08X} | {:08X} '.format(region_id, name, freg, base, limit))

    def display_BIOS_region(self):
        bfpreg = self.cs.read_register('8086.SPI.BFPR')
        for bfpdata in bfpreg:
            base = self.cs.get_register_field('8086.SPI.BFPR', bfpdata.value, 'PRB') << SPI_FLA_SHIFT
            limit = self.cs.get_register_field('8086.SPI.BFPR', bfpdata.value, 'PRL') << SPI_FLA_SHIFT
            limit |= SPI_FLA_PAGE_MASK
            self.logger.log("BIOS Flash Primary Region (bus: {:02X})".format(bfpdata.instance))
            self.logger.log("------------------------------------------------------------")
            self.logger.log("BFPREG = {:08X}:".format(bfpdata.value))
            self.logger.log("  Base  : {:08X}".format(base))
            self.logger.log("  Limit : {:08X}".format(limit))

    def display_SPI_Ranges_Access_Permissions(self):
        _bus = self.cs.Cfg.get_device_bus('8086.SPI')
        if not _bus:
            _bus.append(None)
        for bus in _bus:
            self.logger.log("SPI Flash Region Access Permissions  (bus {:02X})".format(bus))
            self.logger.log("------------------------------------------------------------")
            frap = self.cs.read_register('8086.SPI.FRAP', bus)
            fracc = frap[0].value
            if self.logger.HAL:
                for frapdata in frap:
                    self.cs.print_register('8086.SPI.FRAP', frapdata)
            brra = self.cs.get_register_field('8086.SPI.FRAP', fracc, 'BRRA')
            brwa = self.cs.get_register_field('8086.SPI.FRAP', fracc, 'BRWA')
            bmrag = self.cs.get_register_field('8086.SPI.FRAP', fracc, 'BMRAG')
            bmwag = self.cs.get_register_field('8086.SPI.FRAP', fracc, 'BMWAG')
            self.logger.log('')
            self.logger.log("BIOS Region Write Access Grant ({:02X}):".format(bmwag))
            regions, _ = self.get_SPI_regions(bus)[0]
            for region_id in regions:
                self.logger.log("  {:12}: {:1d}".format(SPI_REGION[region_id], (0 != bmwag & (1 << region_id))))
            self.logger.log("BIOS Region Read Access Grant ({:02X}):".format(bmrag))
            for region_id in regions:
                self.logger.log("  {:12}: {:1d}".format(SPI_REGION[region_id], (0 != bmrag & (1 << region_id))))
            self.logger.log("BIOS Region Write Access ({:02X}):".format(brwa))
            for region_id in regions:
                self.logger.log("  {:12}: {:1d}".format(SPI_REGION[region_id], (0 != brwa & (1 << region_id))))
            self.logger.log("BIOS Region Read Access ({:02X}):".format(brra))
            for region_id in regions:
                self.logger.log("  {:12}: {:1d}".format(SPI_REGION[region_id], (0 != brra & (1 << region_id))))

    def display_SPI_Protected_Ranges(self):
        _bus = self.cs.Cfg.get_device_bus('8086.SPI.SPIBAR')
        if not _bus:
            _bus = None
        for bus in _bus:
            self.logger.log("SPI Protected Ranges  (bus {:02X})".format(bus))
            self.logger.log("------------------------------------------------------------")
            self.logger.log("PRx (offset) | Value    | Base     | Limit    | WP? | RP?")
            self.logger.log("------------------------------------------------------------")
            for j in range(5):
                (base, limit, wpe, rpe, pr_reg_off, pr_reg_value) = self.get_SPI_Protected_Range(j, bus)
                self.logger.log("PR{:d} ({:02X})     | {:08X} | {:08X} | {:08X} | {:d}   | {:d} ".format(
                    j, pr_reg_off, pr_reg_value, base, limit, wpe, rpe))

    def display_SPI_map(self):
        self.logger.log("============================================================")
        self.logger.log("SPI Flash Map")
        self.logger.log("------------------------------------------------------------")
        self.logger.log('')
        self.display_BIOS_region()
        self.logger.log('')
        self.display_SPI_Flash_Regions()
        self.logger.log('')
        self.display_SPI_Flash_Descriptor()
        self.logger.log('')
        self.display_SPI_opcode_info()
        self.logger.log('')
        self.logger.log("============================================================")
        self.logger.log("SPI Flash Protection")
        self.logger.log("------------------------------------------------------------")
        self.logger.log('')
        self.display_SPI_Ranges_Access_Permissions()
        self.logger.log('')
        self.logger.log("BIOS Region Write Protection")
        self.logger.log("------------------------------------------------------------")
        self.display_BIOS_write_protection()
        self.logger.log('')
        self.display_SPI_Protected_Ranges()
        self.logger.log('')

    ##############################################################################################################
    # BIOS Write Protection
    ##############################################################################################################
    def display_BIOS_write_protection(self):
        if self.cs.Cfg.is_register_defined('8086.SPI.BC'):
            bc = self.cs.read_register('8086.SPI.BC')
            for regdata in bc:
                self.cs.print_register('8086.SPI.BC', regdata)
        else:
            self.logger.log_hal("Could not locate the definition of 'BIOS Control' register..")

    def disable_BIOS_write_protection(self):
        if self.logger.HAL:
            self.display_BIOS_write_protection()
        ble = self.cs.get_control('BiosLockEnable')
        bioswe = self.cs.get_control('BiosWriteEnable')
        smmbwp = self.cs.get_control('SmmBiosWriteProtection')

        if self.cs.is_all_value(smmbwp, 1):
            self.logger.log_hal("[spi] SMM BIOS write protection (SmmBiosWriteProtection) is enabled")

        if self.cs.is_any_value(bioswe, 1):
            self.logger.log_hal("[spi] BIOS write protection (BiosWriteEnable) is not enabled")
            return True
        elif self.cs.is_all_value(ble, 0):
            self.logger.log_hal("[spi] BIOS write protection is enabled but not locked. Disabling..")
        else:  # bioswe == 0 and ble == 1
            self.logger.log_hal("[spi] BIOS write protection is enabled. Attempting to disable..")

        # Set BiosWriteEnable control bit
        self.cs.set_control('BiosWriteEnable', 1)

        # read BiosWriteEnable back to check if BIOS writes are enabled
        bioswe = self.cs.get_control('BiosWriteEnable')

        if self.logger.HAL:
            self.display_BIOS_write_protection()
        self.logger.log_hal("BIOS write protection is {}".format(
            'disabled' if self.cs.is_any_value(bioswe, 1) else 'still enabled'))

        return self.cs.is_any_value(bioswe, 1)

    ##############################################################################################################
    # SPI Controller access functions
    ##############################################################################################################
    def _wait_SPI_flash_cycle_done(self, bus):
        self.logger.log_hal("[spi] wait for SPI cycle ready/done..")

        for _ in range(1000):
            hsfsts = self.spi_reg_read(self.hsfs_off, bus, 1)

            cycle_done = not (hsfsts & PCH_RCBA_SPI_HSFSTS_SCIP)
            if cycle_done:
                break

        if not cycle_done:
            self.logger.log_hal("[spi] SPI cycle still in progress. Waiting 0.1 sec..")
            time.sleep(0.1)
            hsfsts = self.spi_reg_read(self.hsfs_off, bus, 1)
            cycle_done = not (hsfsts & PCH_RCBA_SPI_HSFSTS_SCIP)

        if cycle_done:
            self.logger.log_hal("[spi] clear FDONE/FCERR/AEL bits..")
            self.spi_reg_write(self.hsfs_off, HSFSTS_CLEAR, bus, 1)
            hsfsts = self.spi_reg_read(self.hsfs_off, bus, 1)
            cycle_done = not ((hsfsts & PCH_RCBA_SPI_HSFSTS_AEL) or (hsfsts & PCH_RCBA_SPI_HSFSTS_FCERR))

        self.logger.log_hal("[spi] HSFS: 0x{:02X}".format(hsfsts))

        return cycle_done

    def _send_spi_cycle(self, hsfctl_spi_cycle_cmd, dbc, spi_fla, bus):
        self.logger.log_hal("[spi] > send SPI cycle 0x{:x} to address 0x{:08X}..".format(hsfctl_spi_cycle_cmd, spi_fla))

        # No need to check for SPI cycle DONE status before each cycle
        # DONE status is checked once before entire SPI operation

        self.spi_reg_write(self.faddr_off, (spi_fla & PCH_RCBA_SPI_FADDR_MASK), bus)
        # Other options ;)
        # chipsec.chipset.write_register(self.cs, "FADDR", (spi_fla & Cfg.PCH_RCBA_SPI_FADDR_MASK))
        # write_MMIO_reg(self.cs, spi_base, self.faddr_off, (spi_fla & Cfg.PCH_RCBA_SPI_FADDR_MASK))
        # self.cs.mem.write_physical_mem_dword(spi_base + self.faddr_off, (spi_fla & Cfg.PCH_RCBA_SPI_FADDR_MASK))

        if self.logger.HAL:
            _faddr = self.spi_reg_read(self.faddr_off, bus)
            self.logger.log_hal("[spi] FADDR: 0x{:08X}".format(_faddr))

        self.logger.log_hal("[spi] SPI cycle GO (DBC <- 0x{:02X}, HSFC <- 0x{:x})".format(dbc, hsfctl_spi_cycle_cmd))

        if (HSFCTL_ERASE_CYCLE != hsfctl_spi_cycle_cmd):
            self.spi_reg_write(self.hsfc_off + 0x1, dbc, bus, 1)

        self.spi_reg_write(self.hsfc_off, hsfctl_spi_cycle_cmd, bus, 1)

        # Read HSFC back (logging only)
        if self.logger.HAL:
            _hsfc = self.spi_reg_read(self.hsfc_off, bus, 1)
            self.logger.log_hal("[spi] HSFC: 0x{:04X}".format(_hsfc))

        cycle_done = self._wait_SPI_flash_cycle_done(bus)
        if not cycle_done:
            self.logger.log_warning("SPI cycle not done")
        else:
            self.logger.log_hal("[spi] < SPI cycle done")

        return cycle_done

    def check_hardware_sequencing(self):
        # Test if the flash decriptor is valid (and hardware sequencing enabled)
        fdv = self.cs.read_register_field('8086.SPI.HSFS', 'FDV')
        if self.cs.is_any_value(fdv, 0):
            self.logger.error("HSFS.FDV is 0, hardware sequencing is disabled")
            raise SpiRuntimeError("Chipset does not support hardware sequencing")

    #
    # SPI Flash operations
    #

    def read_spi_to_file(self, offset, data_byte_count, filename, bus):
        buf = self.read_spi(offset, data_byte_count, bus)
        if buf is None:
            return None
        if filename is not None:
            write_file(filename, buf)
        else:
            print_buffer(buf, 16)
        return buf

    def write_spi_from_file(self, spi_fla, filename, bus):
        buf = read_file(filename)
        return self.write_spi(spi_fla, struct.unpack('c' * len(buf), buf), bus)

    def read_spi(self, offset, data_byte_count, bus):

        self.check_hardware_sequencing()

        buf = bytearray()
        dbc = SPI_READ_WRITE_DEF_DBC
        if (data_byte_count >= SPI_READ_WRITE_MAX_DBC):
            dbc = SPI_READ_WRITE_MAX_DBC

        n = data_byte_count // dbc
        r = data_byte_count % dbc
        self.logger.log_hal("[spi] reading 0x{:x} bytes from SPI at FLA = 0x{:x} (in {:d} 0x{:x}-byte chunks + 0x{:x}-byte remainder)".format(data_byte_count, offset, n, dbc, r))

        cycle_done = self._wait_SPI_flash_cycle_done(bus)
        if not cycle_done:
            self.logger.error("SPI cycle not ready")
            return None

        for i in range(n):
            self.logger.log_hal("[spi] reading chunk {:d} of 0x{:x} bytes from 0x{:x}".format(i, dbc, offset + i * dbc))
            if not self._send_spi_cycle(HSFCTL_READ_CYCLE, dbc - 1, offset + i * dbc, bus):
                self.logger.error("SPI flash read failed")
            else:
                for fdata_idx in range(0, dbc // 4):
                    dword_value = self.spi_reg_read(self.fdata0_off + fdata_idx * 4, bus)
                    self.logger.log_hal("[spi] FDATA00 + 0x{:x}: 0x{:x}".format(fdata_idx * 4, dword_value))
                    buf += struct.pack("I", dword_value)

        if (0 != r):
            self.logger.log_hal("[spi] reading remaining 0x{:x} bytes from 0x{:x}".format(r, offset + n * dbc))
            if not self._send_spi_cycle(HSFCTL_READ_CYCLE, r - 1, offset + n * dbc, bus):
                self.logger.error("SPI flash read failed")
            else:
                t = 4
                n_dwords = (r + 3) // 4
                for fdata_idx in range(0, n_dwords):
                    dword_value = self.spi_reg_read(self.fdata0_off + fdata_idx * 4, bus)
                    self.logger.log_hal("[spi] FDATA00 + 0x{:x}: 0x{:08X}".format(fdata_idx * 4, dword_value))
                    if (fdata_idx == (n_dwords - 1)) and (0 != r % 4):
                        t = r % 4
                    for j in range(t):
                        buf += struct.pack('B', (dword_value >> (8 * j)) & 0xff)

        self.logger.log_hal("[spi] buffer read from SPI:")
        if self.logger.HAL:
            print_buffer_bytes(buf)

        return buf

    def write_spi(self, spi_fla, buf, bus):

        self.check_hardware_sequencing()

        write_ok = True
        data_byte_count = len(buf)
        dbc = 4
        n = data_byte_count // dbc
        r = data_byte_count % dbc
        self.logger.log_hal("[spi] writing 0x{:x} bytes to SPI at FLA = 0x{:x} (in {:d} 0x{:x}-byte chunks + 0x{:x}-byte remainder)".format(data_byte_count, spi_fla, n, dbc, r))

        cycle_done = self._wait_SPI_flash_cycle_done(bus)
        if not cycle_done:
            self.logger.error("SPI cycle not ready")
            return None

        for i in range(n):
            self.logger.log_hal("[spi] writing chunk {:d} of 0x{:x} bytes to 0x{:x}".format(i, dbc, spi_fla + i * dbc))
            dword_value = (ord(buf[i * dbc + 3]) << 24) | (ord(buf[i * dbc + 2]) << 16) | (ord(buf[i * dbc + 1]) << 8) | ord(buf[i * dbc])
            self.logger.log_hal("[spi] in FDATA00 = 0x{:08X}".format(dword_value))
            self.spi_reg_write(self.fdata0_off, dword_value, bus)
            if not self._send_spi_cycle(HSFCTL_WRITE_CYCLE, dbc - 1, spi_fla + i * dbc, bus):
                write_ok = False
                self.logger.error("SPI flash write cycle failed")

        if (0 != r):
            self.logger.log_hal("[spi] writing remaining 0x{:x} bytes to FLA = 0x{:x}".format(r, spi_fla + n * dbc))
            dword_value = 0
            for j in range(r):
                dword_value |= (ord(buf[n * dbc + j]) << 8 * j)
            self.logger.log_hal("[spi] in FDATA00 = 0x{:08X}".format(dword_value))
            self.spi_reg_write(self.fdata0_off, dword_value, bus)
            if not self._send_spi_cycle(HSFCTL_WRITE_CYCLE, r - 1, spi_fla + n * dbc, bus):
                write_ok = False
                self.logger.error("SPI flash write cycle failed")

        return write_ok

    def erase_spi_block(self, spi_fla, bus):

        self.check_hardware_sequencing()

        self.logger.log_hal("[spi] Erasing SPI Flash block @ 0x{:x}".format(spi_fla))

        cycle_done = self._wait_SPI_flash_cycle_done(bus)
        if not cycle_done:
            self.logger.error("SPI cycle not ready")
            return None

        erase_ok = self._send_spi_cycle(HSFCTL_ERASE_CYCLE, 0, spi_fla, bus)
        if not erase_ok:
            self.logger.error("SPI Flash erase cycle failed")

        return erase_ok

    #
    # SPI SFDP operations
    #
    def ptmesg(self, offset, bus):
        bios_ptinx = self.cs.Cfg.get_register_def("8086.SPI.BIOS_PTINX")['offset']
        bios_ptdata = self.cs.Cfg.get_register_def("8086.SPI.BIOS_PTDATA")['offset']
        self.spi_reg_write(bios_ptinx, offset, bus)
        self.spi_reg_read(bios_ptinx, bus)
        return self.spi_reg_read(bios_ptdata, bus)

    def get_SPI_SFDP(self):
        ret = False
        fdata1_off = self.cs.Cfg.get_register_def("8086.SPI.FDATA13")['offset']
        fdata2_off = self.cs.Cfg.get_register_def("8086.SPI.FDATA14")['offset']
        fdata3_off = self.cs.Cfg.get_register_def("8086.SPI.FDATA15")['offset']
        fdata4_off = self.cs.Cfg.get_register_def("8086.SPI.FDATA12")['offset']
        fdata5_off = self.cs.Cfg.get_register_def("8086.SPI.FDATA13")['offset']
        fdata6_off = self.cs.Cfg.get_register_def("8086.SPI.FDATA14")['offset']
        fdata7_off = self.cs.Cfg.get_register_def("8086.SPI.FDATA15")['offset']
        fdata8_off = self.cs.Cfg.get_register_def("8086.SPI.FDATA12")['offset']
        fdata9_off = self.cs.Cfg.get_register_def("8086.SPI.FDATA13")['offset']
        fdata10_off = self.cs.Cfg.get_register_def("8086.SPI.FDATA14")['offset']
        fdata11_off = self.cs.Cfg.get_register_def("8086.SPI.FDATA15")['offset']
        fdata12_off = self.cs.Cfg.get_register_def("8086.SPI.FDATA12")['offset']
        fdata13_off = self.cs.Cfg.get_register_def("8086.SPI.FDATA13")['offset']
        fdata14_off = self.cs.Cfg.get_register_def("8086.SPI.FDATA14")['offset']
        fdata15_off = self.cs.Cfg.get_register_def("8086.SPI.FDATA15")['offset']

        for component in range(0, 2):
            self.logger.log("Scanning for Flash device {:d}".format(component + 1))
            _bus = self.cs.Cfg.get_device_bus('8086.SPI')
            if not _bus:
                _bus.append(None)
            for bus in _bus:
                offset = 0x0000 | (component << 14)
                sfdp_signature = self.ptmesg(offset, bus)
                if sfdp_signature == SFDP_HEADER:
                    self.logger.log("  * Found valid SFDP header for Flash device {:d}".format(component + 1))
                    ret = True
                else:
                    self.logger.log("  * Didn't find a valid SFDP header for Flash device {:d}".format(component + 1))
                    continue
                # Increment offset to read second dword of SFDP header structure
                sfdp_data = self.ptmesg(offset + 0x4, bus)
                sfdp_minor_version = sfdp_data & 0xFF
                sfdp_major_version = (sfdp_data >> 8) & 0xFF
                self.logger.log("    SFDP version number: {}.{}".format(sfdp_major_version, sfdp_minor_version))
                num_of_param_headers = ((sfdp_data >> 16) & 0xFF) + 1
                self.logger.log("    Number of parameter headers: {:d}".format(num_of_param_headers))
                # Set offset to read 1st Parameter Table in the SFDP header structure
                offset = offset | 0x1000
                parameter_1 = self.ptmesg(offset, bus)
                param1_minor_version = (parameter_1 >> 8) & 0xFF
                param1_major_version = (parameter_1 >> 16) & 0xFF
                param1_length = (parameter_1 >> 24) & 0xFF
                self.logger.log("  * Parameter Header 1 (JEDEC)")
                self.logger.log("    ** Parameter version number: {}.{}".format(param1_major_version, param1_minor_version))
                self.logger.log("    ** Parameter length in double words: {}".format(hex(param1_length)))
                if (num_of_param_headers > 1) and self.cs.Cfg.register_has_field('HSFS', 'FCYCLE'):
                    self.check_hardware_sequencing()
                    self.spi_reg_write(fdata12_off, 0x00000000, bus)
                    self.spi_reg_write(fdata13_off, 0x00000000, bus)
                    self.spi_reg_write(fdata14_off, 0x00000000, bus)
                    self.spi_reg_write(fdata15_off, 0x00000000, bus)
                    if not self._send_spi_cycle(HSFCTL_SFDP_CYCLE, 0x3F, 0, bus):
                        self.logger.error('SPI SFDP signature cycle failed')
                        continue
                    pTable_offset_list = []
                    pTable_length = []
                    # Calculate which fdata_offset registers to read, based on number of parameter headers present
                    for i in range(1, num_of_param_headers):
                        self.logger.log("  * Parameter Header:{:d}".format(i + 1))
                        data_reg_1 = "fdata" + str(2 + (2 * i)) + "_off"
                        data_reg_2 = "fdata" + str(2 + (2 * i) + 1) + "_off"
                        data_dword_1 = self.spi_reg_read(eval(data_reg_1))
                        data_dword_2 = self.spi_reg_read(eval(data_reg_2))
                        id_manuf = (data_dword_2 & 0xFF000000) >> 16 | (data_dword_1 & 0xFF)
                        param_minor_version = (data_dword_1 >> 8) & 0xFF
                        param_major_version = (data_dword_1 >> 16) & 0xFF
                        param_length = (data_dword_1 >> 24) & 0xFF
                        param_table_pointer = (data_dword_2 & 0x00FFFFFF)
                        self.logger.log("    ** Parameter version number:{}.{}".format(param_major_version, param_minor_version))
                        self.logger.log("    ** Pramaeter length in double words: {}".format(hex(param_length)))
                        self.logger.log("    ** Parameter ID: {}".format(hex(id_manuf)))
                        self.logger.log("    ** Parameter Table Pointer(byte address): {} ".format(hex(param_table_pointer)))
                        pTable_offset_list.append(param_table_pointer)
                        pTable_length.append(param_length)
                offset = 0x0000 | (component << 14)
                # Set offset to read 1st Parameter table (JEDEC Basic Flash Parameter Table) content and Parse it
                offset = offset | 0x2000
                self.logger.log("                                ")
                self.logger.log("  * 1'st Parameter Table Content ")
                for count in range(1, param1_length + 1):
                    sfdp_data = self.ptmesg(offset, bus)
                    offset += 4
                    self.cs.print_register("8086.SPI.DWORD{}".format(count), RegData(sfdp_data, bus))
            return ret

    #
    # SPI JEDEC ID operations
    #
    def get_SPI_JEDEC_ID(self):

        jedec_id = []
        if self.cs.Cfg.register_has_field('8086.SPI.HSFS', 'FCYCLE'):
            self.check_hardware_sequencing()
            _bus = self.cs.Cfg.get_device_bus('8086.SPI.SPIBAR')
            if not _bus:
                _bus = None
            for bus in _bus:
                if not self._send_spi_cycle(HSFCTL_JEDEC_CYCLE, 4, 0, bus):
                    self.logger.error('SPI JEDEC ID cycle failed')
                spi_id = self.spi_reg_read(self.fdata0_off, bus)
                jedec_id.append(((spi_id & 0xFF) << 16) | (spi_id & 0xFF00) | ((spi_id >> 16) & 0xFF))
        # else:
        #     return False

        return jedec_id

    def get_SPI_JEDEC_ID_decoded(self):
        ret = []
        jid = self.get_SPI_JEDEC_ID()
        for jedec_id in jid:
            if jedec_id is False:
                return (False, 0, 0)
            manu = JEDEC_ID.MANUFACTURER.get((jedec_id >> 16) & 0xff, 'Unknown')
            part = JEDEC_ID.DEVICE.get(jedec_id, 'Unknown')
            ret.append((jedec_id, manu, part))
        return ret
