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


"""
SPI Flash Descriptor binary parsing functionality

"""

from binascii import hexlify
import struct

from chipsec.chipset import cs
from chipsec.defines import RegData
from chipsec.hal.spi import SPI_REGION_NUMBER_IN_FD, FLASH_DESCRIPTOR, PCH_RCBA_SPI_FREGx_BASE_MASK
from chipsec.hal.spi import SPI_REGION_NAMES, SPI_FLA_SHIFT, SPI_FLA_PAGE_MASK
from chipsec.hal.spi import PCH_RCBA_SPI_FREGx_LIMIT_MASK, SPI_MASTER_NAMES
from chipsec.lib.display_format import print_buffer_bytes
from chipsec.logger import logger

SPI_FLASH_DESCRIPTOR_SIGNATURE = struct.pack('=I', 0x0FF0A55A)
SPI_FLASH_DESCRIPTOR_SIZE = 0x1000


def get_spi_flash_descriptor(rom):
    pos = rom.find(SPI_FLASH_DESCRIPTOR_SIGNATURE)
    if (-1 == pos or pos < 0x10):
        return (-1, None)
    fd_off = pos - 0x10
    fd = rom[fd_off: fd_off + SPI_FLASH_DESCRIPTOR_SIZE]
    return (fd_off, fd)


def get_SPI_master(flmstr):
    requester_id = (flmstr & 0xFFFF)
    master_region_ra = ((flmstr >> 16) & 0xFF)
    master_region_wa = ((flmstr >> 24) & 0xFF)
    return (requester_id, master_region_ra, master_region_wa)


def get_spi_regions(fd):
    pos = fd.find(SPI_FLASH_DESCRIPTOR_SIGNATURE)
    if not (pos == 0x10):
        return None

    flmap0 = struct.unpack_from('=I', fd[0x14:0x18])[0]
    # Flash Region Base Address (bits [23:16])
    frba = ((flmap0 & 0x00FF0000) >> 12)
    # Number of Regions (bits [26:24])
    nr = (((flmap0 & 0xFF000000) >> 24) & 0x7)

    flregs = [None] * SPI_REGION_NUMBER_IN_FD
    for r in range(SPI_REGION_NUMBER_IN_FD):
        flreg_off = frba + r * 4
        flreg = struct.unpack_from('=I', fd[flreg_off:flreg_off + 0x4])[0]
        base = (flreg & PCH_RCBA_SPI_FREGx_BASE_MASK) << SPI_FLA_SHIFT
        limit = ((flreg & PCH_RCBA_SPI_FREGx_LIMIT_MASK) >> 4)
        limit |= SPI_FLA_PAGE_MASK
        notused = (base > limit)
        flregs[r] = (r, SPI_REGION_NAMES[r], flreg, base, limit, notused)

    fd_size = flregs[FLASH_DESCRIPTOR][4] - flregs[FLASH_DESCRIPTOR][3] + 1
    fd_notused = flregs[FLASH_DESCRIPTOR][5]
    if fd_notused or (fd_size != SPI_FLASH_DESCRIPTOR_SIZE):
        return None

    return flregs


def parse_spi_flash_descriptor(self, rom):
    _logger = logger()
    _cs = cs()
    if not (isinstance(rom, str) or isinstance(rom, bytes)):
        _logger.error('Invalid fd object type {}'.format(type(rom)))
        return

    pos = rom.find(SPI_FLASH_DESCRIPTOR_SIGNATURE)
    if (-1 == pos or pos < 0x10):
        _logger.error('Valid SPI flash descriptor is not found (should have signature {:08X})'.format(
            struct.unpack('=I', SPI_FLASH_DESCRIPTOR_SIGNATURE)[0]))
        return None

    fd_off = pos - 0x10
    _logger.log('[spi_fd] Valid SPI flash descriptor found at offset 0x{:08X}'.format(fd_off))

    _logger.log('')
    _logger.log('########################################################')
    _logger.log('# SPI FLASH DESCRIPTOR')
    _logger.log('########################################################')
    _logger.log('')

    fd = rom[fd_off: fd_off + SPI_FLASH_DESCRIPTOR_SIZE]
    fd_sig = struct.unpack_from('=I', fd[0x10:0x14])[0]

    _logger.log('+ 0x0000 Reserved : 0x{}'.format(hexlify(fd[0x0:0xF]).upper()))
    _logger.log('+ 0x0010 Signature: 0x{:08X}'.format(fd_sig))

    #
    # Flash Descriptor Map Section
    #
    flmap0 = struct.unpack_from('=I', fd[0x14:0x18])[0]
    flmap1 = struct.unpack_from('=I', fd[0x18:0x1C])[0]
    flmap2 = struct.unpack_from('=I', fd[0x1C:0x20])[0]
    _cs.print_register('8086.SPI.FLMAP0', RegData(flmap0, None))
    _cs.print_register('8086.SPI.FLMAP1', RegData(flmap1, None))
    _cs.print_register('8086.SPI.FLMAP2', RegData(flmap2, None))

    fcba = _cs.get_register_field('8086.SPI.FLMAP0', flmap0, 'FCBA')
    nc = _cs.get_register_field('8086.SPI.FLMAP0', flmap0, 'NC')
    frba = _cs.get_register_field('8086.SPI.FLMAP0', flmap0, 'FRBA')
    fcba = fcba << 4
    frba = frba << 4
    nc += 1
    _logger.log('')
    _logger.log('+ 0x0014 Flash Descriptor Map:')
    _logger.log('========================================================')
    _logger.log('  Flash Component Base Address: 0x{:08X}'.format(fcba))
    _logger.log('  Flash Region Base Address   : 0x{:08X}'.format(frba))
    _logger.log('  Number of Flash Components  : {:d}'.format(nc))

    nr = SPI_REGION_NUMBER_IN_FD
    if _cs.register_has_field('8086.SPI.FLMAP0', 'NR'):
        nr = _cs.get_register_field('8086.SPI.FLMAP0', flmap0, 'NR')
        if nr == 0:
            _logger.log_warning('only 1 region (FD) is found. Looks like flash descriptor binary is from Skylake platform or later. Try with option --platform')
        nr += 1
        _logger.log('  Number of Regions           : {:d}'.format(nr))

    fmba = _cs.get_register_field('8086.SPI.FLMAP1', flmap1, 'FMBA')
    nm = _cs.get_register_field('8086.SPI.FLMAP1', flmap1, 'NM')
    fpsba = _cs.get_register_field('8086.SPI.FLMAP1', flmap1, 'FPSBA')
    psl = _cs.get_register_field('8086.SPI.FLMAP1', flmap1, 'PSL')
    fmba = fmba << 4
    fpsba = fpsba << 4
    _logger.log('  Flash Master Base Address   : 0x{:08X}'.format(fmba))
    _logger.log('  Number of Masters           : {:d}'.format(nm))
    _logger.log('  Flash PCH Strap Base Address: 0x{:08X}'.format(fpsba))
    _logger.log('  PCH Strap Length            : 0x{:X}'.format(psl))

    fcpusba = _cs.get_register_field('8086.SPI.FLMAP2', flmap2, 'FCPUSBA')
    cpusl = _cs.get_register_field('8086.SPI.FLMAP2', flmap2, 'CPUSL')
    _logger.log('  Flash CPU Strap Base Address: 0x{:08X}'.format(fcpusba))
    _logger.log('  CPU Strap Length            : 0x{:X}'.format(cpusl))

    #
    # Flash Descriptor Component Section
    #
    _logger.log('')
    _logger.log('+ 0x{:04X} Component Section:'.format(fcba))
    _logger.log('========================================================')

    flcomp = struct.unpack_from('=I', fd[fcba + 0x0:fcba + 0x4])[0]
    _logger.log('+ 0x{:04X} FLCOMP   : 0x{:08X}'.format(fcba, flcomp))
    flil = struct.unpack_from('=I', fd[fcba + 0x4:fcba + 0x8])[0]
    _logger.log('+ 0x{:04X} FLIL     : 0x{:08X}'.format(fcba + 0x4, flil))
    flpb = struct.unpack_from('=I', fd[fcba + 0x8:fcba + 0xC])[0]
    _logger.log('+ 0x{:04X} FLPB     : 0x{:08X}'.format(fcba + 0x8, flpb))

    #
    # Flash Descriptor Region Section
    #
    _logger.log('')
    _logger.log('+ 0x{:04X} Region Section:'.format(frba))
    _logger.log('========================================================')

    flregs = [None] * nr
    for r in range(nr):
        flreg_off = frba + r * 4
        flreg = struct.unpack_from('=I', fd[flreg_off:flreg_off + 0x4])[0]
        if not _cs.is_register_defined('8086.SPI.FLREG{:d}'.format(r)):
            continue
        base = _cs.get_register_field(('8086.SPI.FLREG{:d}'.format(r)), flreg, 'RB') << SPI_FLA_SHIFT
        limit = _cs.get_register_field(('8086.SPI.FLREG{:d}'.format(r)), flreg, 'RL') << SPI_FLA_SHIFT
        notused = '(not used)' if base > limit or flreg == 0xFFFFFFFF else ''
        flregs[r] = (flreg, base, limit, notused)
        _logger.log('+ 0x{:04X} FLREG{:d}   : 0x{:08X} {}'.format(flreg_off, r, flreg, notused))

    _logger.log('')
    _logger.log('Flash Regions')
    _logger.log('--------------------------------------------------------')
    _logger.log(' Region                | FLREGx    | Base     | Limit   ')
    _logger.log('--------------------------------------------------------')
    for r in range(nr):
        if flregs[r]:
            _logger.log('{:d} {:20s} | {:08X}  | {:08X} | {:08X} {}'.format(
                r, SPI_REGION_NAMES[r], flregs[r][0], flregs[r][1], flregs[r][2], flregs[r][3]))

    #
    # Flash Descriptor Master Section
    #
    _logger.log('')
    _logger.log('+ 0x{:04X} Master Section:'.format(fmba))
    _logger.log('========================================================')

    flmstrs = [None] * nm
    for m in range(nm):
        flmstr_off = fmba + m * 4
        flmstr = struct.unpack_from('=I', fd[flmstr_off:flmstr_off + 0x4])[0]
        master_region_ra = _cs.get_register_field('8086.SPI.FLMSTR1', flmstr, 'MRRA')
        master_region_wa = _cs.get_register_field('8086.SPI.FLMSTR1', flmstr, 'MRWA')
        flmstrs[m] = (master_region_ra, master_region_wa)
        _logger.log('+ 0x{:04X} FLMSTR{:d}   : 0x{:08X}'.format(flmstr_off, m + 1, flmstr))

    _logger.log('')
    _logger.log('Master Read/Write Access to Flash Regions')
    _logger.log('--------------------------------------------------------')
    s = ' Region                 '
    for m in range(nm):
        if m in SPI_MASTER_NAMES:
            s = s + '| ' + ('{:9}'.format(SPI_MASTER_NAMES[m]))
        else:
            s = s + '| Master {:-2d}'.format(m)
    _logger.log(s)
    _logger.log('--------------------------------------------------------')
    for r in range(nr):
        s = '{:-2d} {:20s} '.format(r, SPI_REGION_NAMES[r])
        for m in range(nm):
            access_s = ''
            mask = (0x1 << r)
            if (flmstrs[m][0] & mask):
                access_s += 'R'
            if (flmstrs[m][1] & mask):
                access_s += 'W'
            s = s + '| ' + ('{:9}'.format(access_s))
        _logger.log(s)

    #
    # Flash Descriptor Upper Map Section
    #
    _logger.log('')
    _logger.log('+ 0x{:04X} Flash Descriptor Upper Map:'.format(0xEFC))
    _logger.log('========================================================')

    flumap1 = struct.unpack_from('=I', fd[0xEFC:0xF00])[0]
    _logger.log('+ 0x{:04X} FLUMAP1   : 0x{:08X}'.format(0xEFC, flumap1))

    vtba = ((flumap1 & 0x000000FF) << 4)
    vtl = (((flumap1 & 0x0000FF00) >> 8) & 0xFF)
    _logger.log('  VSCC Table Base Address    = 0x{:08X}'.format(vtba))
    _logger.log('  VSCC Table Length          = 0x{:02X}'.format(vtl))

    #
    # OEM Section
    #
    _logger.log('')
    _logger.log('+ 0x{:04X} OEM Section:'.format(0xF00))
    _logger.log('========================================================')
    print_buffer_bytes(fd[0xF00:])

    _logger.log('')
    _logger.log('########################################################')
    _logger.log('# END OF SPI FLASH DESCRIPTOR')
    _logger.log('########################################################')
