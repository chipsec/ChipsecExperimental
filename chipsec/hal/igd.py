# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2010-2021, Intel Corporation
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


# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
#
# -------------------------------------------------------------------------------

"""
Working with Intel processor Integrated Graphics Device (IGD)

usage:
    >>> gfx_aperture_dma_read(0x80000000, 0x100)
"""

from chipsec.hal.hal_base import HALBase


class IGD(HALBase):
    def __init__(self, cs):
        super(IGD, self).__init__(cs)
        self.has_config = None
        self.enabled = None

    def __identify_device(self):
        if self.enabled is None:
            self.is_legacy = False
            if self.cs.Cfg.is_register_defined("8086.IGD.DID"):
                self.dev_id = self.cs.read_register('8086.IGD.DID')[0].value
                self.has_config = True
            else:
                self.has_config = False

    def is_enabled(self):
        res = False
        if self.has_config is None:
            self.__identify_device()
        if self.has_config:
            if self.cs.Cfg.register_has_field("8086.HOSTCTL.DEVEN", "D2EN"):
                deven = self.cs.read_register_field("8086.HOSTCTL.DEVEN", "D2EN")[0].value == 1
            else:
                deven = None
            if self.cs.Cfg.register_has_field("8086.HOSTCTL.CAPID0_A", "IGD"):
                capioa = self.cs.read_register_field("PCI0.0.0_CAPID0_A", "IGD") == 0
            else:
                capioa = None

            if deven is not None and capioa is not None:
                res = deven and capioa
            elif deven is not None:
                res = deven
            elif capioa is not None:
                res = capioa
            else:
                res = False
        return res

    def get_GMADR(self):
        if self.has_config is None:
            self.__identify_device()
        if self.has_config and self.cs.Cfg.is_register_defined('8086.IGD.GMADR'):
            base = self.cs.mmio.get_MMIO_BAR_base_address('8086.IGD.GMADR', 0)[0].value
            self.logger.log_hal('[igd] Aperture (GMADR): 0x{:016X}'.format(base))
            return base
        else:
            return None

    def get_GTTMMADR(self):
        if self.has_config is None:
            self.__identify_device()
        if self.has_config and self.cs.Cfg.is_register_defined('8086.IGD.GTTMMADR'):
            base = self.cs.mmio.get_MMIO_BAR_base_address('8086.IGD.GTTMMADR', 0)[0].value
            self.logger.log_hal('[igd] Graphics MMIO and GTT (GTTMMADR): 0x{:016X}'.format(base))
            return base
        else:
            return None
