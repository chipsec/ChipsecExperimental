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


"""
Access to IOMMU engines
"""

from chipsec.hal import hal_base, paging
from chipsec.exceptions import IOMMUError


class IOMMU(hal_base.HALBase):

    def __init__(self, cs):
        super(IOMMU, self).__init__(cs)

    def get_engines(self):
        engines = self.cs.Cfg.get_MMIO_match("*.*.VTBAR")
        self.logger.log_hal(engines)
        return engines

    def get_IOMMU_Base_Address(self, iommu_engine, bus):
        if self.cs.mmio.is_MMIO_BAR_defined(iommu_engine):
            (base, size) = self.cs.mmio.get_MMIO_BAR_base_address(iommu_engine, bus)
        else:
            raise IOMMUError('IOMMUError: IOMMU BAR {} is not defined in the config'.format(iommu_engine))
        return base

    def is_IOMMU_Engine_Enabled(self, iommu_engine, bus):
        enabled = False
        if self.cs.mmio.is_MMIO_BAR_defined(iommu_engine):
            enabled = self.cs.mmio.is_MMIO_BAR_enabled(iommu_engine, bus)
        return enabled

    def is_IOMMU_Translation_Enabled(self, iommu_engine, bus):
        tes = self.cs.read_register_field(iommu_engine + '_GSTS', 'TES', bus)[0].value
        return 1 == tes

    def set_IOMMU_Translation(self, iommu_engine, te):
        return self.cs.write_register_field(iommu_engine + '_GCMD', 'TE', te)

    def dump_IOMMU_configuration(self, iommu_engine):
        self.logger.log("==================================================================")
        self.logger.log("[iommu] {} IOMMU Engine Configuration".format(iommu_engine))
        self.logger.log("==================================================================")
        regdata = self.cs.read_register(iommu_engine)
        if not self.is_valid(iommu_engine, regdata):
            return
        for reg in regdata:
            self.logger.log("Base register (BAR)       : {}  - BUS {}".format(iommu_engine, reg.instance))
            self.logger.log("BAR register value        : 0x{:X}".format(reg.value))
            if reg.value == 0:
                continue
            base = self.get_IOMMU_Base_Address(iommu_engine, reg.instance)
            self.logger.log("MMIO base                 : 0x{:016X}".format(base))
            self.logger.log("------------------------------------------------------------------")
            ver_min = self.cs.read_register_field(iommu_engine + '_VER', 'MIN', instance=reg.instance)[0].value
            ver_max = self.cs.read_register_field(iommu_engine + '_VER', 'MAX', instance=reg.instance)[0].value
            self.logger.log("Version                   : {:X}.{:X}".format(ver_max, ver_min))
            enabled = self.is_IOMMU_Engine_Enabled(iommu_engine, reg.instance)
            self.logger.log("Engine enabled            : {:d}".format(enabled))
            te = self.is_IOMMU_Translation_Enabled(iommu_engine, reg.instance)
            self.logger.log("Translation enabled       : {:d}".format(te))
            rtaddr_rta = self.cs.read_register_field(iommu_engine + '_RTADDR', 'RTA', True, reg.instance)[0].value
            self.logger.log("Root Table Address        : 0x{:016X}".format(rtaddr_rta))
            irta = self.cs.read_register_field(iommu_engine + '_IRTA', 'IRTA', instance=reg.instance)[0].value
            self.logger.log("Interrupt Remapping Table : 0x{:016X}".format(irta))
            self.logger.log("------------------------------------------------------------------")
            self.logger.log("Protected Memory:")
            pmen_epm = self.cs.read_register_field(iommu_engine + '_PMEN', 'EPM', instance=reg.instance)[0].value
            pmen_prs = self.cs.read_register_field(iommu_engine + '_PMEN', 'PRS', instance=reg.instance)[0].value
            self.logger.log("  Enabled                 : {:d}".format(pmen_epm))
            self.logger.log("  Status                  : {:d}".format(pmen_prs))
            plmbase = self.cs.read_register_field(iommu_engine + '_PLMBASE', 'PLMB', instance=reg.instance)[0].value
            plmlimit = self.cs.read_register_field(iommu_engine + '_PLMLIMIT', 'PLML', instance=reg.instance)[0].value
            phmbase = self.cs.read_register_field(iommu_engine + '_PHMBASE', 'PHMB', instance=reg.instance)[0].value
            phmlimit = self.cs.read_register_field(iommu_engine + '_PHMLIMIT', 'PHML', instance=reg.instance)[0].value
            self.logger.log("  Low Memory Base         : 0x{:016X}".format(plmbase))
            self.logger.log("  Low Memory Limit        : 0x{:016X}".format(plmlimit))
            self.logger.log("  High Memory Base        : 0x{:016X}".format(phmbase))
            self.logger.log("  High Memory Limit       : 0x{:016X}".format(phmlimit))
            self.logger.log("------------------------------------------------------------------")
            self.logger.log("Capabilities:\n")
            cap_reg = self.cs.read_register(iommu_engine + '_CAP', reg.instance)[0]
            self.cs.print_register(iommu_engine + '_CAP', cap_reg)
            ecap_reg = self.cs.read_register(iommu_engine + '_ECAP', reg.instance)[0]
            self.cs.print_register(iommu_engine + '_ECAP', ecap_reg)
            self.logger.log('')

    def dump_IOMMU_page_tables(self, iommu_engine):
        regdata = self.cs.read_register(iommu_engine)
        if not self.is_valid(iommu_engine, regdata):
            return
        for reg in regdata:
            self.logger.log("==================================================================")
            self.logger.log("[iommu] {} IOMMU Page Tables - BUS {}:".format(iommu_engine, reg.instance))
            self.logger.log("==================================================================")
            te = self.is_IOMMU_Translation_Enabled(iommu_engine, reg.instance)
            self.logger.log("[iommu] Translation enabled    : {:d}".format(te))
            rtaddr_reg = self.cs.read_register(iommu_engine + '_RTADDR', reg.instance)[0]
            rtaddr_rta = self.cs.get_register_field(iommu_engine + '_RTADDR', rtaddr_reg.value, 'RTA', True)
            rtaddr_rtt = self.cs.get_register_field(iommu_engine + '_RTADDR', rtaddr_reg.value, 'RTT')
            self.logger.log("[iommu] Root Table Address/Type: 0x{:016X}/{:X}".format(rtaddr_rta, rtaddr_rtt))

            ecap_reg = self.cs.read_register(iommu_engine + '_ECAP', reg.instance)[0]
            ecs = self.cs.get_register_field(iommu_engine + '_ECAP', ecap_reg.value, 'ECS')
            pasid = self.cs.get_register_field(iommu_engine + '_ECAP', ecap_reg.value, 'PASID')
            self.logger.log('[iommu] PASID / ECS            : {:X} / {:X}'.format(pasid, ecs))

            if 0xFFFFFFFFFFFFFFFF != rtaddr_reg.value:
                if te:
                    self.logger.log('[iommu] dumping VT-d page table hierarchy at 0x{:016X} (vtd_context_{:08X})..'.format(rtaddr_rta, rtaddr_rta))
                    paging_vtd = paging.c_vtd_page_tables(self.cs)
                    paging_vtd.read_vtd_context('vtd_context_{:08X}'.format(rtaddr_rta), rtaddr_rta)
                    self.logger.log('[iommu] total VTd domains: {:d}'.format(len(paging_vtd.domains)))
                    for domain in paging_vtd.domains:
                        paging_vtd.read_pt_and_show_status('vtd_{:08X}'.format(domain), 'VTd', domain)
                else:
                    self.logger.log("[iommu] translation via VT-d engine '{}' is not enabled".format(iommu_engine))
            else:
                self.logger.error("cannot access VT-d registers")
            self.logger.log('')

    def dump_IOMMU_status(self, iommu_engine):
        self.logger.log("==================================================================")
        self.logger.log("[iommu] {} IOMMU Engine Status:".format(iommu_engine))
        self.logger.log("==================================================================")
        regdata = self.cs.read_register(iommu_engine)
        if not self.is_valid(iommu_engine, regdata):
            return
        for reg in regdata:
            gsts_reg = self.cs.read_register(iommu_engine + '_GSTS', reg.instance)[0]
            self.cs.print_register(iommu_engine + '_GSTS', gsts_reg)
            fsts_reg = self.cs.read_register(iommu_engine + '_FSTS', reg.instance)[0]
            self.cs.print_register(iommu_engine + '_FSTS', fsts_reg)
            frcdl_reg = self.cs.read_register(iommu_engine + '_FRCDL', reg.instance)[0]
            self.cs.print_register(iommu_engine + '_FRCDL', frcdl_reg)
            frcdh_reg = self.cs.read_register(iommu_engine + '_FRCDH', reg.instance)[0]
            self.cs.print_register(iommu_engine + '_FRCDH', frcdh_reg)
            ics_reg = self.cs.read_register(iommu_engine + '_ICS', reg.instance)[0]
            self.cs.print_register(iommu_engine + '_ICS', ics_reg)
            self.logger.log('')

    def is_valid(self, iommu_engine, regdata):
        cont = False
        if not regdata:
            self.logger.log("[iommu] Unable to read {}".format(regdata))
        for reg in regdata:
            if reg.value == 0:
                self.logger.log("[iommu] {} value is zero for bus {}".format(iommu_engine, reg.instance))
            else:
                cont = True
        return cont

    def supported(self):
        if self.cs.is_server():
            return True
        capid = '8086.HOSTCTL.CAPID0_A'
        if self.cs.Cfg.is_register_defined(capid):
            regdata = self.cs.read_register_field(capid, 'VTDD')
            return self.cs.is_all_value(regdata, 0)
        else:
            return False
