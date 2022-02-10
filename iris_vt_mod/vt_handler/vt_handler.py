#!/usr/bin/env python3
#
#  IRIS VT Module Source Code
#  contact@dfir-iris.org
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 3 of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
import logging
from virus_total_apis import PublicApi, PrivateApi

from iris_interface.IrisModuleInterface import IrisPipelineTypes, IrisModuleInterface, IrisModuleTypes
import iris_interface.IrisInterfaceStatus as InterfaceStatus

log = logging.getLogger(__name__)


class VtHandler():
    def __init__(self, mod_config):
        self.mod_config = mod_config
        self.vt = self.get_vt_instance()

    def get_vt_instance(self):
        """
        Returns an VT API instance depending if the key is premium or not

        :return: VT Instance
        """
        is_premium = self.mod_config.get('vt_key_is_premium')
        api_key = self.mod_config.get('vt_api_key')

        if is_premium:
            return PrivateApi(api_key)
        else:
            return PublicApi(api_key)

    def handle_vt_domain(self, ioc):
        """
        Handles an IOC of type domain and adds VT insights

        :param ioc: IOC instance
        :return: IIStatus
        """

        log.info(f'Getting domain report for {ioc.ioc_value}')
        report = self.vt.get_domain_report(ioc.ioc_value)

        log.info(f'VT report fetched.')
        results = report.get('results')

        if results.get('response_code') == 0:
            log.error(f'Got invalid feedback from VT :: {results.get("verbose_msg")}')
            return InterfaceStatus.I2Success()

        if self.mod_config.get('vt_domain_add_whois_as_desc') is True:
            ioc.ioc_description = f"{ioc.ioc_description}\n\nWHOIS\n {report.get('results').get('whois')}"

        return InterfaceStatus.I2Success()

    def handle_vt_ip(self, ioc):
        """
        Handles an IOC of type IP and adds VT insights

        :param ioc: IOC instance
        :return: IIStatus
        """
        vt = self.get_vt_instance()

        log.info(f'Getting IP report for {ioc.ioc_value}')
        report = vt.get_ip_report(ioc.ioc_value)

        log.info(f'VT report fetched.')

        results = report.get('results')
        if not results:
            log.error(f'Unable to get report. Is the API key valid ?')
            return InterfaceStatus.I2Error

        if results.get('response_code') == 0:
            log.error(f'Got invalid feedback from VT :: {results.get("verbose_msg")}')
            return InterfaceStatus.I2Success

        log.info(f'Report results validated')
        if self.mod_config.get('vt_ip_assign_asn_as_tag') is True:
            log.info('Assigning new ASN tag to IOC.')

            asn = report.get('results').get('asn')
            if asn is None:
                log.info('ASN was nul - skipping')

            ioc.ioc_tags = f"{ioc.ioc_tags},ASN:{report.get('results').get('asn')}"

        return InterfaceStatus.I2Success("Successfully processed IP")