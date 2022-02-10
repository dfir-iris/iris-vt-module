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

from iris_vt_module.vt_handler.vt_handler import VtHandler

import iris_vt_module.IrisVTConfig as interface_conf

log = logging.getLogger('iris_vt_module')


class IrisVTInterface(IrisModuleInterface):
    """
    Provide the interface between Iris and VT
    """
    name = "IrisVTInterface"
    _module_name = interface_conf.module_name
    _module_description = interface_conf.module_description
    _interface_version = interface_conf.interface_version
    _module_version = interface_conf.module_version
    _pipeline_support = interface_conf.pipeline_support
    _pipeline_info = interface_conf.pipeline_info
    _module_configuration = interface_conf.module_configuration
    _module_type = IrisModuleTypes.module_processor

    def register_hooks(self, module_id: int):
        """
        Registers all the hooks

        :param module_id: Module ID provided by IRIS
        :return: Nothing
        """
        status = self.register_to_hook(module_id, iris_hook_name='on_postload_ioc_create')
        if status.is_failure():
            log.error(status.get_message())
            log.error(status.get_data())

        else:
            log.info("Successfully registered on_postload_ioc_create hook")

        self.register_to_hook(module_id, iris_hook_name='on_postload_ioc_update')
        if status.is_failure():
            log.error(status.get_message())
            log.error(status.get_data())

        else:
            log.info("Successfully registered on_postload_ioc_update hook")

        self.register_to_hook(module_id, iris_hook_name='on_preload_ioc_update')
        if status.is_failure():
            log.error(status.get_message())
            log.error(status.get_data())

        else:
            log.info("Successfully registered on_preload_ioc_update hook")

    def hooks_handler(self, hook_name: str, data):
        """
        Hooks handler table. Calls corresponding methods depending on the hooks name.

        :param hook_name: Name of the hook which triggered
        :param data: Data associated with the trigger.
        :return: Data
        """
        log.addHandler(self.set_log_handler())

        log.info(f'Received {hook_name}')
        if hook_name == 'on_postload_ioc_create':
            status = self._handle_ioc(data=data)

        elif hook_name == "on_postload_ioc_update":
            status = self._handle_ioc(data=data)

        elif hook_name == "on_manual_trigger_ioc":
            status = self._handle_ioc(data=data)

        else:
            log.critical(f'Received unsupported hook {hook_name}')
            return InterfaceStatus.I2Error(data=data, logs=list(self.message_queue))

        if status.is_failure():
            log.error(f"Encountered error processing hook {hook_name}")
            return InterfaceStatus.I2Error(data=data, logs=list(self.message_queue))

        log.info(f"Successfully processed hook {hook_name}")
        return InterfaceStatus.I2Success(data=data, logs=list(self.message_queue))

    def _handle_ioc(self, data) -> InterfaceStatus.IIStatus:
        """
        Handle the IOC data the module just received. The module registered
        to on_postload hooks, so it receives instances of IOC object.
        These objects are attached to a dedicated SQlAlchemy session so data can
        be modified safely.

        :param data: Data associated to the hook, here IOC object
        :return: IIStatus
        """
        vt_handler = VtHandler(mod_config=self._dict_conf)
        # Check that the IOC we receive is of type the module can handle and dispatch
        if 'ip-' in data.ioc_type.type_name:
            return vt_handler.handle_vt_ip(ioc=data)

        elif 'domain' in data.ioc_type.type_name:
            return vt_handler.handle_vt_domain(ioc=data)

        log.error(f'IOC type {data.ioc_type.type_name} not handled by VT module. Skipping')
        return InterfaceStatus.I2Success(data=data)

