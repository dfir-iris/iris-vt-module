#!/usr/bin/env python3
#
#  IRIS Source Code
#  Copyright (C) 2021 - Airbus CyberSecurity (SAS)
#  ir@cyberactionlab.net
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

module_name = "IrisVT"
module_description = "Provides an interface between VirusTotal and IRIS"
interface_version = 1.1
module_version = 1.0
pipeline_support = False
pipeline_info = {}

module_configuration = [
    {
        "param_name": "vt_api_key",
        "param_human_name": "VT API Key",
        "param_description": "API key to use to communicate with VT",
        "default": None,
        "mandatory": True,
        "type": "sensitive_string"
    },
    {
        "param_name": "vt_key_is_premium",
        "param_human_name": "VT Key is premium",
        "param_description": "Set to True if the VT key is premium",
        "default": False,
        "mandatory": True,
        "type": "bool"
    },
    {
        "param_name": "vt_manual_hook_enabled",
        "param_human_name": "Enable manual triggers on IOCs",
        "param_description": "Set to True to offers possibility to manually triggers the module via the UI",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "vt_on_update_hook_enabled",
        "param_human_name": "Triggers on IOC update",
        "param_description": "Set to True to automatically add a VT insight each time an IOC is updated",
        "default": False,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "vt_on_create_hook_enabled",
        "param_human_name": "Triggers on IOC create",
        "param_description": "Set to True to automatically add a VT insight each time an IOC is created",
        "default": False,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "vt_ip_assign_asn_as_tag",
        "param_human_name": "Assign ASN tag to IP",
        "param_description": "Assign a new tag to IOC IPs with the ASN fetched from VT",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Insights"
    },
    {
        "param_name": "vt_report_as_attribute",
        "param_human_name": "Add VT report as new IOC attribute",
        "param_description": "Creates a new attribute on the IOC, base on the VT report. Attributes are based "
                             "on the templates of this configuration",
        "default": False,
        "mandatory": True,
        "type": "bool",
        "section": "Insights"
    },
    {
        "param_name": "vt_domain_report_template",
        "param_human_name": "Domain report template",
        "param_description": "Domain reports template used to add a new custom attribute to the target IOC",
        "default": "<div class=\"row\">\n    <div class=\"col-12\">\n        <h3>WHOIS</h3>\n        <blockquote "
                   "class=\"blockquote\">\n            {% autoescape false %}\n            <p>{{ whois| replace("
                   "\"\\n\", \"<br/>\") }}</p>\n            {% endautoescape %}\n        </blockquote>\n    "
                   "</div>\n</div>\n<hr/>\n<div class=\"row\">\n    <div class=\"col-12\">\n        "
                   "<h3>Resolutions</h3>\n        <ul>\n            {% for resolution in resolutions %} \n            "
                   "<li>{{resolution.ip_address}} ( Last resolved on {{resolution.last_resolved}} )</li>\n            "
                   "{% endfor %}\n        </ul>\n    </div>\n</div>\n",
        "mandatory": False,
        "type": "textfield_html",
        "section": "Templates"
    },
    {
        "param_name": "vt_ip_report_template",
        "param_human_name": "IP report template",
        "param_description": "IP report template used to add a new custom attribute to the target IOC",
        "default": "",
        "mandatory": False,
        "type": "textfield_html",
        "section": "Templates"
    },
    {
        "param_name": "vt_hash_report_template",
        "param_human_name": "Hash report template",
        "param_description": "Hash report template used to add a new custom attribute to the target IOC",
        "default": "",
        "mandatory": False,
        "type": "textfield_html",
        "section": "Templates"
    }
]