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
module_description = "Provides an interface between VT and IRIS"
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
        "param_name": "vt_ip_assign_asn_as_tag",
        "param_human_name": "Assign ASN tag to IP",
        "param_description": "Assign a new tag to IOC IPs with the ASN fetched from VT",
        "default": True,
        "mandatory": True,
        "type": "bool"
    },
    {
        "param_name": "vt_domain_add_whois_as_desc",
        "param_human_name": "Add domain whois information",
        "param_description": "Add whois information into the description of IOCs of type domain",
        "default": True,
        "mandatory": True,
        "type": "bool"
    },
    {
        "param_name": "vt_domain_add_subdomain_as_desc",
        "param_human_name": "Add subdomains in IOC description",
        "param_description": "Add subdomains information into the description of IOCs of type domain",
        "default": False,
        "mandatory": True,
        "type": "bool"
    }
]