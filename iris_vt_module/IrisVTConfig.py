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
interface_version = "1.2.1"
module_version = "1.2.1"
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
        "param_human_name": "Manual triggers on IOCs",
        "param_description": "Set to True to offers possibility to manually triggers the module via the UI",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "vt_on_update_hook_enabled",
        "param_human_name": "Triggers automatically on IOC update",
        "param_description": "Set to True to automatically add a VT insight each time an IOC is updated",
        "default": False,
        "mandatory": True,
        "type": "bool",
        "section": "Triggers"
    },
    {
        "param_name": "vt_on_create_hook_enabled",
        "param_human_name": "Triggers automatically on IOC create",
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
        "param_name": "vt_tag_malicious_threshold",
        "param_human_name": "IOC tag malicious threshold",
        "param_description": "Tag the IOC has malicious if the percentage of detection is above the specified threshold",
        "default": "10",
        "mandatory": True,
        "type": "float",
        "section": "Insights"
    },
    {
        "param_name": "vt_tag_suspicious_threshold",
        "param_human_name": "IOC tag suspicious threshold",
        "param_description": "Tag the IOC has suspicious if the percentage of detection is above the specified "
                             "threshold",
        "default": "5",
        "mandatory": True,
        "type": "float",
        "section": "Insights"
    },
    {
        "param_name": "vt_report_as_attribute",
        "param_human_name": "Add VT report as new IOC attribute",
        "param_description": "Creates a new attribute on the IOC, base on the VT report. Attributes are based "
                             "on the templates of this configuration",
        "default": True,
        "mandatory": True,
        "type": "bool",
        "section": "Insights"
    },
    {
        "param_name": "vt_domain_report_template",
        "param_human_name": "Domain report template",
        "param_description": "Domain reports template used to add a new custom attribute to the target IOC",
        "default": "{% if nb_detected_urls %}\n<div class=\"row\">\n    <div class=\"col-12\">\n        <h3>Detected URLS</h3>\n        <dl class=\"row\">\n            <dt class=\"col-sm-3\">Total detected URLs</dt>\n            <dd class=\"col-sm-9\">{{ nb_detected_urls }}</dd>\n            \n            <dt class=\"col-sm-3\">Average detection ratio</dt>\n            <dd class=\"col-sm-9\">{{ avg_urls_detect_ratio }}</dd>\n        </dl>\n    </div>\n</div>    \n{% endif %}\n\n{% if nb_detected_samples %}\n<div class=\"row\">\n    <div class=\"col-12\">\n        <h3>Detected samples</h3>\n        <dl class=\"row\">\n            <dt class=\"col-sm-3\">Total detected samples</dt>\n            <dd class=\"col-sm-9\">{{ nb_detected_samples }}</dd>\n            \n            <dt class=\"col-sm-3\">Average detection ratio</dt>\n            <dd class=\"col-sm-9\">{{ avg_samples_detect_ratio }}</dd>\n        </dl>\n    </div>\n</div>    \n{% endif %}\n\n<div class=\"row\">\n    <div class=\"col-12\">\n        <div class=\"accordion\">\n            <h3>Additional information</h3>\n            {% if whois %}\n            <div class=\"card\">\n                <div class=\"card-header collapsed\" id=\"drop_wh\" data-toggle=\"collapse\" data-target=\"#drop_whois\" aria-expanded=\"false\" aria-controls=\"drop_resolutions\" role=\"button\">\n                    <div class=\"span-icon\">\n                        <div class=\"flaticon-user-6\"></div>\n                    </div>\n                    <div class=\"span-title\">\n                        WHOIS\n                    </div>\n                    <div class=\"span-mode\"></div>\n                </div>\n                <div id=\"drop_whois\" class=\"collapse\" aria-labelledby=\"drop_wh\" style=\"\">\n                    <div class=\"card-body\">\n                        <blockquote class=\"blockquote\">\n                            {% autoescape false %}\n                            <p>{{ whois| replace(\"\\n\", \"<br/>\") }}</p>\n                            {% endautoescape %}\n                        </blockquote>\n                    </div>\n                </div>\n            </div>\n            {% endif %}\n    \n            {% if resolutions %}\n            <div class=\"card\">\n                <div class=\"card-header collapsed\" id=\"drop_res\" data-toggle=\"collapse\" data-target=\"#drop_resolutions\" aria-expanded=\"false\" aria-controls=\"drop_resolutions\" role=\"button\">\n                    <div class=\"span-icon\">\n                        <div class=\"flaticon-file\"></div>\n                    </div>\n                    <div class=\"span-title\">\n                        Resolutions history\n                    </div>\n                    <div class=\"span-mode\"></div>\n                </div>\n                <div id=\"drop_resolutions\" class=\"collapse\" aria-labelledby=\"drop_res\" style=\"\">\n                    <div class=\"card-body\">\n                        <ul>\n                            {% for resolution in resolutions %} \n                            <li>{{resolution.ip_address}} ( Last resolved on {{resolution.last_resolved}} )</li>\n                            {% endfor %}\n                        </ul>\n                    </div>\n                </div>\n            </div>\n            {% endif %}\n            \n            {% if subdomains %}\n            <div class=\"card\">\n                <div class=\"card-header collapsed\" id=\"drop_sub\" data-toggle=\"collapse\" data-target=\"#drop_subdomains\" aria-expanded=\"false\" aria-controls=\"drop_subdomains\" role=\"button\">\n                    <div class=\"span-icon\">\n                        <div class=\"flaticon-diagram\"></div>\n                    </div>\n                    <div class=\"span-title\">\n                        Subdomains\n                    </div>\n                    <div class=\"span-mode\"></div>\n                </div>\n                <div id=\"drop_subdomains\" class=\"collapse\" aria-labelledby=\"drop_sub\" style=\"\">\n                    <div class=\"card-body\">\n                        <ul>\n                            {% for subdomain in subdomains %} \n                            <li>{{subdomain}}</li>\n                            {% endfor %}\n                        </ul>\n                    </div>\n                </div>\n            </div>\n            {% endif %}\n        </div>\n    </div>\n</div>\n\n<div class=\"row\">\n    <div class=\"col-12\">\n        <div class=\"accordion\">\n            <h3>Raw report</h3>\n\n            <div class=\"card\">\n                <div class=\"card-header collapsed\" id=\"drop_r\" data-toggle=\"collapse\" data-target=\"#drop_raw\" aria-expanded=\"false\" aria-controls=\"drop_raw\" role=\"button\">\n                    <div class=\"span-icon\">\n                        <div class=\"flaticon-file\"></div>\n                    </div>\n                    <div class=\"span-title\">\n                        Raw report\n                    </div>\n                    <div class=\"span-mode\"></div>\n                </div>\n                <div id=\"drop_raw\" class=\"collapse\" aria-labelledby=\"drop_r\" style=\"\">\n                    <div class=\"card-body\">\n                        <div id='vt_raw_ace'>{{ results| tojson(indent=4) }}</div>\n                    </div>\n                </div>\n            </div>\n        </div>\n    </div>\n</div> \n<script>\nvar vt_in_raw = ace.edit(\"vt_raw_ace\",\n{\n    autoScrollEditorIntoView: true,\n    minLines: 30,\n});\nvt_in_raw.setReadOnly(true);\nvt_in_raw.setTheme(\"ace/theme/tomorrow\");\nvt_in_raw.session.setMode(\"ace/mode/json\");\nvt_in_raw.renderer.setShowGutter(true);\nvt_in_raw.setOption(\"showLineNumbers\", true);\nvt_in_raw.setOption(\"showPrintMargin\", false);\nvt_in_raw.setOption(\"displayIndentGuides\", true);\nvt_in_raw.setOption(\"maxLines\", \"Infinity\");\nvt_in_raw.session.setUseWrapMode(true);\nvt_in_raw.setOption(\"indentedSoftWrap\", true);\nvt_in_raw.renderer.setScrollMargin(8, 5);\n</script>",
        "mandatory": False,
        "type": "textfield_html",
        "section": "Templates"
    },
    {
        "param_name": "vt_ip_report_template",
        "param_human_name": "IP report template",
        "param_description": "IP report template used to add a new custom attribute to the target IOC",
        "default": "<div class=\"row\">\n    <div class=\"col-12\">\n        <h3>Basic information</h3>\n        <dl class=\"row\">\n            {% if results.as_owner %}\n            <dt class=\"col-sm-3\">AS owner</dt>\n            <dd class=\"col-sm-9\">{{ results.as_owner }}</dd>\n            {% endif %}\n            \n            {% if country %}\n            <dt class=\"col-sm-3\">Country</dt>\n            <dd class=\"col-sm-9\">{{ results.country }}</dd>\n            {% endif %}\n        </dl>\n    </div>\n</div>    \n\n{% if nb_detected_urls %}\n<div class=\"row\">\n    <div class=\"col-12\">\n        <h3>Detected URLS</h3>\n        <dl class=\"row\">\n            <dt class=\"col-sm-3\">Total detected URLs</dt>\n            <dd class=\"col-sm-9\">{{ nb_detected_urls }}</dd>\n            \n            <dt class=\"col-sm-3\">Average detection ratio</dt>\n            <dd class=\"col-sm-9\">{{ avg_urls_detect_ratio }}</dd>\n        </dl>\n    </div>\n</div>    \n{% endif %}\n\n{% if nb_detected_samples %}\n<div class=\"row\">\n    <div class=\"col-12\">\n        <h3>Detected communicating samples</h3>\n        <dl class=\"row\">\n            <dt class=\"col-sm-3\">Total detected samples</dt>\n            <dd class=\"col-sm-9\">{{ nb_detected_samples }}</dd>\n            \n            <dt class=\"col-sm-3\">Average detection ratio</dt>\n            <dd class=\"col-sm-9\">{{ avg_samples_detect_ratio }}</dd>\n        </dl>\n    </div>\n</div>    \n{% endif %}\n\n<div class=\"row\">\n    <div class=\"col-12\">\n        <div class=\"accordion\">\n            <h3>Additional information</h3>\n\n            {% if results.resolutions %}\n            <div class=\"card\">\n                <div class=\"card-header collapsed\" id=\"drop_res\" data-toggle=\"collapse\" data-target=\"#drop_resolutions\" aria-expanded=\"false\" aria-controls=\"drop_resolutions\" role=\"button\">\n                    <div class=\"span-icon\">\n                        <div class=\"flaticon-file\"></div>\n                    </div>\n                    <div class=\"span-title\">\n                        Resolutions history\n                    </div>\n                    <div class=\"span-mode\"></div>\n                </div>\n                <div id=\"drop_resolutions\" class=\"collapse\" aria-labelledby=\"drop_res\" style=\"\">\n                    <div class=\"card-body\">\n                        <ul>\n                            {% for resolution in results.resolutions %} \n                            <li>{{ resolution.hostname }} ( Last resolved on {{resolution.last_resolved}} )</li>\n                            {% endfor %}\n                        </ul>\n                    </div>\n                </div>\n            </div>\n            {% endif %}\n            \n        </div>\n    </div>\n</div>\n\n<div class=\"row\">\n    <div class=\"col-12\">\n        <div class=\"accordion\">\n            <h3>Raw report</h3>\n\n            <div class=\"card\">\n                <div class=\"card-header collapsed\" id=\"drop_r\" data-toggle=\"collapse\" data-target=\"#drop_raw\" aria-expanded=\"false\" aria-controls=\"drop_raw\" role=\"button\">\n                    <div class=\"span-icon\">\n                        <div class=\"flaticon-file\"></div>\n                    </div>\n                    <div class=\"span-title\">\n                        Raw report\n                    </div>\n                    <div class=\"span-mode\"></div>\n                </div>\n                <div id=\"drop_raw\" class=\"collapse\" aria-labelledby=\"drop_r\" style=\"\">\n                    <div class=\"card-body\">\n                        <div id='vt_raw_ace'>{{ results| tojson(indent=4) }}</div>\n                    </div>\n                </div>\n            </div>\n        </div>\n    </div>\n</div> \n<script>\nvar vt_in_raw = ace.edit(\"vt_raw_ace\",\n{\n    autoScrollEditorIntoView: true,\n    minLines: 30,\n});\nvt_in_raw.setReadOnly(true);\nvt_in_raw.setTheme(\"ace/theme/tomorrow\");\nvt_in_raw.session.setMode(\"ace/mode/json\");\nvt_in_raw.renderer.setShowGutter(true);\nvt_in_raw.setOption(\"showLineNumbers\", true);\nvt_in_raw.setOption(\"showPrintMargin\", false);\nvt_in_raw.setOption(\"displayIndentGuides\", true);\nvt_in_raw.setOption(\"maxLines\", \"Infinity\");\nvt_in_raw.session.setUseWrapMode(true);\nvt_in_raw.setOption(\"indentedSoftWrap\", true);\nvt_in_raw.renderer.setScrollMargin(8, 5);\n</script>",
        "mandatory": False,
        "type": "textfield_html",
        "section": "Templates"
    },
    {
        "param_name": "vt_hash_report_template",
        "param_human_name": "Hash report template",
        "param_description": "Hash report template used to add a new custom attribute to the target IOC",
        "default": "<div class=\"row\">\n    <div class=\"col-12\">\n        <h3>Basic information</h3>\n        <dl class=\"row\">\n            {% if results.total %}\n            <dt class=\"col-sm-3\">Detection</dt>\n            <dd class=\"col-sm-9\">{{ results.positives }} / {{ results.total }}</dd>\n            {% endif %}\n            \n            {% if results.permalink %}\n            <dt class=\"col-sm-3\">Permalink</dt>\n            <dd class=\"col-sm-9\"><a href='{{ results.permalink }}'>{{ results.permalink }}</a></dd>\n            {% endif %}\n            \n            \n            {% if results.scan_date %}\n            <dt class=\"col-sm-3\">Scan date</dt>\n            <dd class=\"col-sm-9\">{{ results.scan_date }}</dd>\n            {% endif %}\n            \n            {% if results.md5 %}\n            <dt class=\"col-sm-3\">MD5</dt>\n            <dd class=\"col-sm-9\">{{ results.md5 }}</dd>\n            {% endif %}\n            \n            {% if results.sha256 %}\n            <dt class=\"col-sm-3\">SHA256</dt>\n            <dd class=\"col-sm-9\">{{ results.sha256 }}</dd>\n            {% endif %}\n        \n        </dl>\n    </div>\n</div>    \n\n<div class=\"row\">\n    <div class=\"col-12\">\n        <div class=\"accordion\">\n            <h3>Additional information</h3>\n\n            {% if results.scans %}\n            <div class=\"card\">\n                <div class=\"card-header collapsed\" id=\"drop_sc\" data-toggle=\"collapse\" data-target=\"#drop_scans\" aria-expanded=\"false\" aria-controls=\"drop_scans\" role=\"button\">\n                    <div class=\"span-icon\">\n                        <div class=\"flaticon-file\"></div>\n                    </div>\n                    <div class=\"span-title\">\n                        Scans results\n                    </div>\n                    <div class=\"span-mode\"></div>\n                </div>\n                <div id=\"drop_scans\" class=\"collapse\" aria-labelledby=\"drop_sc\" style=\"\">\n                    <div class=\"card-body\">\n                        <table class=\"table display table-bordered table-striped table-hover\" width=\"100%\" cellspacing=\"0\" id=\"vt_in_scans\" >\n                                <thead>\n                                  <tr>\n                                      <th>Engine</th>\n                                      <th>Detected</th>\n                                      <th>Result</th>\n                                      <th>Update</th>\n                                      <th>Version</th>\n                                  </tr>\n                                </thead>\n                                <tbody>\n                                {% for scan in results.scans %} \n                                    <tr role=\"row\">\n                                        <td>{{ scan }}</td>\n                                        <td>{{ results.scans[scan].detected }}</td>\n                                        <td>{{ results.scans[scan].result }}</td>\n                                        <td>{{ results.scans[scan].update }}</td>\n                                        <td>{{ results.scans[scan].version }}</td>\n                                    </tr>\n                                {% endfor %}\n                                </tbody>\n                        </table>\n                    </div>\n                </div>\n            </div>\n            {% endif %}\n            \n        </div>\n    </div>\n</div>\n\n<div class=\"row\">\n    <div class=\"col-12\">\n        <div class=\"accordion\">\n            <h3>Raw report</h3>\n\n            <div class=\"card\">\n                <div class=\"card-header collapsed\" id=\"drop_r\" data-toggle=\"collapse\" data-target=\"#drop_raw\" aria-expanded=\"false\" aria-controls=\"drop_raw\" role=\"button\">\n                    <div class=\"span-icon\">\n                        <div class=\"flaticon-file\"></div>\n                    </div>\n                    <div class=\"span-title\">\n                        Raw report\n                    </div>\n                    <div class=\"span-mode\"></div>\n                </div>\n                <div id=\"drop_raw\" class=\"collapse\" aria-labelledby=\"drop_r\" style=\"\">\n                    <div class=\"card-body\">\n                        <div id='vt_raw_ace'>{{ results| tojson(indent=4) }}</div>\n                    </div>\n                </div>\n            </div>\n        </div>\n    </div>\n</div> \n<script>\nvar vt_in_raw = ace.edit(\"vt_raw_ace\",\n{\n    autoScrollEditorIntoView: true,\n    minLines: 30,\n});\nvt_in_raw.setReadOnly(true);\nvt_in_raw.setTheme(\"ace/theme/tomorrow\");\nvt_in_raw.session.setMode(\"ace/mode/json\");\nvt_in_raw.renderer.setShowGutter(true);\nvt_in_raw.setOption(\"showLineNumbers\", true);\nvt_in_raw.setOption(\"showPrintMargin\", false);\nvt_in_raw.setOption(\"displayIndentGuides\", true);\nvt_in_raw.setOption(\"maxLines\", \"Infinity\");\nvt_in_raw.session.setUseWrapMode(true);\nvt_in_raw.setOption(\"indentedSoftWrap\", true);\nvt_in_raw.renderer.setScrollMargin(8, 5);\n\n{% if results.scans %}\n$(\"#vt_in_scans\").DataTable({\n    filter: true,\n    info: true,\n    ordering: true,\n    processing: true,\n});\n    \n{% endif %}\n\n</script>",
        "mandatory": False,
        "type": "textfield_html",
        "section": "Templates"
    }
]