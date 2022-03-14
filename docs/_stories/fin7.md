---
title: "FIN7"
last_modified_at: 2021-09-14
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the FIN7 JS Implant and JSSLoader, including looking for Image Loading of ldap and wmi modules, associated with its payload, data collection and script execution.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-14
- **Author**: Teoderick Contreras, Splunk
- **ID**: df2b00d3-06ba-49f1-b253-b19cef19b569

#### Narrative

FIN7 is a Russian criminal advanced persistent threat group that has primarily targeted the U.S. retail, restaurant, and hospitality sectors since mid-2015. A portion of FIN7 is run out of the front company Combi Security. It has been called one of the most successful criminal hacking groups in the world. this passed few day FIN7 tools and implant are seen in the wild where its code is updated. the FIN& is known to use the spear phishing attack as a entry to targetted network or host that will drop its staging payload like the JS and JSSloader. Now this artifacts and implants seen downloading other malware like cobaltstrike and event ransomware to encrypt host.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Check Elevated CMD using whoami](/endpoint/check_elevated_cmd_using_whoami/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery)| TTP |
| [Cmdline Tool Not Executed In CMD Shell](/endpoint/cmdline_tool_not_executed_in_cmd_shell/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [JavaScript](/tags/#javascript)| TTP |
| [Jscript Execution Using Cscript App](/endpoint/jscript_execution_using_cscript_app/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [JavaScript](/tags/#javascript)| TTP |
| [MS Scripting Process Loading Ldap Module](/endpoint/ms_scripting_process_loading_ldap_module/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [JavaScript](/tags/#javascript)| Anomaly |
| [MS Scripting Process Loading WMI Module](/endpoint/ms_scripting_process_loading_wmi_module/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [JavaScript](/tags/#javascript)| Anomaly |
| [Non Chrome Process Accessing Chrome Default Dir](/endpoint/non_chrome_process_accessing_chrome_default_dir/) | [Credentials from Password Stores](/tags/#credentials-from-password-stores), [Credentials from Web Browsers](/tags/#credentials-from-web-browsers)| Anomaly |
| [Non Firefox Process Access Firefox Profile Dir](/endpoint/non_firefox_process_access_firefox_profile_dir/) | [Credentials from Password Stores](/tags/#credentials-from-password-stores), [Credentials from Web Browsers](/tags/#credentials-from-web-browsers)| Anomaly |
| [Office Application Drop Executable](/endpoint/office_application_drop_executable/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment)| TTP |
| [Office Product Spawning Wmic](/endpoint/office_product_spawning_wmic/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment)| TTP |
| [Vbscript Execution Using Wscript App](/endpoint/vbscript_execution_using_wscript_app/) | [Visual Basic](/tags/#visual-basic), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter)| TTP |
| [Wscript Or Cscript Suspicious Child Process](/endpoint/wscript_or_cscript_suspicious_child_process/) | [Process Injection](/tags/#process-injection), [Create or Modify System Process](/tags/#create-or-modify-system-process), [Parent PID Spoofing](/tags/#parent-pid-spoofing), [Access Token Manipulation](/tags/#access-token-manipulation)| TTP |
| [XSL Script Execution With WMIC](/endpoint/xsl_script_execution_with_wmic/) | [XSL Script Processing](/tags/#xsl-script-processing)| TTP |

#### Reference

* [https://en.wikipedia.org/wiki/FIN7](https://en.wikipedia.org/wiki/FIN7)
* [https://threatpost.com/fin7-windows-11-release/169206/](https://threatpost.com/fin7-windows-11-release/169206/)
* [https://www.proofpoint.com/us/blog/threat-insight/jssloader-recoded-and-reloaded](https://www.proofpoint.com/us/blog/threat-insight/jssloader-recoded-and-reloaded)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/fin7.yml) \| *version*: **1**