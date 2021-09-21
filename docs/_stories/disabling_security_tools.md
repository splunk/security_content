---
title: "Disabling Security Tools"
last_modified_at: 2020-02-04
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Looks for activities and techniques associated with the disabling of security tools on a Windows system, such as suspicious `reg.exe` processes, processes launching netsh, and many others.

- **ID**: fcc27099-46a0-46b0-a271-5c7dab56b6f1
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-02-04
- **Author**: Rico Valdez, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Attempt To Add Certificate To Untrusted Store](/endpoint/attempt_to_add_certificate_to_untrusted_store/) | None | TTP |
| [Attempt To Stop Security Service](/endpoint/attempt_to_stop_security_service/) | None | TTP |
| [Processes launching netsh](/endpoint/processes_launching_netsh/) | None | TTP |
| [Sc exe Manipulating Windows Services](/endpoint/sc_exe_manipulating_windows_services/) | None | TTP |
| [Suspicious Reg exe Process](/endpoint/suspicious_reg_exe_process/) | None | TTP |
| [Unload Sysmon Filter Driver](/endpoint/unload_sysmon_filter_driver/) | None | TTP |

#### Reference

* [https://attack.mitre.org/wiki/Technique/T1089](https://attack.mitre.org/wiki/Technique/T1089)
* [https://blog.malwarebytes.com/cybercrime/2015/11/vonteera-adware-uses-certificates-to-disable-anti-malware/](https://blog.malwarebytes.com/cybercrime/2015/11/vonteera-adware-uses-certificates-to-disable-anti-malware/)
* [https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Tools-Report.pdf](https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Tools-Report.pdf)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/disabling_security_tools.yml) \| *version*: **2**