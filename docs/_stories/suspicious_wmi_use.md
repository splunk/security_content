---
title: "Suspicious WMI Use"
last_modified_at: 2018-10-23
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Attackers are increasingly abusing Windows Management Instrumentation (WMI), a framework and associated utilities available on all modern Windows operating systems. Because WMI can be leveraged to manage both local and remote systems, it is important to identify the processes executed and the user context within which the activity occurred.

- **ID**: c8ddc5be-69bc-4202-b3ab-4010b27d7ad5
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2018-10-23
- **Author**: Rico Valdez, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect WMI Event Subscription Persistence](/endpoint/detect_wmi_event_subscription_persistence/) | None | TTP |
| [Process Execution via WMI](/endpoint/process_execution_via_wmi/) | None | TTP |
| [Remote Process Instantiation via WMI](/endpoint/remote_process_instantiation_via_wmi/) | None | TTP |
| [Remote WMI Command Attempt](/endpoint/remote_wmi_command_attempt/) | None | TTP |
| [Script Execution via WMI](/endpoint/script_execution_via_wmi/) | None | TTP |
| [WMI Permanent Event Subscription](/endpoint/wmi_permanent_event_subscription/) | None | TTP |
| [WMI Permanent Event Subscription - Sysmon](/endpoint/wmi_permanent_event_subscription_-_sysmon/) | None | TTP |
| [WMI Temporary Event Subscription](/endpoint/wmi_temporary_event_subscription/) | None | TTP |

#### Kill Chain Phase



#### Reference

* [https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf](https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf)
* [https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html](https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html)



_version_: 2