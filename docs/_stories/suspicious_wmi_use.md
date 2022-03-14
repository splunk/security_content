---
title: "Suspicious WMI Use"
last_modified_at: 2018-10-23
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Attackers are increasingly abusing Windows Management Instrumentation (WMI), a framework and associated utilities available on all modern Windows operating systems. Because WMI can be leveraged to manage both local and remote systems, it is important to identify the processes executed and the user context within which the activity occurred.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2018-10-23
- **Author**: Rico Valdez, Splunk
- **ID**: c8ddc5be-69bc-4202-b3ab-4010b27d7ad5

#### Narrative

WMI is a Microsoft infrastructure for management data and operations on Windows operating systems. It includes of a set of utilities that can be leveraged to manage both local and remote Windows systems. Attackers are increasingly turning to WMI abuse in their efforts to conduct nefarious tasks, such as reconnaissance, detection of antivirus and virtual machines, code execution, lateral movement, persistence, and data exfiltration. The detection searches included in this Analytic Story are used to look for suspicious use of WMI commands that attackers may leverage to interact with remote systems. The searches specifically look for the use of WMI to run processes on remote systems. In the event that unauthorized WMI execution occurs, it will be important for analysts and investigators to determine the context of the event. These details may provide insights related to how WMI was used and to what end.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect WMI Event Subscription Persistence](/endpoint/detect_wmi_event_subscription_persistence/) | [Windows Management Instrumentation Event Subscription](/tags/#windows-management-instrumentation-event-subscription), [Event Triggered Execution](/tags/#event-triggered-execution)| TTP |
| [Process Execution via WMI](/endpoint/process_execution_via_wmi/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation)| TTP |
| [Remote Process Instantiation via WMI](/endpoint/remote_process_instantiation_via_wmi/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation)| TTP |
| [Remote WMI Command Attempt](/endpoint/remote_wmi_command_attempt/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation)| TTP |
| [Script Execution via WMI](/endpoint/script_execution_via_wmi/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation)| TTP |
| [Windows WMI Process Call Create](/endpoint/windows_wmi_process_call_create/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation)| Hunting |
| [WMI Permanent Event Subscription - Sysmon](/endpoint/wmi_permanent_event_subscription_-_sysmon/) | [Windows Management Instrumentation Event Subscription](/tags/#windows-management-instrumentation-event-subscription), [Event Triggered Execution](/tags/#event-triggered-execution)| TTP |
| [WMIC XSL Execution via URL](/endpoint/wmic_xsl_execution_via_url/) | [XSL Script Processing](/tags/#xsl-script-processing)| TTP |
| [XSL Script Execution With WMIC](/endpoint/xsl_script_execution_with_wmic/) | [XSL Script Processing](/tags/#xsl-script-processing)| TTP |
| [WMI Permanent Event Subscription](/endpoint/wmi_permanent_event_subscription/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation)| TTP |
| [WMI Temporary Event Subscription](/endpoint/wmi_temporary_event_subscription/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation)| TTP |

#### Reference

* [https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf](https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf)
* [https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html](https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_wmi_use.yml) \| *version*: **2**