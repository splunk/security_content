---
title: "Suspicious Command-Line Executions"
last_modified_at: 2020-02-03
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Leveraging the Windows command-line interface (CLI) is one of the most common attack techniques--one that is also detailed in the MITRE ATT&CK framework. Use this Analytic Story to help you identify unusual or suspicious use of the CLI on Windows systems.

- **ID**: f4368ddf-d59f-4192-84f6-778ac5a3ffc7
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-02-03
- **Author**: Bhavin Patel, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Prohibited Applications Spawning cmd exe](/endpoint/detect_prohibited_applications_spawning_cmd_exe/) | None | Hunting |
| [Detect Prohibited Applications Spawning cmd exe](/endpoint/detect_prohibited_applications_spawning_cmd_exe/) | None | TTP |
| [Detect Use of cmd exe to Launch Script Interpreters](/endpoint/detect_use_of_cmd_exe_to_launch_script_interpreters/) | None | TTP |
| [System Processes Run From Unexpected Locations](/endpoint/system_processes_run_from_unexpected_locations/) | None | TTP |
| [Unusually Long Command Line](/endpoint/unusually_long_command_line/) | None | Anomaly |
| [Unusually Long Command Line - MLTK](/endpoint/unusually_long_command_line_-_mltk/) | None | Anomaly |

#### Kill Chain Phase



#### Reference

* [https://attack.mitre.org/wiki/Technique/T1059](https://attack.mitre.org/wiki/Technique/T1059)
* [https://www.microsoft.com/en-us/wdsi/threats/macro-malware](https://www.microsoft.com/en-us/wdsi/threats/macro-malware)
* [https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf](https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf)



_version_: 2