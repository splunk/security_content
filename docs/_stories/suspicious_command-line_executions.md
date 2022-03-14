---
title: "Suspicious Command-Line Executions"
last_modified_at: 2020-02-03
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
  - Command & Control
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leveraging the Windows command-line interface (CLI) is one of the most common attack techniques--one that is also detailed in the MITRE ATT&CK framework. Use this Analytic Story to help you identify unusual or suspicious use of the CLI on Windows systems.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-02-03
- **Author**: Bhavin Patel, Splunk
- **ID**: f4368ddf-d59f-4192-84f6-778ac5a3ffc7

#### Narrative

The ability to execute arbitrary commands via the Windows CLI is a primary goal for the adversary. With access to the shell, an attacker can easily run scripts and interact with the target system. Often, attackers may only have limited access to the shell or may obtain access in unusual ways. In addition, malware may execute and interact with the CLI in ways that would be considered unusual and inconsistent with typical user activity. This provides defenders with opportunities to identify suspicious use and investigate, as appropriate. This Analytic Story contains various searches to help identify this suspicious activity, as well as others to aid you in deeper investigation.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [First time seen command line argument](/deprecated/first_time_seen_command_line_argument/) | [PowerShell](/tags/#powershell), [Windows Command Shell](/tags/#windows-command-shell)| Hunting |
| [Detect Prohibited Applications Spawning cmd exe](/endpoint/detect_prohibited_applications_spawning_cmd_exe/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Windows Command Shell](/tags/#windows-command-shell)| Hunting |
| [Detect Use of cmd exe to Launch Script Interpreters](/endpoint/detect_use_of_cmd_exe_to_launch_script_interpreters/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Windows Command Shell](/tags/#windows-command-shell)| TTP |
| [Potentially malicious code on commandline](/endpoint/potentially_malicious_code_on_commandline/) | [Windows Command Shell](/tags/#windows-command-shell)| Anomaly |
| [System Processes Run From Unexpected Locations](/endpoint/system_processes_run_from_unexpected_locations/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities)| TTP |
| [Unusually Long Command Line](/endpoint/unusually_long_command_line/) | None| Anomaly |
| [Unusually Long Command Line - MLTK](/endpoint/unusually_long_command_line_-_mltk/) | None| Anomaly |

#### Reference

* [https://attack.mitre.org/wiki/Technique/T1059](https://attack.mitre.org/wiki/Technique/T1059)
* [https://www.microsoft.com/en-us/wdsi/threats/macro-malware](https://www.microsoft.com/en-us/wdsi/threats/macro-malware)
* [https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf](https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_command-line_executions.yml) \| *version*: **2**