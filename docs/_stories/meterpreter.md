---
title: "Meterpreter"
last_modified_at: 2021-06-08
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

Meterpreter provides red teams, pen testers and threat actors interactive access to a compromised host to run commands, upload payloads, download files, and other actions.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-06-08
- **Author**: Michael Hart
- **ID**: d5f8e298-c85a-11eb-9fea-acde48001122

#### Narrative

This Analytic Story supports you to detect Tactics, Techniques and Procedures (TTPs) from Meterpreter. Meterpreter is a Metasploit payload for remote execution that leverages DLL injection to make it extremely difficult to detect.  Since the software runs in memory, no new processes are created upon injection.  It also leverages encrypted communication channels.\
Meterpreter enables the operator to remotely run commands on the target machine, upload payloads, download files, dump password hashes, and much more.  It is difficult to determine from the forensic evidence what actions the operator performed.  Splunk Research, however, has observed anomalous behaviors on the compromised hosts that seem to only appear when Meterpreter is executing various commands.  With that, we have written new detections targeted to these detections.\
While investigating a detection related to this analytic story, please bear in mind that the detections look for anomalies in system behavior.  It will be imperative to look for other signs in the endpoint and network logs for lateral movement, discovery and other actions to confirm that the host was compromised and a remote actor used it to progress on their objectives.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Excessive distinct processes from Windows Temp](/endpoint/excessive_distinct_processes_from_windows_temp/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter)| Anomaly |
| [Excessive number of taskhost processes](/endpoint/excessive_number_of_taskhost_processes/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery)| Anomaly |

#### Reference

* [https://www.offensive-security.com/metasploit-unleashed/about-meterpreter/](https://www.offensive-security.com/metasploit-unleashed/about-meterpreter/)
* [https://doubleoctopus.com/security-wiki/threats-and-tools/meterpreter/](https://doubleoctopus.com/security-wiki/threats-and-tools/meterpreter/)
* [https://www.rapid7.com/products/metasploit/](https://www.rapid7.com/products/metasploit/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/meterpreter.yml) \| *version*: **1**