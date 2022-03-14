---
title: "Orangeworm Attack Group"
last_modified_at: 2020-01-22
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
  - Command & Control
  - Installation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Detect activities and various techniques associated with the Orangeworm Attack Group, a group that frequently targets the healthcare industry.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-01-22
- **Author**: David Dorsey, Splunk
- **ID**: bb9f5ed2-916e-4364-bb6d-97c370efcf52

#### Narrative

In May of 2018, the attack group Orangeworm was implicated for installing a custom backdoor called Trojan.Kwampirs within large international healthcare corporations in the United States, Europe, and Asia. This malware provides the attackers with remote access to the target system, decrypting and extracting a copy of its main DLL payload from its resource section. Before writing the payload to disk, it inserts a randomly generated string into the middle of the decrypted payload in an attempt to evade hash-based detections.\
Awareness of the Orangeworm group first surfaced in January, 2015. It has conducted targeted attacks against related industries, as well, such as pharmaceuticals and healthcare IT solution providers.\
Healthcare may be a promising target, because it is notoriously behind in technology, often using older operating systems and neglecting to patch computers. Even so, the group was able to evade detection for a full three years. Sources say that the malware spread quickly within the target networks, infecting computers used to control medical devices, such as MRI and X-ray machines.\
This Analytic Story is designed to help you detect and investigate suspicious activities that may be indicative of an Orangeworm attack. One detection search looks for command-line arguments. Another monitors for uses of sc.exe, a non-essential Windows file that can manipulate Windows services. One of the investigative searches helps you get more information on web hosts that you suspect have been compromised.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [First time seen command line argument](/deprecated/first_time_seen_command_line_argument/) | [PowerShell](/tags/#powershell), [Windows Command Shell](/tags/#windows-command-shell)| Hunting |
| [Sc exe Manipulating Windows Services](/endpoint/sc_exe_manipulating_windows_services/) | [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process)| TTP |
| [First Time Seen Running Windows Service](/endpoint/first_time_seen_running_windows_service/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution)| Anomaly |

#### Reference

* [https://www.symantec.com/blogs/threat-intelligence/orangeworm-targets-healthcare-us-europe-asia](https://www.symantec.com/blogs/threat-intelligence/orangeworm-targets-healthcare-us-europe-asia)
* [https://www.infosecurity-magazine.com/news/healthcare-targeted-by-hacker/](https://www.infosecurity-magazine.com/news/healthcare-targeted-by-hacker/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/orangeworm_attack_group.yml) \| *version*: **2**