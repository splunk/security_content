---
title: "CyclopsBLink"
last_modified_at: 2022-04-07
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

Leverage searches that allow you to detect and investigate unusual activities that might relate to the cyclopsblink malware including firewall modification, spawning more process, botnet c2 communication, defense evasion and etc. Cyclops Blink is a Linux ELF executable compiled for 32-bit x86 and PowerPC architecture that has targeted several network devices. The complete list of targeted devices is unknown at this time, but WatchGuard FireBox has specifically been listed as a target. The modular malware consists of core components and modules that are deployed as child processes using the Linux API fork. At this point, four modules have been identified that download and upload files, gather system information and contain updating mechanisms for the malware itself. Additional modules can be downloaded and executed from the command and control (C2) server.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-04-07
- **Author**: Teoderick Contreras, Splunk
- **ID**: 7c75b1c8-dfff-46f1-8250-e58df91b6fd9

#### Narrative

Adversaries may use this technique to maximize the impact on the target organization in operations where network wide availability interruption is the goal.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Linux Iptables Firewall Modification](/endpoint/linux_iptables_firewall_modification/) | [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall), [Impair Defenses](/tags/#impair-defenses)| Anomaly |
| [Linux Kworker Process In Writable Process Path](/endpoint/linux_kworker_process_in_writable_process_path/) | [Masquerade Task or Service](/tags/#masquerade-task-or-service), [Masquerading](/tags/#masquerading)| Hunting |
| [Linux Stdout Redirection To Dev Null File](/endpoint/linux_stdout_redirection_to_dev_null_file/) | [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall), [Impair Defenses](/tags/#impair-defenses)| Anomaly |

#### Reference

* [https://www.ncsc.gov.uk/files/Cyclops-Blink-Malware-Analysis-Report.pdf](https://www.ncsc.gov.uk/files/Cyclops-Blink-Malware-Analysis-Report.pdf)
* [https://www.trendmicro.com/en_us/research/22/c/cyclops-blink-sets-sights-on-asus-routers--.html](https://www.trendmicro.com/en_us/research/22/c/cyclops-blink-sets-sights-on-asus-routers--.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/cyclopsblink.yml) \| *version*: **1**