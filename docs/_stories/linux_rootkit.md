---
title: "Linux Rootkit"
last_modified_at: 2022-07-27
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
  - Reconnaissance
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and other system components. Rootkits are programs that hide the existence of malware by intercepting/hooking and modifying operating system API calls that supply system information.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-07-27
- **Author**: Michael Haag, Splunk
- **ID**: e30f4054-ac08-4999-b8bc-5cc46886c18d

#### Narrative

Rootkits or rootkit enabling functionality may reside at the user or kernel level in the operating system or lower, to include a hypervisor, Master Boot Record, or System Firmware. Rootkits have been seen for Windows, Linux, and Mac OS X systems. Linux rootkits may not standout as much as a Windows rootkit, therefore understanding what kernel modules are installed today and monitoring for new is important. As with any rootkit, it may blend in using a common kernel name or variation of legitimate names.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Linux File Created In Kernel Driver Directory](/endpoint/linux_file_created_in_kernel_driver_directory/) | [Kernel Modules and Extensions](/tags/#kernel-modules-and-extensions), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution)| Anomaly |
| [Linux Insert Kernel Module Using Insmod Utility](/endpoint/linux_insert_kernel_module_using_insmod_utility/) | [Kernel Modules and Extensions](/tags/#kernel-modules-and-extensions), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution)| Anomaly |
| [Linux Install Kernel Module Using Modprobe Utility](/endpoint/linux_install_kernel_module_using_modprobe_utility/) | [Kernel Modules and Extensions](/tags/#kernel-modules-and-extensions), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution)| Anomaly |
| [Linux Kernel Module Enumeration](/endpoint/linux_kernel_module_enumeration/) | [System Information Discovery](/tags/#system-information-discovery), [Rootkit](/tags/#rootkit)| Anomaly |

#### Reference

* [https://attack.mitre.org/techniques/T1014/](https://attack.mitre.org/techniques/T1014/)
* [https://content.fireeye.com/apt-41/rpt-apt41](https://content.fireeye.com/apt-41/rpt-apt41)
* [https://medium.com/chronicle-blog/winnti-more-than-just-windows-and-gates-e4f03436031a](https://medium.com/chronicle-blog/winnti-more-than-just-windows-and-gates-e4f03436031a)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/linux_rootkit.yml) \| *version*: **1**