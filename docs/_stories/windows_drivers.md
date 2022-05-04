---
title: "Windows Drivers"
last_modified_at: 2022-03-30
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

Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and other system components.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-03-30
- **Author**: Michael Haag, Splunk
- **ID**: d0a9323f-9411-4da6-86b2-18c184d750c0

#### Narrative

A rootkit on Windows may sometimes be in the form of a Windows Driver. A driver typically has a file extension of .sys, however the internals of a sys file is similar to a Windows DLL. For Microsoft Windows to load a driver, a few requirements are needed. First, it must have a valid signature. Second, typically it should load from the windows\system32\drivers path. There are a few methods to investigate drivers in the environment. Drivers are noisy. An inventory of all drivers is important to understand prevalence. A driver location (Path) is also important when attempting to baseline. Looking at a driver name and path is not enough, we must also explore the signing information. Product, description, company name, signer and signing result are all items to take into account when reviewing drivers. What makes a driver malicious? Depending if a driver was dropped during a campaign or you are baselining drivers after, triaging a driver to determine maliciousness may be tough. We break this into two categories - 1. vulnerable drivers 2. driver rootkits. Attempt to identify prevelance of the driver. Is it on one or many? Review the signing information if it is present. Is it common? A lot of driver hunting will lead down rabbit holes, but we hope to help lead the way.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Windows Drivers Loaded by Signature](/endpoint/windows_drivers_loaded_by_signature/) | [Rootkit](/tags/#rootkit)| Hunting |
| [Windows Registry Certificate Added](/endpoint/windows_registry_certificate_added/) | [Install Root Certificate](/tags/#install-root-certificate), [Subvert Trust Controls](/tags/#subvert-trust-controls)| TTP |
| [Windows Registry Modification for Safe Mode Persistence](/endpoint/windows_registry_modification_for_safe_mode_persistence/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution)| TTP |

#### Reference

* [https://redcanary.com/blog/tracking-driver-inventory-to-expose-rootkits/](https://redcanary.com/blog/tracking-driver-inventory-to-expose-rootkits/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_drivers.yml) \| *version*: **1**