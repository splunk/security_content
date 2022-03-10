---
title: "DarkSide Ransomware"
last_modified_at: 2021-05-12
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the DarkSide Ransomware

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-12
- **Author**: Bhavin Patel, Splunk
- **ID**: 507edc74-13d5-4339-878e-b9114ded1f35

#### Narrative

This story addresses Darkside ransomware. This ransomware payload has many similarities to common ransomware however there are certain items particular to it. The creation of a .TXT log that shows every item being encrypted as well as the creation of ransomware notes and files adding a machine ID created based on CRC32 checksum algorithm. This ransomware payload leaves machines in minimal operation level,enough to browse the attackers websites. A customized URI with leaked information is presented to each victim.This is the ransomware payload that shut down the Colonial pipeline. The story is composed of several detection searches covering similar items to other ransomware payloads and those particular to Darkside payload.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Attempted Credential Dump From Registry via Reg exe](/detection/attempted_credential_dump_from_registry_via_reg_exe/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping)| TTP |

#### Reference

* [https://www.splunk.com/en_us/blog/security/the-darkside-of-the-ransomware-pipeline.htmlbig-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/](https://www.splunk.com/en_us/blog/security/the-darkside-of-the-ransomware-pipeline.htmlbig-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/)
* [https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html](https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/darkside_ransomware.yml) \| *version*: **1**