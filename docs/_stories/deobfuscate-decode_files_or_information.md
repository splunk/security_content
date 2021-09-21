---
title: "Deobfuscate-Decode Files or Information"
last_modified_at: 2021-03-24
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Adversaries may use Obfuscated Files or Information to hide artifacts of an intrusion from analysis.

- **ID**: 0bd01a54-8cbe-11eb-abcd-acde48001122
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-03-24
- **Author**: Michael Haag, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [CertUtil With Decode Argument](/endpoint/certutil_with_decode_argument/) | None | TTP |

#### Reference

* [https://attack.mitre.org/techniques/T1140/](https://attack.mitre.org/techniques/T1140/)



[_source_](https://github.com/splunk/security_content/tree/develop/stories/deobfuscate-decode_files_or_information.yml) | _version_: **1**