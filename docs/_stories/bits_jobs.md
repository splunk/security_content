---
title: "BITS Jobs"
last_modified_at: 2021-03-26
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Adversaries may abuse BITS jobs to persistently execute or clean up after malicious payloads.

- **ID**: dbc7edce-8e4c-11eb-9f31-acde48001122
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-03-26
- **Author**: Michael Haag, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [BITS Job Persistence](/endpoint/bits_job_persistence/) | None | TTP |
| [BITSAdmin Download File](/endpoint/bitsadmin_download_file/) | None | TTP |
| [PowerShell Start-BitsTransfer](/endpoint/powershell_start-bitstransfer/) | None | TTP |

#### Reference

* [https://attack.mitre.org/techniques/T1197/](https://attack.mitre.org/techniques/T1197/)
* [https://docs.microsoft.com/en-us/windows/win32/bits/bitsadmin-tool](https://docs.microsoft.com/en-us/windows/win32/bits/bitsadmin-tool)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/bits_jobs.yml) \| *version*: **1**