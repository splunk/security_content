---
title: "Monitor for Updates"
last_modified_at: 2017-09-15
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Updates
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor your enterprise to ensure that your endpoints are being patched and updated. Adversaries notoriously exploit known vulnerabilities that could be mitigated by applying routine security patches.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Updates](https://docs.splunk.com/Documentation/CIM/latest/User/Updates)
- **Last Updated**: 2017-09-15
- **Author**: Rico Valdez, Splunk
- **ID**: 9ef8d677-7b52-4213-a038-99cfc7acc2d8

#### Narrative

It is a common best practice to ensure that endpoints are being patched and updated in a timely manner, in order to reduce the risk of compromise via a publicly disclosed vulnerability. Timely application of updates/patches is important to eliminate known vulnerabilities that may be exploited by various threat actors.\
Searches in this analytic story are designed to help analysts monitor endpoints for system patches and/or updates. This helps analysts identify any systems that are not successfully updated in a timely matter.\
Microsoft releases updates for Windows systems on a monthly cadence. They should be installed as soon as possible after following internal testing and validation procedures. Patches and updates for other systems or applications are typically released as needed.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [No Windows Updates in a time frame](/application/no_windows_updates_in_a_time_frame/) | None| Hunting |

#### Reference

* [https://learn.cisecurity.org/20-controls-download](https://learn.cisecurity.org/20-controls-download)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/monitor_for_updates.yml) \| *version*: **1**