---
title: "Monitor Backup Solution"
last_modified_at: 2017-09-12
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Address common concerns when monitoring your backup processes. These searches can help you reduce risks from ransomware, device theft, or denial of physical access to a host by backing up data on endpoints.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2017-09-12
- **Author**: David Dorsey, Splunk
- **ID**: abe807c7-1eb6-4304-ac32-6e7aacdb891d

#### Narrative

Having backups is a standard best practice that helps ensure continuity of business operations.  Having mature backup processes can also help you reduce the risks of many security-related incidents and streamline your response processes. The detection searches in this Analytic Story will help you identify systems that have backup failures, as well as systems that have not been backed up for an extended period of time. The story will also return the notable event history and all of the backup logs for an endpoint.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Extended Period Without Successful Netbackup Backups](/deprecated/extended_period_without_successful_netbackup_backups/) | None| Hunting |
| [Unsuccessful Netbackup backups](/deprecated/unsuccessful_netbackup_backups/) | None| Hunting |

#### Reference

* [https://www.carbonblack.com/2016/03/04/tracking-locky-ransomware-using-carbon-black/](https://www.carbonblack.com/2016/03/04/tracking-locky-ransomware-using-carbon-black/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/monitor_backup_solution.yml) \| *version*: **1**