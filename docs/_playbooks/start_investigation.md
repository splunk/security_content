---
title: "Start Investigation"
last_modified_at: 2021-10-07
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Handle cases in Splunk SOAR with consistency that only automation can provide. This playbook ensures that cases are being assigned to analysts, and follow on work gets started.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: 
- **Last Updated**: 2021-10-07
- **Author**: Kelby Shelton, Splunk
- **ID**: fc5adc76-f3ab-4cb0-5f6f-63bc3493fd46

#### Associated Detections


#### How To Implement
This is a playbook that is designed to be recommended within a workbook. If used in this manner, the playbook will assign the user that launched the playbook as the owner of the event, move the event status to "Open", and complete the workbook task where this playbook appears. If there is a task after the one where the playbook appears (within the same phase), it will set the next task to "In Progress."

#### Playbooks
![](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/start_investigation.png)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/start_investigation.yml) \| *version*: **1**