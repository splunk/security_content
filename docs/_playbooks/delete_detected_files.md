---
title: "Delete Detected Files"
last_modified_at: 2021-03-29
toc: true
toc_label: ""
tags:
  - Response
  - Splunk SOAR
  - Windows Remote Management
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

This playbook acts upon events where a file has been determined to be malicious (ie webshells being dropped on an end host). Before deleting the file, we run a "more" command on the file in question to extract its contents. We then run a delete on the file in question.

- **Type**: Response
- **Product**: Splunk SOAR
- **Apps**: [Windows Remote Management](https://splunkbase.splunk.com/apps/#/search/Windows Remote Management/product/soar)
- **Last Updated**: 2021-03-29
- **Author**: Philip Royer, Splunk
- **ID**: fc0edc96-ff2b-48b0-9a6f-63da6783fd63

#### Associated Detections

* [Executable File Written in Administrative SMB Share](/detection/executable_file_written_in_administrative_smb_share/)



#### How To Implement
This playbook reads and then deletes files stored with artifact:*.cef.filePath from hosts stored in artifact:*.cef.destinationAddress. Windows Remote Management must be enabled on the remote computer.

#### Playbooks
![](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/delete_detected_files.png)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/delete_detected_files.yml) \| *version*: **1**