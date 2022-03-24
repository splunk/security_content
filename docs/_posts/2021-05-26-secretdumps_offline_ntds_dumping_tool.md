---
title: "SecretDumps Offline NTDS Dumping Tool"
excerpt: "NTDS
, OS Credential Dumping
"
categories:
  - Endpoint
last_modified_at: 2021-05-26
toc: true
toc_label: ""
tags:
  - NTDS
  - OS Credential Dumping
  - Credential Access
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic detects a potential usage of secretsdump.py tool for dumping credentials (ntlm hash) from a copy of ntds.dit and SAM.Security,SYSTEM registrry hive. This technique was seen in some attacker that dump ntlm hashes offline after having a copy of ntds.dit and SAM/SYSTEM/SECURITY registry hive.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-05-26
- **Author**: Teoderick Contreras, Splunk
- **ID**: 5672819c-be09-11eb-bbfb-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1003.003](https://attack.mitre.org/techniques/T1003/003/) | NTDS | Credential Access |

| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | Credential Access |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name = "python*.exe" Processes.process = "*.py*" Processes.process = "*-ntds*" (Processes.process = "*-system*" OR Processes.process = "*-sam*" OR Processes.process = "*-security*" OR Processes.process = "*-bootkey*") by Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process Processes.dest Processes.user Processes.process_id Processes.process_guid 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `secretdumps_offline_ntds_dumping_tool_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `secretdumps_offline_ntds_dumping_tool_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.process_name
* Processes.process
* Processes.parent_process_name
* Processes.parent_process
* Processes.dest
* Processes.user
* Processes.process_id
* Processes.process_guid


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
unknown

#### Associated Analytic story
* [Credential Dumping](/stories/credential_dumping)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | A secretdump process $process_name$ with secretdump commandline $process$ to dump credentials in host $dest$ |




#### Reference

* [https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/honeypots/casper/datasets1/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/honeypots/casper/datasets1/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/secretdumps_offline_ntds_dumping_tool.yml) \| *version*: **1**