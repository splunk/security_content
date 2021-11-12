---
title: "Esentutl SAM Copy"
excerpt: "Security Account Manager, OS Credential Dumping"
categories:
  - Endpoint
last_modified_at: 2021-08-18
toc: true
toc_label: ""
tags:
  - Security Account Manager
  - Credential Access
  - OS Credential Dumping
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the process - `esentutl.exe` - being used to capture credentials stored in ntds.dit or the SAM file on disk. During triage, review parallel processes and determine if legitimate activity. Upon determination of illegitimate activity, take further action to isolate and contain the threat.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-08-18
- **Author**: Michael Haag, Splunk
- **ID**: d372f928-ce4f-11eb-a762-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1003.002](https://attack.mitre.org/techniques/T1003/002/) | Security Account Manager | Credential Access |

| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | Credential Access |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_esentutl` Processes.process IN ("*ntds*", "*SAM*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.original_file_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `esentutl_sam_copy_filter`
```

#### Associated Analytic Story
* [Credential Dumping](/stories/credential_dumping)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.parent_process
* Processes.original_file_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_path
* Processes.process_path
* Processes.parent_process_id


#### Kill Chain Phase
* Privilege Escalation
* Lateral Movement


#### Known False Positives
False positives should be limited. Filter as needed.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user user$ attempting to capture credentials for offline cracking or observability. |




#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/6a570c2a4630cf0c2bd41a2e8375b5d5ab92f700/atomics/T1003.002/T1003.002.md](https://github.com/redcanaryco/atomic-red-team/blob/6a570c2a4630cf0c2bd41a2e8375b5d5ab92f700/atomics/T1003.002/T1003.002.md)
* [https://attack.mitre.org/software/S0404/](https://attack.mitre.org/software/S0404/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/esentutl_sam_copy.yml) \| *version*: **1**