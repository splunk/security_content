---
title: "IcedID Exfiltrated Archived File Creation"
excerpt: "Archive via Utility, Archive Collected Data"
categories:
  - Endpoint
last_modified_at: 2021-07-30
toc: true
toc_label: ""
tags:
  - Archive via Utility
  - Collection
  - Archive Collected Data
  - Collection
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect a suspicious file creation namely passff.tar and cookie.tar. This files are possible archived of stolen browser information like history and cookies in a compromised machine with IcedID.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-07-30
- **Author**: Teoderick Contreras, Splunk
- **ID**: 0db4da70-f14b-11eb-8043-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | Archive via Utility | Collection |

| [T1560](https://attack.mitre.org/techniques/T1560/) | Archive Collected Data | Collection |

#### Search

```
`sysmon` EventCode= 11  (TargetFilename = "*\\passff.tar" OR TargetFilename = "*\\cookie.tar") 
|stats count min(_time) as firstTime max(_time) as lastTime by TargetFilename EventCode process_id  process_name Computer 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `icedid_exfiltrated_archived_file_creation_filter`
```

#### Associated Analytic Story
* [IcedID](/stories/icedid)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* TargetFilename
* EventCode
* process_id
* process_name
* Computer


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 80 | 90 | process $SourceImage$ create a file $TargetImage$ in host $Computer$ |




#### Reference

* [https://www.cisecurity.org/white-papers/security-primer-icedid/](https://www.cisecurity.org/white-papers/security-primer-icedid/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/simulated_icedid/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/simulated_icedid/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/icedid_exfiltrated_archived_file_creation.yml) \| *version*: **1**