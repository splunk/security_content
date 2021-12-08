---
title: "Drop IcedID License dat"
excerpt: "User Execution, Malicious File"
categories:
  - Endpoint
last_modified_at: 2021-07-30
toc: true
toc_label: ""
tags:
  - User Execution
  - Execution
  - Malicious File
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect dropping a suspicious file named as &#34;license.dat&#34; in %appdata%. This behavior seen in latest IcedID malware that contain the actual core bot that will be injected in other process to do banking stealing.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-07-30
- **Author**: Teoderick Contreras, Splunk
- **ID**: b7a045fc-f14a-11eb-8e79-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1204](https://attack.mitre.org/techniques/T1204/) | User Execution | Execution |

| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Malicious File | Execution |

#### Search

```
`sysmon` EventCode= 11  TargetFilename = "*\\license.dat" AND (TargetFilename="*\\appdata\\*" OR TargetFilename="*\\programdata\\*") 
|stats count min(_time) as firstTime max(_time) as lastTime by TargetFilename EventCode process_id  process_name Computer 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `drop_icedid_license_dat_filter`
```

#### Associated Analytic Story
* [IcedID](/stories/icedid)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 70 | 90 | process $SourceImage$ create a file $TargetImage$ in host $Computer$ |




#### Reference

* [https://www.cisecurity.org/white-papers/security-primer-icedid/](https://www.cisecurity.org/white-papers/security-primer-icedid/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/simulated_icedid/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/simulated_icedid/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/drop_icedid_license_dat.yml) \| *version*: **1**