---
title: "Detect SharpHound Usage"
excerpt: "Domain Account
, Local Groups
, Domain Trust Discovery
, Local Account
, Account Discovery
, Domain Groups
, Permission Groups Discovery
"
categories:
  - Endpoint
last_modified_at: 2021-05-27
toc: true
toc_label: ""
tags:
  - Domain Account
  - Local Groups
  - Domain Trust Discovery
  - Local Account
  - Account Discovery
  - Domain Groups
  - Permission Groups Discovery
  - Discovery
  - Discovery
  - Discovery
  - Discovery
  - Discovery
  - Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies SharpHound binary usage by using the original filena,e. In addition to renaming the PE, other coverage is available to detect command-line arguments. This particular analytic looks for the original_file_name of `SharpHound.exe` and the process name. It is possible older instances of SharpHound.exe have different original filenames. Dependent upon the operator, the code may be re-compiled and the attributes removed or changed to anything else. During triage, review the metadata of the binary in question. Review parallel processes for suspicious behavior. Identify the source of this binary.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-05-27
- **Author**: Michael Haag, Splunk
- **ID**: dd04b29a-beed-11eb-87bc-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | Domain Account | Discovery |

| [T1069.001](https://attack.mitre.org/techniques/T1069/001/) | Local Groups | Discovery |

| [T1482](https://attack.mitre.org/techniques/T1482/) | Domain Trust Discovery | Discovery |

| [T1087.001](https://attack.mitre.org/techniques/T1087/001/) | Local Account | Discovery |

| [T1087](https://attack.mitre.org/techniques/T1087/) | Account Discovery | Discovery |

| [T1069.002](https://attack.mitre.org/techniques/T1069/002/) | Domain Groups | Discovery |

| [T1069](https://attack.mitre.org/techniques/T1069/) | Permission Groups Discovery | Discovery |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=sharphound.exe OR Processes.original_file_name=SharpHound.exe) by Processes.dest Processes.user Processes.parent_process_name Processes.original_file_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_sharphound_usage_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `detect_sharphound_usage_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
False positives should be limited as this is specific to a file attribute not used by anything else. Filter as needed.

#### Associated Analytic story
* [Discovery Techniques](/stories/discovery_techniques)
* [Ransomware](/stories/ransomware)


#### Kill Chain Phase
* Reconnaissance



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 24.0 | 30 | 80 | Potential SharpHound binary identified on $dest$ |




#### Reference

* [https://attack.mitre.org/software/S0521/](https://attack.mitre.org/software/S0521/)
* [https://thedfirreport.com/?s=bloodhound](https://thedfirreport.com/?s=bloodhound)
* [https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors)
* [https://github.com/BloodHoundAD/SharpHound3](https://github.com/BloodHoundAD/SharpHound3)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md#atomic-test-2---run-bloodhound-from-local-disk](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md#atomic-test-2---run-bloodhound-from-local-disk)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/sharphound/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/sharphound/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_sharphound_usage.yml) \| *version*: **2**