---
title: "Detect AzureHound Command-Line Arguments"
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
last_modified_at: 2021-06-01
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

The following analytic identifies the common command-line argument used by AzureHound `Invoke-AzureHound`. Being the script is FOSS, function names may be modified, but these changes are dependent upon the operator. In most instances the defaults are used. This analytic works to identify the common command-line attributes used. It does not cover the entirety of every argument in order to avoid false positives.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-06-01
- **Author**: Michael Haag, Splunk
- **ID**: 26f02e96-c300-11eb-b611-acde48001122


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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process IN ("*invoke-azurehound*") by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_azurehound_command_line_arguments_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `detect_azurehound_command-line_arguments_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Known False Positives
Unknown.

#### Associated Analytic story
* [Discovery Techniques](/stories/discovery_techniques)


#### Kill Chain Phase
* Reconnaissance



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ using AzureHound to enumerate AzureAD. |




#### Reference

* [https://attack.mitre.org/software/S0521/](https://attack.mitre.org/software/S0521/)
* [https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors)
* [https://posts.specterops.io/introducing-bloodhound-4-0-the-azure-update-9b2b26c5e350](https://posts.specterops.io/introducing-bloodhound-4-0-the-azure-update-9b2b26c5e350)
* [https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/AzureHound.ps1](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/AzureHound.ps1)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/sharphound/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/sharphound/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_azurehound_command-line_arguments.yml) \| *version*: **1**