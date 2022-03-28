---
title: "Detect AzureHound File Modifications"
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

The following analytic is similar to SharpHound file modifications, but this instance covers the use of Invoke-AzureHound. AzureHound is the SharpHound equivilent but for Azure. It's possible this may never be seen in an environment as most attackers may execute this tool remotely. Once execution is complete, a zip file with a similar name will drop `20210601090751-azurecollection.zip`. In addition to the zip, multiple .json files will be written to disk, which are in the zip.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-06-01
- **Author**: Michael Haag, Splunk
- **ID**: 1c34549e-c31b-11eb-996b-acde48001122


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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("*-azurecollection.zip", "*-azprivroleadminrights.json", "*-azglobaladminrights.json", "*-azcloudappadmins.json", "*-azapplicationadmins.json") by Filesystem.file_create_time Filesystem.process_id  Filesystem.file_name Filesystem.file_path Filesystem.dest 
| `drop_dm_object_name(Filesystem)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_azurehound_file_modifications_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `detect_azurehound_file_modifications_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* file_path
* dest
* file_name
* process_id
* file_create_time


#### How To Implement
To successfully implement this search you need to be ingesting information on file modifications that include the name of the process, and file, responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Filesystem` node.

#### Known False Positives
False positives should be limited as the analytic is specific to a filename with extension .zip. Filter as needed.

#### Associated Analytic story
* [Discovery Techniques](/stories/discovery_techniques)


#### Kill Chain Phase
* Reconnaissance



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 70 | 90 | A file - $file_name$ was written to disk that is related to AzureHound, a AzureAD enumeration utility, has occurred on endpoint $dest$ by user $user$. |




#### Reference

* [https://posts.specterops.io/introducing-bloodhound-4-0-the-azure-update-9b2b26c5e350](https://posts.specterops.io/introducing-bloodhound-4-0-the-azure-update-9b2b26c5e350)
* [https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/AzureHound.ps1](https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/AzureHound.ps1)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/sharphound/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/sharphound/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_azurehound_file_modifications.yml) \| *version*: **1**