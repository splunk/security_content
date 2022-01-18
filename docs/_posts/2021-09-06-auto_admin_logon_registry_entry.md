---
title: "Auto Admin Logon Registry Entry"
excerpt: "Credentials in Registry, Unsecured Credentials"
categories:
  - Endpoint
last_modified_at: 2021-09-06
toc: true
toc_label: ""
tags:
  - Credentials in Registry
  - Credential Access
  - Unsecured Credentials
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

this search is to detect a suspicious registry modification to implement auto admin logon to a host. This technique was seen in BlackMatter ransomware to automatically logon to the compromise host after  triggering a safemode boot to continue encrypting the whole network. This behavior is not a common practice and really a suspicious TTP or alert need to be consider if found within then network premise.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-06
- **Author**: Teoderick Contreras, Splunk
- **ID**: 1379d2b8-0f18-11ec-8ca3-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1552.002](https://attack.mitre.org/techniques/T1552/002/) | Credentials in Registry | Credential Access |

| [T1552](https://attack.mitre.org/techniques/T1552/) | Unsecured Credentials | Credential Access |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path= "*SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon*" AND Registry.registry_key_name=AutoAdminLogon AND Registry.registry_value_name=1 by Registry.registry_path Registry.registry_key_name Registry.registry_value_name Registry.dest 
| `drop_dm_object_name(Registry)` 
| `security_content_ctime(firstTime)` 
|`security_content_ctime(lastTime)` 
| `auto_admin_logon_registry_entry_filter`
```

#### Associated Analytic Story
* [BlackMatter Ransomware](/stories/blackmatter_ransomware)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Registry` node. Also make sure that this registry was included in your config files ex. sysmon config to be monitored.

#### Required field
* _time
* Registry.registry_path
* Registry.registry_key_name
* Registry.registry_value_name
* Registry.dest


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 70 | 90 | modified registry key $registry_key_name$ with registry value $registry_value_name$ to prepare autoadminlogon |




#### Reference

* [https://news.sophos.com/en-us/2021/08/09/blackmatter-ransomware-emerges-from-the-shadow-of-darkside/](https://news.sophos.com/en-us/2021/08/09/blackmatter-ransomware-emerges-from-the-shadow-of-darkside/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552.002/autoadminlogon/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552.002/autoadminlogon/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/auto_admin_logon_registry_entry.yml) \| *version*: **1**