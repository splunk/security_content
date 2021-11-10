---
title: "Enable WDigest UseLogonCredential Registry"
excerpt: "Modify Registry, OS Credential Dumping"
categories:
  - Endpoint
last_modified_at: 2021-10-05
toc: true
toc_label: ""
tags:
  - Modify Registry
  - Defense Evasion
  - OS Credential Dumping
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to detect a suspicious registry modification to enable plain text credential feature of windows. This technique was used by several malware and also by mimikatz to be able to dumpe the a plain text credential to the compromised or target host. This TTP is really a good indicator that someone wants to dump the crendential of the host so it must be a good pivot for credential dumping techniques.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-10-05
- **Author**: Teoderick Contreras, Splunk
- **ID**: 0c7d8ffe-25b1-11ec-9f39-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1112](https://attack.mitre.org/techniques/T1112/) | Modify Registry | Defense Evasion |

| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | Credential Access |

#### Search

```

| tstats `security_content_summariesonly` count  min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Registry where Registry.registry_path="*\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\*" Registry.registry_value_name = "UseLogonCredential" Registry.registry_value_data = 0x00000001 by Registry.dest Registry.user Registry.registry_value_name Registry.registry_key_name Registry.registry_path Registry.registry_value_data 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `enable_wdigest_uselogoncredential_registry_filter`
```

#### Associated Analytic Story
* [Credential Dumping](/stories/credential_dumping)


#### How To Implement
To successfully implement this search, you must be ingesting data that records registry activity from your hosts to populate the endpoint data model in the registry node. This is typically populated via endpoint detection-and-response product, such as Carbon Black or endpoint data sources, such as Sysmon. The data used for this search is typically generated via logs that report reads and writes to the registry.

#### Required field
* _time
* Registry.dest
* Registry.user
* Registry.registry_value_name
* Registry.registry_key_name
* Registry.registry_path
* Registry.registry_value_data


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | wdigest registry $registry_path$ was modified in $dest$ |




#### Reference

* [https://www.csoonline.com/article/3438824/how-to-detect-and-halt-credential-theft-via-windows-wdigest.html](https://www.csoonline.com/article/3438824/how-to-detect-and-halt-credential-theft-via-windows-wdigest.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003/wdigest_enable/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003/wdigest_enable/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/enable_wdigest_uselogoncredential_registry.yml) \| *version*: **1**