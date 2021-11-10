---
title: "Remcos client registry install entry"
excerpt: "Modify Registry"
categories:
  - Endpoint
last_modified_at: 2021-09-24
toc: true
toc_label: ""
tags:
  - Modify Registry
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search detects registry key license at host where Remcos RAT agent is installed.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-24
- **Author**: Bhavin Patel, Rod Soto, Splunk
- **ID**: f2a1615a-1d63-11ec-97d2-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1112](https://attack.mitre.org/techniques/T1112/) | Modify Registry | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Registry.registry_path) as  registry_path FROM datamodel=Endpoint.Registry where (Registry.registry_key_name=*\\Software\\Remcos*) by Registry.dest  Registry.user Registry.registry_key_name Registry.process_id
| `drop_dm_object_name(Registry)` 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)`
|`remcos_client_registry_install_entry_filter`
```

#### Associated Analytic Story
* [Remcos](/stories/remcos)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Registry` node. Also make sure that this registry was included in your config files ex. sysmon config to be monitored.

#### Required field
* _time
* Registry.registry_path
* Registry.registry_key_name
* Registry.process_id
* Registry.dest
* Registry.user


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 90.0 | 90 | 100 | A registry entry $registry_path$ with registry keyname $registry_key_name$ related to Remcos RAT in host $dest$ |




#### Reference

* [https://attack.mitre.org/software/S0332/](https://attack.mitre.org/software/S0332/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/remcos/remcos_panel_client/remcos_registry_entry.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/remcos/remcos_panel_client/remcos_registry_entry.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/remcos_client_registry_install_entry.yml) \| *version*: **1**