---
title: "Active Setup Registry Autostart"
excerpt: "Active Setup, Boot or Logon Autostart Execution"
categories:
  - Endpoint
last_modified_at: 2021-09-28
toc: true
toc_label: ""
tags:
  - Active Setup
  - Persistence
  - Privilege Escalation
  - Boot or Logon Autostart Execution
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to detect a suspicious modification of the active setup registry for persistence and privilege escalation. This technique was seen in several malware (poisonIvy), adware and APT to gain persistence to the compromised machine upon boot up. This TTP is a good indicator to further check the process id that do the modification since modification of this registry is not commonly done. check the legitimacy of the file and process involve in this rules to check if it is a valid setup installer that creating or modifying this registry.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-28
- **Author**: Teoderick Contreras, Splunk
- **ID**: f64579c0-203f-11ec-abcc-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1547.014](https://attack.mitre.org/techniques/T1547/014/) | Active Setup | Persistence, Privilege Escalation |

| [T1547](https://attack.mitre.org/techniques/T1547/) | Boot or Logon Autostart Execution | Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count  min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Registry where Registry.registry_value_name = "StubPath" Registry.registry_key_name = "*\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components*" by Registry.dest  Registry.user Registry.registry_path Registry.registry_key_name Registry.registry_value_name 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `drop_dm_object_name(Registry)` 
| `active_setup_registry_autostart_filter`
```

#### Associated Analytic Story
* [Windows Persistence Techniques](/stories/windows_persistence_techniques)
* [Windows Privilege Escalation](/stories/windows_privilege_escalation)


#### How To Implement
To successfully implement this search, you must be ingesting data that records registry activity from your hosts to populate the endpoint data model in the registry node. This is typically populated via endpoint detection-and-response product, such as Carbon Black or endpoint data sources, such as Sysmon. The data used for this search is typically generated via logs that report reads and writes to the registry.

#### Required field
* _time
* Registry.dest
* Registry.user
* Registry.registry_path
* Registry.registry_key_name
* Registry.registry_value_name


#### Kill Chain Phase
* Exploitation


#### Known False Positives
Active setup installer may add or modify this registry.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | modified/added/deleted registry entry $Registry.registry_path$ in $dest$ |




#### Reference

* [https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Backdoor%3aWin32%2fPoisonivy.E](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Backdoor%3aWin32%2fPoisonivy.E)
* [https://attack.mitre.org/techniques/T1547/014/](https://attack.mitre.org/techniques/T1547/014/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/t1547.014/active_setup_stubpath/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/t1547.014/active_setup_stubpath/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/active_setup_registry_autostart.yml) \| *version*: **1**