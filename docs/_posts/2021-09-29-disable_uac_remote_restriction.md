---
title: "Disable UAC Remote Restriction"
excerpt: "Bypass User Account Control, Abuse Elevation Control Mechanism"
categories:
  - Endpoint
last_modified_at: 2021-09-29
toc: true
toc_label: ""
tags:
  - Bypass User Account Control
  - Privilege Escalation
  - Defense Evasion
  - Abuse Elevation Control Mechanism
  - Privilege Escalation
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to detect a suspicious modification of registry to disable UAC remote restriction. This technique was well documented in Microsoft page where attacker may modify this registry value to bypassed UAC feature of windows host. This is a good indicator that some tries to bypassed UAC to suspicious process or gain privilege escalation.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-29
- **Author**: Teoderick Contreras, Splunk
- **ID**: 9928b732-210e-11ec-b65e-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | Bypass User Account Control | Privilege Escalation, Defense Evasion |

| [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism | Privilege Escalation, Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count  min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Registry where Registry.registry_path ="*\\CurrentVersion\\Policies\\System*" Registry.registry_value_name="LocalAccountTokenFilterPolicy" Registry.registry_value_data="0x00000001" by Registry.dest  Registry.user Registry.registry_path Registry.registry_key_name Registry.registry_value_name Registry.registry_value_data 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `drop_dm_object_name(Registry)` 
| `disable_uac_remote_restriction_filter`
```

#### Associated Analytic Story
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)
* [Suspicious Windows Registry Activities](/stories/suspicious_windows_registry_activities)


#### How To Implement
To successfully implement this search, you must be ingesting data that records registry activity from your hosts to populate the endpoint data model in the registry node. This is typically populated via endpoint detection-and-response product, such as Carbon Black or endpoint data sources, such as Sysmon. The data used for this search is typically generated via logs that report reads and writes to the registry.

#### Required field
* _time
* Registry.dest
* Registry.user
* Registry.registry_path
* Registry.registry_key_name
* Registry.registry_value_name
* Registry.registry_value_data


#### Kill Chain Phase
* Exploitation


#### Known False Positives
admin may set this policy for non-critical machine.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | modified/added/deleted registry entry $Registry.registry_path$ in $dest$ |




#### Reference

* [https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.002/LocalAccountTokenFilterPolicy/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.002/LocalAccountTokenFilterPolicy/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/disable_uac_remote_restriction.yml) \| *version*: **1**