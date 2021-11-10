---
title: "Sdclt UAC Bypass"
excerpt: "Bypass User Account Control, Abuse Elevation Control Mechanism"
categories:
  - Endpoint
last_modified_at: 2021-07-01
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

This search is to detect a suspicious sdclt.exe registry modification. This technique is commonly seen when attacker try to bypassed UAC by using sdclt.exe application by modifying some registry that sdclt.exe tries to open or query with payload file path on it to be executed.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-07-01
- **Author**: Teoderick Contreras, Splunk
- **ID**: d71efbf6-da63-11eb-8c6e-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | Bypass User Account Control | Privilege Escalation, Defense Evasion |

| [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism | Privilege Escalation, Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where (Registry.registry_path= "*\\Windows\\CurrentVersion\\App Paths\\control.exe*" OR Registry.registry_path= "*\\exefile\\shell\\runas\\command\\*") (Registry.registry_key_name = "(Default)" OR Registry.registry_key_name = "IsolatedCommand") by Registry.registry_path Registry.registry_key_name Registry.registry_value_name Registry.dest 
| `drop_dm_object_name(Registry)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `sdclt_uac_bypass_filter`
```

#### Associated Analytic Story
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Required field
* _time
* Registry.registry_path
* Registry.registry_key_name
* Registry.registry_value_name
* Registry.dest


#### Kill Chain Phase
* Exploitation


#### Known False Positives
Limited to no false positives are expected.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 70 | 90 | Suspicious modification of registry $registry_path$ with possible payload path $registry_value_name$ in $dest$ |




#### Reference

* [https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/](https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/)
* [https://github.com/hfiref0x/UACME](https://github.com/hfiref0x/UACME)
* [https://www.cyborgsecurity.com/cyborg_labs/threat-hunt-deep-dives-user-account-control-bypass-via-registry-modification/](https://www.cyborgsecurity.com/cyborg_labs/threat-hunt-deep-dives-user-account-control-bypass-via-registry-modification/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/uac_bypass/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/uac_bypass/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/sdclt_uac_bypass.yml) \| *version*: **1**