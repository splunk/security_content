---
title: "Eventvwr UAC Bypass"
excerpt: "Bypass User Account Control, Abuse Elevation Control Mechanism"
categories:
  - Endpoint
last_modified_at: 2021-03-01
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

The following search identifies Eventvwr bypass by identifying the registry modification into a specific path that eventvwr.msc looks to (but is not valid) upon execution. A successful attack will include a suspicious command to be executed upon eventvwr.msc loading. Upon triage, review the parallel processes that have executed. Identify any additional registry modifications on the endpoint that may look suspicious. Remediate as necessary.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-03-01
- **Author**: Michael Haag, Splunk
- **ID**: 9cf8fe08-7ad8-11eb-9819-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | Bypass User Account Control | Privilege Escalation, Defense Evasion |

| [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism | Privilege Escalation, Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count values(Registry.registry_key_name) as registry_key_name values(Registry.registry_path) as registry_path min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Registry where  Registry.registry_path="*mscfile\\shell\\open\\command\\*"  by Registry.user, Registry.dest , Registry.registry_value_name
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `drop_dm_object_name(Registry)` 
| `eventvwr_uac_bypass_filter`
```

#### Associated Analytic Story
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)
* [IcedID](/stories/icedid)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Registry` node.

#### Required field
* _time
* Registry.registry_key_name
* Registry.registry_path
* Registry.user
* Registry.dest
* Registry.registry_value_name


#### Kill Chain Phase
* Exploitation
* Privilege Escalation


#### Known False Positives
Some false positives may be present and will need to be filtered.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | Registry values were modified to bypass UAC using Event Viewer on $dest$ by $user$. |




#### Reference

* [https://blog.malwarebytes.com/malwarebytes-news/2021/02/lazyscripter-from-empire-to-double-rat/](https://blog.malwarebytes.com/malwarebytes-news/2021/02/lazyscripter-from-empire-to-double-rat/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md)
* [https://attack.mitre.org/techniques/T1548/002](https://attack.mitre.org/techniques/T1548/002)
* [https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/](https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.002/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.002/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/eventvwr_uac_bypass.yml) \| *version*: **1**