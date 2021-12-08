---
title: "Registry Keys Used For Persistence"
excerpt: "Registry Run Keys / Startup Folder, Boot or Logon Autostart Execution"
categories:
  - Endpoint
last_modified_at: 2021-09-07
toc: true
toc_label: ""
tags:
  - Registry Run Keys / Startup Folder
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

The search looks for modifications to registry keys that can be used to launch an application or service at system startup.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-07
- **Author**: Jose Hernandez, David Dorsey, Splunk
- **ID**: f5f6af30-7aa7-4295-bfe9-07fe87c01a4b


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run Keys / Startup Folder | Persistence, Privilege Escalation |

| [T1547](https://attack.mitre.org/techniques/T1547/) | Boot or Logon Autostart Execution | Persistence, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count values(Registry.registry_key_name) as registry_key_name values(Registry.registry_path) as registry_path min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Registry where (Registry.registry_path=*\\currentversion\\run* OR Registry.registry_path=*\\currentVersion\\Windows\\Appinit_Dlls* OR Registry.registry_path=*\\CurrentVersion\\Winlogon\\Shell* OR Registry.registry_path=*\\CurrentVersion\\Winlogon\\Notify* OR Registry.registry_path=*\\CurrentVersion\\Winlogon\\Userinit* OR Registry.registry_path=*\\CurrentVersion\\Winlogon\\VmApplet* OR Registry.registry_path=*\\currentversion\\policies\\explorer\\run* OR Registry.registry_path=*\\currentversion\\runservices* OR Registry.registry_path=HKLM\\SOFTWARE\\Microsoft\\Netsh\\* OR (Registry.registry_path="*Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options*" AND Registry.registry_key_name=Debugger) OR (Registry.registry_path="*\\CurrentControlSet\\Control\\Lsa" AND Registry.registry_key_name="Security Packages") OR (Registry.registry_path="*\\CurrentControlSet\\Control\\Lsa\\OSConfig" AND Registry.registry_key_name="Security Packages") OR (Registry.registry_path="*\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\*") OR (Registry.registry_path="*currentVersion\\Windows" AND Registry.registry_key_name="Load") OR (Registry.registry_path="*\\CurrentVersion" AND Registry.registry_key_name="Svchost") OR (Registry.registry_path="*\\CurrentControlSet\Control\Session Manager"AND Registry.registry_key_name="BootExecute") OR (Registry.registry_path="*\\Software\\Run" AND Registry.registry_key_name="auto_update")) by Registry.dest Registry.user 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `drop_dm_object_name(Registry)` 
| `registry_keys_used_for_persistence_filter`
```

#### Associated Analytic Story
* [Suspicious Windows Registry Activities](/stories/suspicious_windows_registry_activities)
* [Suspicious MSHTA Activity](/stories/suspicious_mshta_activity)
* [DHS Report TA18-074A](/stories/dhs_report_ta18-074a)
* [Possible Backdoor Activity Associated With MUDCARP Espionage Campaigns](/stories/possible_backdoor_activity_associated_with_mudcarp_espionage_campaigns)
* [Ransomware](/stories/ransomware)
* [Windows Persistence Techniques](/stories/windows_persistence_techniques)
* [Emotet Malware  DHS Report TA18-201A ](/stories/emotet_malware__dhs_report_ta18-201a_)
* [IcedID](/stories/icedid)
* [Remcos](/stories/remcos)


#### How To Implement
To successfully implement this search, you must be ingesting data that records registry activity from your hosts to populate the endpoint data model in the registry node. This is typically populated via endpoint detection-and-response product, such as Carbon Black or endpoint data sources, such as Sysmon. The data used for this search is typically generated via logs that report reads and writes to the registry.

#### Required field
* _time
* Registry.registry_key_name
* Registry.registry_path
* Registry.dest
* Registry.user


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
There are many legitimate applications that must execute on system startup and will use these registry keys to accomplish that task.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 76.0 | 80 | 95 | A registry activity in $registry_path$ related to persistence in host $dest$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.001/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.001/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/registry_keys_used_for_persistence.yml) \| *version*: **6**