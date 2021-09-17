---
title: "Allow Operation with Consent Admin"
excerpt: "Abuse Elevation Control Mechanism"
categories:
  - Endpoint
last_modified_at: 2021-06-10
toc: true
tags:
  - TTP
  - T1548
  - Abuse Elevation Control Mechanism
  - Privilege Escalation
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---

#### Description

This analytic identifies a potential privilege escalation attempt to perform malicious task. This registry modification is designed to allow the `Consent Admin` to perform an operation that requires elevation without consent or credentials. We also found this in some attacker to gain privilege escalation to the compromise machine.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:[Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-06-10
- **Author**: Teoderick Contreras, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|| [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism | Privilege Escalation, Defense Evasion |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Registry where Registry.registry_path= "*\\Microsoft\\Windows\\CurrentVersion\\Policies\\System*" Registry.registry_key_name = ConsentPromptBehaviorAdmin Registry.registry_value_name = "DWORD (0x00000000)" by Registry.registry_path Registry.registry_key_name Registry.registry_value_name Registry.dest 
| `drop_dm_object_name(Registry)` 
| `security_content_ctime(firstTime)` 
|`security_content_ctime(lastTime)` 
| `allow_operation_with_consent_admin_filter`
```

#### Associated Analytic Story
* [Ransomware](_stories/ransomware)


#### How To Implement
To successfully implement this search, you must be ingesting data that records registry activity from your hosts to populate the endpoint data model in the registry node. This is typically populated via endpoint detection-and-response product, such as Carbon Black or endpoint data sources, such as Sysmon. The data used for this search is typically generated via logs that report reads and writes to the registry.

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

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 25.0 | 50 | 50 |



#### Reference

* [https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/341747f5-6b5d-4d30-85fc-fa1cc04038d4](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/341747f5-6b5d-4d30-85fc-fa1cc04038d4)
* [https://www.trendmicro.com/vinfo/no/threat-encyclopedia/malware/Ransom.Win32.MRDEC.MRA/](https://www.trendmicro.com/vinfo/no/threat-encyclopedia/malware/Ransom.Win32.MRDEC.MRA/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data1/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data1/windows-sysmon.log)


_version_: 1