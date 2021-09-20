---
title: "UAC Bypass MMC Load Unsigned Dll"
excerpt: "Bypass User Account Control"
categories:
  - Endpoint
last_modified_at: 2021-07-12
toc: true
tags:
  - TTP
  - T1548.002
  - Bypass User Account Control
  - Privilege Escalation
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



#### Description

This search is to detect a suspicious loaded unsigned dll by MMC.exe application. This technique is commonly seen in attacker that tries to bypassed UAC feature or gain privilege escalation. This is done by modifying some CLSID registry that will trigger the mmc.exe to load the dll path

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-07-12
- **Author**: Teoderick Contreras, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | Bypass User Account Control | Privilege Escalation, Defense Evasion |


#### Search

```
`sysmon` EventCode=7  ImageLoaded = "*.dll" Image = "*\\mmc.exe" Signed=false Company != "Microsoft Corporation" 
| stats count min(_time) as firstTime max(_time) as lastTime by Image ImageLoaded Signed ProcessId OriginalFileName Computer EventCode Company 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `uac_bypass_mmc_load_unsigned_dll_filter`
```

#### Associated Analytic Story
* [Windows Defense Evasion Tactics](_stories/windows_defense_evasion_tactics)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name and imageloaded executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* Image
* ImageLoaded
* Signed
* ProcessId
* OriginalFileName
* Computer
* EventCode
* Company


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown. all of the dll loaded by mmc.exe is microsoft signed dll.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 63.0 | 70 | 90 |



#### Reference

* [https://offsec.almond.consulting/UAC-bypass-dotnet.html](https://offsec.almond.consulting/UAC-bypass-dotnet.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/uac_bypass/windows-sysmon2.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/uac_bypass/windows-sysmon2.log)


_version_: 1