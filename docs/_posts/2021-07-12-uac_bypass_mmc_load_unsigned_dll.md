---
title: "UAC Bypass MMC Load Unsigned Dll"
excerpt: "Bypass User Account Control
, Abuse Elevation Control Mechanism
"
categories:
  - Endpoint
last_modified_at: 2021-07-12
toc: true
toc_label: ""
tags:
  - Bypass User Account Control
  - Abuse Elevation Control Mechanism
  - Defense Evasion
  - Privilege Escalation
  - Defense Evasion
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect a suspicious loaded unsigned dll by MMC.exe application. This technique is commonly seen in attacker that tries to bypassed UAC feature or gain privilege escalation. This is done by modifying some CLSID registry that will trigger the mmc.exe to load the dll path

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-07-12
- **Author**: Teoderick Contreras, Splunk
- **ID**: 7f04349c-e30d-11eb-bc7f-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | Bypass User Account Control | Defense Evasion, Privilege Escalation |

| [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism | Defense Evasion, Privilege Escalation |

#### Search

```
`sysmon` EventCode=7  ImageLoaded = "*.dll" Image = "*\\mmc.exe" Signed=false Company != "Microsoft Corporation" 
| stats count min(_time) as firstTime max(_time) as lastTime by Image ImageLoaded Signed ProcessId OriginalFileName Computer EventCode Company 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `uac_bypass_mmc_load_unsigned_dll_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)

Note that `uac_bypass_mmc_load_unsigned_dll_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name and imageloaded executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
unknown. all of the dll loaded by mmc.exe is microsoft signed dll.

#### Associated Analytic story
* [Windows Defense Evasion Tactics](/stories/windows_defense_evasion_tactics)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 70 | 90 | Suspicious unsigned $ImageLoaded$ loaded by $Image$ on endpoint $Computer$ with EventCode $EventCode$ |




#### Reference

* [https://offsec.almond.consulting/UAC-bypass-dotnet.html](https://offsec.almond.consulting/UAC-bypass-dotnet.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/uac_bypass/windows-sysmon2.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/uac_bypass/windows-sysmon2.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/uac_bypass_mmc_load_unsigned_dll.yml) \| *version*: **1**