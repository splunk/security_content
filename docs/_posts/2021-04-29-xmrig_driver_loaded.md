---
title: "XMRIG Driver Loaded"
excerpt: "Windows Service, Create or Modify System Process"
categories:
  - Endpoint
last_modified_at: 2021-04-29
toc: true
toc_label: ""
tags:
  - Windows Service
  - Persistence
  - Privilege Escalation
  - Create or Modify System Process
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic identifies XMRIG coinminer driver installation on the system. The XMRIG driver name by default is `WinRing0x64.sys`. This cpu miner is an open source project that is commonly abused by adversaries to infect and mine bitcoin.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-04-29
- **Author**: Teoderick Contreras, Splunk
- **ID**: 90080fa6-a8df-11eb-91e4-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service | Persistence, Privilege Escalation |

| [T1543](https://attack.mitre.org/techniques/T1543/) | Create or Modify System Process | Persistence, Privilege Escalation |

#### Search

```
`sysmon` EventCode=6 Signature="Noriyuki MIYAZAKI" OR ImageLoaded= "*\\WinRing0x64.sys" 
|  stats  min(_time) as firstTime max(_time) as lastTime count by  Computer ImageLoaded Hashes IMPHASH Signature Signed 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `xmrig_driver_loaded_filter`
```

#### Associated Analytic Story
* [XMRig](/stories/xmrig)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the driver loaded and Signature from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* Computer
* ImageLoaded
* Hashes
* IMPHASH
* Signature
* Signed


#### Kill Chain Phase
* Exploitation


#### Known False Positives
False positives should be limited.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | A driver $ImageLoaded$ related to xmrig crytominer loaded in host $Computer$ |




#### Reference

* [https://www.trendmicro.com/vinfo/hk/threat-encyclopedia/malware/trojan.ps1.powtran.a/](https://www.trendmicro.com/vinfo/hk/threat-encyclopedia/malware/trojan.ps1.powtran.a/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/xmrig_driver_loaded.yml) \| *version*: **1**