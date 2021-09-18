---
title: "Suspicious Driver Loaded Path"
excerpt: "Windows Service"
categories:
  - Endpoint
last_modified_at: 2021-04-29
toc: true
tags:
  - TTP
  - T1543.003
  - Windows Service
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



#### Description

This analytic will detect suspicious driver loaded paths. This technique is commonly used by malicious software like coin miners (xmrig) to register its malicious driver from notable directories where executable or drivers do not commonly exist. During triage, validate this driver is for legitimate business use. Review the metadata and certificate information. Unsigned drivers from non-standard paths is not normal, but occurs. In addition, review driver loads into `ntoskrnl.exe` for possible other drivers of interest. Long tail analyze drivers by path (outside of default, and in default) for further review.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-04-29
- **Author**: Teoderick Contreras, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | Windows Service | Persistence, Privilege Escalation |


#### Search

```
`sysmon` EventCode=6 ImageLoaded = "*.sys" NOT (ImageLoaded IN("*\\WINDOWS\\inf","*\\WINDOWS\\System32\\drivers\\*", "*\\WINDOWS\\System32\\DriverStore\\FileRepository\\*")) 
|  stats  min(_time) as firstTime max(_time) as lastTime count by Computer ImageLoaded Hashes IMPHASH Signature Signed 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `suspicious_driver_loaded_path_filter`
```

#### Associated Analytic Story
* [XMRig](_stories/xmrig)


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
Limited false positives will be present. Some applications do load drivers



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 63.0 | 70 | 90 |



#### Reference

* [https://www.trendmicro.com/vinfo/hk/threat-encyclopedia/malware/trojan.ps1.powtran.a/](https://www.trendmicro.com/vinfo/hk/threat-encyclopedia/malware/trojan.ps1.powtran.a/)
* [https://redcanary.com/blog/tracking-driver-inventory-to-expose-rootkits/](https://redcanary.com/blog/tracking-driver-inventory-to-expose-rootkits/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log)


_version_: 1