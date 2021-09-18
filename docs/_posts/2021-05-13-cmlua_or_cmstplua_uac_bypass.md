---
title: "CMLUA Or CMSTPLUA UAC Bypass"
excerpt: "CMSTP"
categories:
  - Endpoint
last_modified_at: 2021-05-13
toc: true
tags:
  - TTP
  - T1218.003
  - CMSTP
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



#### Description

This analytic detects a potential process using COM Object like CMLUA or CMSTPLUA to bypass UAC. This technique has been used by ransomware adversaries to gain administrative privileges to its running process.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-13
- **Author**: Teoderick Contreras, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1218.003](https://attack.mitre.org/techniques/T1218/003/) | CMSTP | Defense Evasion |


#### Search

```
`sysmon` EventCode=7  ImageLoaded IN ("*\\CMLUA.dll", "*\\CMSTPLUA.dll", "*\\CMLUAUTIL.dll") NOT(process_name IN("CMSTP.exe", "CMMGR32.exe")) NOT(Image IN("*\\windows\\*", "*\\program files*")) 
| stats count min(_time) as firstTime max(_time) as lastTime by Image ImageLoaded process_name Computer EventCode Signed ProcessId 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `cmlua_or_cmstplua_uac_bypass_filter`
```

#### Associated Analytic Story
* [DarkSide Ransomware](_stories/darkside_ransomware)
* [Ransomware](_stories/ransomware)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name and imageloaded executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* Image
* ImageLoaded
* process_name
* Computer
* EventCode
* Signed
* ProcessId


#### Kill Chain Phase
* Exploitation


#### Known False Positives
Legitimate windows application that are not on the list loading this dll. Filter as needed.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 80.0 | 80 | 100 |



#### Reference

* [https://attack.mitre.org/techniques/T1218/003/](https://attack.mitre.org/techniques/T1218/003/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/darkside_cmstp_com/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548/darkside_cmstp_com/windows-sysmon.log)


_version_: 1