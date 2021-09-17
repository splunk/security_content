---
title: "Delete ShadowCopy With PowerShell"
excerpt: "Inhibit System Recovery"
categories:
  - Endpoint
last_modified_at: 2021-05-12
toc: true
tags:
  - TTP
  - T1490
  - Inhibit System Recovery
  - Impact
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---

#### Description

This following analytic detects PowerShell command to delete shadow copy using the WMIC PowerShell module. This technique was seen used by a recent adversary to deploy DarkSide Ransomware where it executed a child process of PowerShell to execute a hex encoded command to delete shadow copy. This hex encoded command was able to be decrypted by PowerShell log.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:[Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-12
- **Author**: Teoderick Contreras, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|| [T1490](https://attack.mitre.org/techniques/T1490/) | Inhibit System Recovery | Impact |


#### Search

```
`powershell` EventCode=4104 Message= "*ShadowCopy*" (Message = "*Delete*" OR Message = "*Remove*") 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Message ComputerName User 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `delete_shadowcopy_with_powershell_filter`
```

#### Associated Analytic Story
* [DarkSide Ransomware](_stories/darkside_ransomware)
* [Ransomware](_stories/ransomware)
* [Revil Ransomware](_stories/revil_ransomware)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the powershell logs  from your endpoints. make sure you enable needed registry to monitor this event.

#### Required field
* _time
* EventCode
* Message
* ComputerName
* User


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 81.0 | 90 | 90 |



#### Reference

* [https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html](https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html)
* [https://searchwindowsserver.techtarget.com/tutorial/Set-up-PowerShell-script-block-logging-for-added-security](https://searchwindowsserver.techtarget.com/tutorial/Set-up-PowerShell-script-block-logging-for-added-security)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/revil/inf1/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/revil/inf1/windows-powershell.log)


_version_: 1