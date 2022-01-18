---
title: "Windows Hunting System Account Targeting Lsass"
excerpt: "LSASS Memory, OS Credential Dumping"
categories:
  - Endpoint
last_modified_at: 2022-01-12
toc: true
toc_label: ""
tags:
  - LSASS Memory
  - Credential Access
  - OS Credential Dumping
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following hunting analytic identifies all processes requesting access into Lsass.exe. his behavior may be related to credential dumping or applications requiring access to credentials. Triaging this event will require understanding the GrantedAccess from the SourceImage. In addition, whether the account is privileged or not. Review the process requesting permissions and review parallel processes.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2022-01-12
- **Author**: Michael Haag, Splunk
- **ID**: 1c6abb08-73d1-11ec-9ca0-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS Memory | Credential Access |

| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | Credential Access |

#### Search

```
`sysmon` EventCode=10 TargetImage=*lsass.exe 
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, TargetImage, GrantedAccess, SourceImage, SourceProcessId, SourceUser, TargetUser 
| rename Computer as dest 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_hunting_system_account_targeting_lsass_filter`
```

#### Associated Analytic Story
* [Credential Dumping](/stories/credential_dumping)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Enabling EventCode 10 TargetProcess lsass.exe is required.

#### Required field
* _time
* Computer
* TargetImage
* GrantedAccess
* SourceImage
* SourceProcessId
* SourceUser
* TargetUser


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
False positives will occur based on GrantedAccess and SourceUser, filter based on source image as needed.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | A process, $SourceImage$, has loaded $ImageLoaded$ that are typically related to credential dumping on $dest$. Review for further details. |




#### Reference

* [https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)
* [https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump](https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump)
* [https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html)
* [https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1)
* [https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights?redirectedfrom=MSDN)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon_creddump.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon_creddump.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_hunting_system_account_targeting_lsass.yml) \| *version*: **1**