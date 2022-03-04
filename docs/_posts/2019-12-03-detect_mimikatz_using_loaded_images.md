---
title: "Detect Mimikatz Using Loaded Images"
excerpt: "LSASS Memory
, OS Credential Dumping
"
categories:
  - Endpoint
last_modified_at: 2019-12-03
toc: true
toc_label: ""
tags:

  - LSASS Memory
  - OS Credential Dumping
  - Credential Access
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for reading loaded Images unique to credential dumping with Mimikatz. Deprecated because mimikatz libraries changed and very noisy sysmon Event Code.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2019-12-03
- **Author**: Patrick Bareiss, Splunk
- **ID**: 29e307ba-40af-4ab2-91b2-3c6b392bbba0


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS Memory | Credential Access |

| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | Credential Access |

#### Search

```
`sysmon` EventCode=7 
| stats values(ImageLoaded) as ImageLoaded values(ProcessId) as ProcessId by Computer, Image 
| search ImageLoaded=*WinSCard.dll ImageLoaded=*cryptdll.dll ImageLoaded=*hid.dll ImageLoaded=*samlib.dll ImageLoaded=*vaultcli.dll 
| rename Computer as dest 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `detect_mimikatz_using_loaded_images_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)

Note that `detect_mimikatz_using_loaded_images_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* ImageLoaded
* ProcessId
* Computer
* Image


#### How To Implement
This search needs Sysmon Logs and a sysmon configuration, which includes EventCode 7 with powershell.exe. This search uses an input macro named `sysmon`. We strongly recommend that you specify your environment-specific configurations (index, source, sourcetype, etc.) for Windows Sysmon logs. Replace the macro definition with configurations for your Splunk environment. The search also uses a post-filter macro designed to filter out known false positives.

#### Known False Positives
Other tools can import the same DLLs. These tools should be part of a whitelist. False positives may be present with any process that authenticates or uses credentials, PowerShell included. Filter based on parent process.

#### Associated Analytic story
* [Credential Dumping](/stories/credential_dumping)
* [Detect Zerologon Attack](/stories/detect_zerologon_attack)
* [Cloud Federated Credential Abuse](/stories/cloud_federated_credential_abuse)
* [DarkSide Ransomware](/stories/darkside_ransomware)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | A process, $Image$, has loaded $ImageLoaded$ that are typically related to credential dumping on $Computer$. Review for further details. |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_mimikatz_using_loaded_images.yml) \| *version*: **1**