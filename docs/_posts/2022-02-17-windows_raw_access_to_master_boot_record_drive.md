---
title: "Windows Raw Access To Master Boot Record Drive"
excerpt: "Disk Structure Wipe
, Disk Wipe
"
categories:
  - Endpoint
last_modified_at: 2022-02-17
toc: true
toc_label: ""
tags:
  - Disk Structure Wipe
  - Disk Wipe
  - Impact
  - Impact
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to look for suspicious raw access read to drive where the master boot record is placed. This technique was seen in several attacks by adversaries or threat actor to wipe, encrypt or overwrite the master boot record code as part of their impact payload. This detection is a good indicator that there is a process try to read or write on MBR sector.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2022-02-17
- **Author**: Teoderick Contreras, Splunk
- **ID**: 7b83f666-900c-11ec-a2d9-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1561.002](https://attack.mitre.org/techniques/T1561/002/) | Disk Structure Wipe | Impact |

| [T1561](https://attack.mitre.org/techniques/T1561/) | Disk Wipe | Impact |

#### Search

```
`sysmon` EventCode=9 Device = \\Device\\Harddisk0\\DR0 NOT (Image IN("*\\Windows\\System32\\*", "*\\Windows\\SysWOW64\\*")) 
| stats count min(_time) as firstTime max(_time) as lastTime by Computer Image Device ProcessGuid ProcessId EventDescription EventCode 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_raw_access_to_master_boot_record_drive_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)

Note that `windows_raw_access_to_master_boot_record_drive_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Computer
* Image
* Device
* ProcessGuid
* ProcessId
* EventDescription
* EventCode


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the raw access read event (like sysmon eventcode 9), process name and process guid from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
This event is really notable but we found minimal number of normal application from system32 folder like svchost.exe accessing it too. In this case we used 'system32' and 'syswow64' path as a filter for this detection.

#### Associated Analytic story
* [WhisperGate](/stories/whispergate)
* [Hermetic Wiper](/stories/hermetic_wiper)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 90.0 | 90 | 100 | process accessing MBR $device$ in $dest$ |




#### Reference

* [https://www.splunk.com/en_us/blog/security/threat-advisory-strt-ta02-destructive-software.html](https://www.splunk.com/en_us/blog/security/threat-advisory-strt-ta02-destructive-software.html)
* [https://www.crowdstrike.com/blog/technical-analysis-of-whispergate-malware/](https://www.crowdstrike.com/blog/technical-analysis-of-whispergate-malware/)
* [https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/](https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1561.002/mbr_raw_access/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1561.002/mbr_raw_access/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_raw_access_to_master_boot_record_drive.yml) \| *version*: **1**