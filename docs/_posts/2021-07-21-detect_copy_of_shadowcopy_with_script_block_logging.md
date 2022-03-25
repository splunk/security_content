---
title: "Detect Copy of ShadowCopy with Script Block Logging"
excerpt: "Security Account Manager
, OS Credential Dumping
"
categories:
  - Endpoint
last_modified_at: 2021-07-21
toc: true
toc_label: ""
tags:
  - Security Account Manager
  - OS Credential Dumping
  - Credential Access
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2021-36934
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic utilizes PowerShell Script Block Logging (EventCode=4104) to identify suspicious PowerShell execution. Script Block Logging captures the command sent to PowerShell, the full command to be executed. Upon enabling, logs will output to Windows event logs. Dependent upon volume, enable on critical endpoints or all. \
This analytic identifies `copy` or `[System.IO.File]::Copy` being used to capture the SAM, SYSTEM or SECURITY hives identified in script block. This will catch the most basic use cases for credentials being taken for offline cracking. \
During triage, review parallel processes using an EDR product or 4688 events. It will be important to understand the timeline of events around this activity. Review the entire logged PowerShell script block.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2021-07-21
- **Author**: Michael Haag, Splunk
- **ID**: 9251299c-ea5b-11eb-a8de-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1003.002](https://attack.mitre.org/techniques/T1003/002/) | Security Account Manager | Credential Access |

| [T1003](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping | Credential Access |

#### Search

```
`powershell` EventCode=4104 Message IN ("*copy*","*[System.IO.File]::Copy*") AND Message IN ("*System32\\config\\SAM*", "*System32\\config\\SYSTEM*","*System32\\config\\SECURITY*") 
| stats count min(_time) as firstTime max(_time) as lastTime by OpCode ComputerName User EventCode Message 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_copy_of_shadowcopy_with_script_block_logging_filter`
```

#### Macros
The SPL above uses the following Macros:
* [powershell](https://github.com/splunk/security_content/blob/develop/macros/powershell.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `detect_copy_of_shadowcopy_with_script_block_logging_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Message
* OpCode
* ComputerName
* User
* EventCode


#### How To Implement
To successfully implement this analytic, you will need to enable PowerShell Script Block Logging on some or all endpoints. Additional setup here https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell.

#### Known False Positives
Limited false positives as the scope is limited to SAM, SYSTEM and SECURITY hives.

#### Associated Analytic story
* [Credential Dumping](/stories/credential_dumping)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | PowerShell was identified running a script to capture the SAM hive on endpoint $ComputerName$ by user $user$. |


#### CVE

| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2021-36934](https://nvd.nist.gov/vuln/detail/CVE-2021-36934) | Windows Elevation of Privilege Vulnerability | 4.6 |



#### Reference

* [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934)
* [https://github.com/GossiTheDog/HiveNightmare](https://github.com/GossiTheDog/HiveNightmare)
* [https://github.com/JumpsecLabs/Guidance-Advice/tree/main/SAM_Permissions](https://github.com/JumpsecLabs/Guidance-Advice/tree/main/SAM_Permissions)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.002/serioussam/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.002/serioussam/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_copy_of_shadowcopy_with_script_block_logging.yml) \| *version*: **1**