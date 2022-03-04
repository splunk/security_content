---
title: "Get-ForestTrust with PowerShell Script Block"
excerpt: "Domain Trust Discovery"
categories:
  - Endpoint
last_modified_at: 2021-09-02
toc: true
toc_label: ""
tags:
  - Domain Trust Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic utilizes PowerShell Script Block Logging (EventCode=4104) to identify suspicious PowerShell execution. Script Block Logging captures the command sent to PowerShell, the full command to be executed. Upon enabling, logs will output to Windows event logs. Dependent upon volume, enable on critical endpoints or all. \
This analytic identifies Get-ForestTrust from PowerSploit in order to gather domain trust information. \
During triage, review parallel processes using an EDR product or 4688 events. It will be important to understand the timeline of events around this activity. Review the entire logged PowerShell script block.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-09-02
- **Author**: Michael Haag, Splunk
- **ID**: 70fac80e-0bf1-11ec-9ba0-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1482](https://attack.mitre.org/techniques/T1482/) | Domain Trust Discovery | Discovery |

#### Search

```
`powershell` EventCode=4104 Message = "*get-foresttrust*" 
| stats count min(_time) as firstTime max(_time) as lastTime by  Message OpCode ComputerName User EventCode 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `get_foresttrust_with_powershell_script_block_filter`
```

#### Macros
The SPL above uses the following Macros:
* [powershell](https://github.com/splunk/security_content/blob/develop/macros/powershell.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `get-foresttrust_with_powershell_script_block_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* Message
* Path
* OpCode
* ComputerName
* User


#### How To Implement
To successfully implement this analytic, you will need to enable PowerShell Script Block Logging on some or all endpoints. Additional setup here https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell.

#### Known False Positives
UPDATE_KNOWN_FALSE_POSITIVES

#### Associated Analytic story
* [Active Directory Discovery](/stories/active_directory_discovery)


#### Kill Chain Phase
* Reconnaissance



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 12.0 | 30 | 40 | Suspicious PowerShell Get-ForestTrust was identified on endpoint $ComputerName$ by user $User$. |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://powersploit.readthedocs.io/en/latest/Recon/Get-ForestTrust/](https://powersploit.readthedocs.io/en/latest/Recon/Get-ForestTrust/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1482/discovery/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1482/discovery/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/get-foresttrust_with_powershell_script_block.yml) \| *version*: **1**