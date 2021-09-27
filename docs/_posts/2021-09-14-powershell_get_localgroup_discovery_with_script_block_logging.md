---
title: "Powershell Get LocalGroup Discovery with Script Block Logging"
excerpt: "Local Groups"
categories:
  - Endpoint
last_modified_at: 2021-09-14
toc: true
tags:
  - Hunting
  - T1069.001
  - Local Groups
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Reconnaissance
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic utilizes PowerShell Script Block Logging (EventCode=4104) to identify suspicious PowerShell execution. Script Block Logging captures the command sent to PowerShell, the full command to be executed. Upon enabling, logs will output to Windows event logs. Dependent upon volume, enable on critical endpoints or all. \
This analytic identifies PowerShell cmdlet - `get-localgroup` being ran. Typically, by itself, is not malicious but may raise suspicion based on time of day, endpoint and username. \
During triage, review parallel processes using an EDR product or 4688 events. It will be important to understand the timeline of events around this activity. Review the entire logged PowerShell script block.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-14
- **Author**: Michael Haag, Splunk
- **ID**: d7c6ad22-155c-11ec-bb64-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1069.001](https://attack.mitre.org/techniques/T1069/001/) | Local Groups | Discovery |


#### Search

```
`powershell` EventCode=4104 Message = "*get-localgroup*" 
| stats count min(_time) as firstTime max(_time) as lastTime by Message OpCode ComputerName User EventCode
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `powershell_get_localgroup_discovery_with_script_block_logging_filter`
```

#### Associated Analytic Story
* [Active Directory Discovery](/stories/active_directory_discovery)


#### How To Implement
To successfully implement this analytic, you will need to enable PowerShell Script Block Logging on some or all endpoints. Additional setup here https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell.

#### Required field
* _time
* EventCode
* Message
* ComputerName
* User


#### Kill Chain Phase
* Reconnaissance


#### Known False Positives
False positives may be present. Tune as needed.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 15.0 | 30 | 50 | Local group discovery on $dest$ by $user$. |



#### Reference

* [https://www.splunk.com/en_us/blog/security/powershell-detections-threat-research-release-august-2021.html](https://www.splunk.com/en_us/blog/security/powershell-detections-threat-research-release-august-2021.html)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.001/T1069.001.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.001/T1069.001.md)
* [https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell](https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell)
* [https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63](https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63)
* [https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/59c1814829f18782e24f1fe2/1505853768977/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2017+v2.1.pdf](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/59c1814829f18782e24f1fe2/1505853768977/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2017+v2.1.pdf)
* [https://www.crowdstrike.com/blog/investigating-powershell-command-and-script-logging/](https://www.crowdstrike.com/blog/investigating-powershell-command-and-script-logging/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.001/atomic_red_team/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.001/atomic_red_team/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/powershell_get_localgroup_discovery_with_script_block_logging.yml) \| *version*: **1**