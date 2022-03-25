---
title: "Recon Using WMI Class"
excerpt: "Gather Victim Host Information
"
categories:
  - Endpoint
last_modified_at: 2021-06-10
toc: true
toc_label: ""
tags:
  - Gather Victim Host Information
  - Reconnaissance
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies suspicious PowerShell via EventCode 4104, where WMI is performing an event query looking for running processes or running services. This technique is commonly found where the adversary will identify services and system information on the compromised machine. During triage, review parallel processes within the same timeframe. Review the full script block to identify other related artifacts.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2021-06-10
- **Author**: Teoderick Contreras, Splunk
- **ID**: 018c1972-ca07-11eb-9473-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1592](https://attack.mitre.org/techniques/T1592/) | Gather Victim Host Information | Reconnaissance |

#### Search

```
`powershell` EventCode=4104 (Message= "*SELECT*" OR Message= "*Get-WmiObject*") AND (Message= "*Win32_Bios*" OR Message= "*Win32_OperatingSystem*" OR Message= "*Win32_Processor*" OR Message= "*Win32_ComputerSystem*" OR Message= "*Win32_ComputerSystemProduct*" OR Message= "*Win32_ShadowCopy*") 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Message ComputerName User 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `recon_using_wmi_class_filter`
```

#### Macros
The SPL above uses the following Macros:
* [powershell](https://github.com/splunk/security_content/blob/develop/macros/powershell.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `recon_using_wmi_class_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* Message
* ComputerName
* User


#### How To Implement
To successfully implement this analytic, you will need to enable PowerShell Script Block Logging on some or all endpoints. Additional setup here https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell.

#### Known False Positives
network administrator may used this command for checking purposes

#### Associated Analytic story
* [Malicious PowerShell](/stories/malicious_powershell)


#### Kill Chain Phase
* Reconnaissance



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 60.0 | 75 | 80 | A suspicious powershell script contains host recon command in $Message$ with EventCode $EventCode$ in host $ComputerName$ |




#### Reference

* [https://news.sophos.com/en-us/2020/05/12/maze-ransomware-1-year-counting/](https://news.sophos.com/en-us/2020/05/12/maze-ransomware-1-year-counting/)
* [https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell.](https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell.)
* [https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63](https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63)
* [https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/59c1814829f18782e24f1fe2/1505853768977/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2017+v2.1.pdf](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/59c1814829f18782e24f1fe2/1505853768977/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2017+v2.1.pdf)
* [https://www.crowdstrike.com/blog/investigating-powershell-command-and-script-logging/](https://www.crowdstrike.com/blog/investigating-powershell-command-and-script-logging/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/honeypots/pwsh/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/honeypots/pwsh/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/recon_using_wmi_class.yml) \| *version*: **1**