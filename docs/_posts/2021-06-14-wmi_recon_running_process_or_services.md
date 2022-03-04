---
title: "WMI Recon Running Process Or Services"
excerpt: "Gather Victim Host Information
"
categories:
  - Endpoint
last_modified_at: 2021-06-14
toc: true
toc_label: ""
tags:

  - Gather Victim Host Information
  - Reconnaissance
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies suspicious PowerShell script execution via EventCode 4104, where WMI is performing an event query looking for running processes or running services. This technique is commonly found in malware and APT events where the adversary will map all running security applications or services on the compromised machine. During triage, review parallel processes within the same timeframe. Review the full script block to identify other related artifacts.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-06-14
- **Author**: Teoderick Contreras, Splunk
- **ID**: b5cd5526-cce7-11eb-b3bd-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1592](https://attack.mitre.org/techniques/T1592/) | Gather Victim Host Information | Reconnaissance |

#### Search

```
`powershell` EventCode=4104 Message= "*SELECT*" AND (Message="*Win32_Process*" OR Message="*Win32_Service*") 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Message ComputerName User 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `wmi_recon_running_process_or_services_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [powershell](https://github.com/splunk/security_content/blob/develop/macros/powershell.yml)

Note that `wmi_recon_running_process_or_services_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
| 30.0 | 30 | 100 | Suspicious powerShell script execution by $user$ on $ComputerName$ via EventCode 4104, where WMI is performing an event query looking for running processes or running services |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://news.sophos.com/en-us/2020/05/12/maze-ransomware-1-year-counting/](https://news.sophos.com/en-us/2020/05/12/maze-ransomware-1-year-counting/)
* [https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/](https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/)
* [https://github.com/trustedsec/SysmonCommunityGuide/blob/master/WMI-events.md](https://github.com/trustedsec/SysmonCommunityGuide/blob/master/WMI-events.md)
* [https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/](https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/honeypots/pwsh/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/honeypots/pwsh/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/wmi_recon_running_process_or_services.yml) \| *version*: **1**