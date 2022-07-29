---
title: "WMI Recon Running Process Or Services"
excerpt: "Gather Victim Host Information
"
categories:
  - Endpoint
last_modified_at: 2022-05-02
toc: true
toc_label: ""
tags:
  - Gather Victim Host Information
  - Reconnaissance
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies suspicious PowerShell script execution via EventCode 4104, where WMI is performing an event query looking for running processes or running services. This technique is commonly found in malware and APT events where the adversary will map all running security applications or services on the compromised machine. During triage, review parallel processes within the same timeframe. Review the full script block to identify other related artifacts.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-05-02
- **Author**: Teoderick Contreras, Splunk
- **ID**: b5cd5526-cce7-11eb-b3bd-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1592](https://attack.mitre.org/techniques/T1592/) | Gather Victim Host Information | Reconnaissance |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Reconnaissance


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search 

```
`powershell` EventCode=4104 ScriptBlockText= "*SELECT*" AND (ScriptBlockText="*Win32_Process*" OR ScriptBlockText="*Win32_Service*") 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode ScriptBlockText Computer UserID 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `wmi_recon_running_process_or_services_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [powershell](https://github.com/splunk/security_content/blob/develop/macros/powershell.yml)

> :information_source:
> **wmi_recon_running_process_or_services_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* ScriptBlockText
* Opcode
* Computer
* UserID
* EventCode


#### How To Implement
To successfully implement this analytic, you will need to enable PowerShell Script Block Logging on some or all endpoints. Additional setup here https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell.

#### Known False Positives
network administrator may used this command for checking purposes

#### Associated Analytic story
* [Hermetic Wiper](/stories/hermetic_wiper)
* [Malicious PowerShell](/stories/malicious_powershell)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 30.0 | 30 | 100 | Suspicious powerShell script execution by $user$ on $Computer$ via EventCode 4104, where WMI is performing an event query looking for running processes or running services |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://news.sophos.com/en-us/2020/05/12/maze-ransomware-1-year-counting/](https://news.sophos.com/en-us/2020/05/12/maze-ransomware-1-year-counting/)
* [https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/](https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/)
* [https://github.com/trustedsec/SysmonCommunityGuide/blob/master/chapters/WMI-events.md](https://github.com/trustedsec/SysmonCommunityGuide/blob/master/chapters/WMI-events.md)
* [https://in.security/2019/04/03/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/](https://in.security/2019/04/03/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/win32process.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/win32process.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/wmi_recon_running_process_or_services.yml) \| *version*: **2**