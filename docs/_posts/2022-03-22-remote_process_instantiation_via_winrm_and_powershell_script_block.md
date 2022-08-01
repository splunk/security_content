---
title: "Remote Process Instantiation via WinRM and PowerShell Script Block"
excerpt: "Remote Services
, Windows Remote Management
"
categories:
  - Endpoint
last_modified_at: 2022-03-22
toc: true
toc_label: ""
tags:
  - Remote Services
  - Windows Remote Management
  - Lateral Movement
  - Lateral Movement
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic utilizes PowerShell Script Block Logging (EventCode=4104) to identify the execution of PowerShell with arguments utilized to start a process on a remote endpoint by abusing the WinRM protocol. Specifically, this search looks for the abuse of the `Invoke-Command` commandlet. Red Teams and adversaries alike may abuse WinRM for lateral movement and remote code execution.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-03-22
- **Author**: Mauricio Velazco, Splunk
- **ID**: 7d4c618e-4716-11ec-951c-3e22fbd008af


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | Lateral Movement |

| [T1021.006](https://attack.mitre.org/techniques/T1021/006/) | Windows Remote Management | Lateral Movement |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Exploitation


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
`powershell` EventCode=4104 (ScriptBlockText="*Invoke-Command*" AND ScriptBlockText="*-ComputerName*") 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode ScriptBlockText Computer user_id 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `remote_process_instantiation_via_winrm_and_powershell_script_block_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [powershell](https://github.com/splunk/security_content/blob/develop/macros/powershell.yml)

> :information_source:
> **remote_process_instantiation_via_winrm_and_powershell_script_block_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* ScriptBlockText
* Opcode
* Computer
* UserID
* EventCode


#### How To Implement
To successfully implement this analytic, you will need to enable PowerShell Script Block Logging on some or all endpoints. Additional setup instructions can be found https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell.

#### Known False Positives
Administrators may leverage WinRM and `Invoke-Command` to start a process on remote systems for system administration or automation use cases. This activity is usually limited to a small set of hosts or users. In certain environments, tuning may not be possible.

#### Associated Analytic story
* [Active Directory Lateral Movement](/stories/active_directory_lateral_movement)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 45.0 | 90 | 50 | A process was started on a remote endpoint from $Computer$ by abusing WinRM using PowerShell.exe |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://attack.mitre.org/techniques/T1021/006/](https://attack.mitre.org/techniques/T1021/006/)
* [https://pentestlab.blog/2018/05/15/lateral-movement-winrm/](https://pentestlab.blog/2018/05/15/lateral-movement-winrm/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.006/lateral_movement_psh/windows-powershell-xml.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.006/lateral_movement_psh/windows-powershell-xml.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/remote_process_instantiation_via_winrm_and_powershell_script_block.yml) \| *version*: **2**