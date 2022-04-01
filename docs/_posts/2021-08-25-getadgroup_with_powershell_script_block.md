---
title: "GetAdGroup with PowerShell Script Block"
excerpt: "Permission Groups Discovery
, Domain Groups
"
categories:
  - Endpoint
last_modified_at: 2021-08-25
toc: true
toc_label: ""
tags:
  - Permission Groups Discovery
  - Domain Groups
  - Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic utilizes PowerShell Script Block Logging (EventCode=4104) to identify the execution of the `Get-AdGroup` commandlet. The `Get-AdGroup` commandlet is used to return a list of all domain groups. Red Teams and adversaries may leverage this commandlet to enumerate domain groups for situational awareness and Active Directory Discovery.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2021-08-25
- **Author**: Mauricio Velazco, Splunk
- **ID**: e4c73d68-794b-468d-b4d0-dac1772bbae7


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1069](https://attack.mitre.org/techniques/T1069/) | Permission Groups Discovery | Discovery |

| [T1069.002](https://attack.mitre.org/techniques/T1069/002/) | Domain Groups | Discovery |

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
`powershell` EventCode=4104 (Message = "*Get-ADGroup*") 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Message ComputerName User 
| `security_content_ctime(firstTime)` 
| `getadgroup_with_powershell_script_block_filter`
```

#### Macros
The SPL above uses the following Macros:
* [powershell](https://github.com/splunk/security_content/blob/develop/macros/powershell.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **getadgroup_with_powershell_script_block_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* Message
* ComputerName
* User


#### How To Implement
To successfully implement this analytic, you will need to enable PowerShell Script Block Logging on some or all endpoints. Additional setup here https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell.

#### Known False Positives
Administrators or power users may use this PowerShell commandlet for troubleshooting.

#### Associated Analytic story
* [Active Directory Discovery](/stories/active_directory_discovery)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 15.0 | 30 | 50 | Domain group discovery enumeration using PowerShell on $dest$ by $user$ |


#### Reference

* [https://attack.mitre.org/techniques/T1069/002/](https://attack.mitre.org/techniques/T1069/002/)
* [https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adgroup?view=windowsserver2019-ps](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adgroup?view=windowsserver2019-ps)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.002/AD_discovery/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.002/AD_discovery/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/getadgroup_with_powershell_script_block.yml) \| *version*: **1**