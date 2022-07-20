---
title: "GetWmiObject DS User with PowerShell Script Block"
excerpt: "Domain Account
, Account Discovery
"
categories:
  - Endpoint
last_modified_at: 2022-05-02
toc: true
toc_label: ""
tags:
  - Domain Account
  - Account Discovery
  - Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic utilizes PowerShell Script Block Logging (EventCode=4104) to identify the execution of the `Get-WmiObject` commandlet. The `DS_User` class parameter leverages WMI to query for all domain users. Red Teams and adversaries may leverage this commandlet to enumerate domain users for situational awareness and Active Directory Discovery.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-05-02
- **Author**: Teoderick Contreras, Mauricio Velazco, Splunk
- **ID**: fabd364e-04f3-11ec-b34b-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | Domain Account | Discovery |

| [T1087](https://attack.mitre.org/techniques/T1087/) | Account Discovery | Discovery |

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
`powershell` EventCode=4104 ScriptBlockText = "*get-wmiobject*" ScriptBlockText = "*ds_user*" ScriptBlockText = "*-namespace*" ScriptBlockText = "*root\\directory\\ldap*" 
| stats count min(_time) as firstTime max(_time) as lastTime by Opcode Computer UserID EventCode ScriptBlockText 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `getwmiobject_ds_user_with_powershell_script_block_filter`
```

#### Macros
The SPL above uses the following Macros:
* [powershell](https://github.com/splunk/security_content/blob/develop/macros/powershell.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **getwmiobject_ds_user_with_powershell_script_block_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* ScriptBlockText
* Opcode
* Computer
* UserID
* EventCode


#### How To Implement
he following Hunting analytic requires PowerShell operational logs to be imported. Modify the powershell macro as needed to match the sourcetype or add index. This analytic is specific to 4104, or PowerShell Script Block Logging.

#### Known False Positives
Administrators or power users may use this command for troubleshooting.

#### Associated Analytic story
* [Active Directory Discovery](/stories/active_directory_discovery)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | powershell process having commandline $ScriptBlockText$ for user enumeration |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://www.blackhillsinfosec.com/red-blue-purple/](https://www.blackhillsinfosec.com/red-blue-purple/)
* [https://docs.microsoft.com/en-us/windows/win32/wmisdk/describing-the-ldap-namespace](https://docs.microsoft.com/en-us/windows/win32/wmisdk/describing-the-ldap-namespace)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/AD_discovery/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/AD_discovery/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/getwmiobject_ds_user_with_powershell_script_block.yml) \| *version*: **2**