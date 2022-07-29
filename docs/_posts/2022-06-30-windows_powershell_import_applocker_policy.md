---
title: "Windows Powershell Import Applocker Policy"
excerpt: "PowerShell
"
categories:
  - Endpoint
last_modified_at: 2022-06-30
toc: true
toc_label: ""
tags:
  - PowerShell
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic is to identify the imports of Windows PowerShell Applocker commandlets. This technique was seen in Azorult malware where it drops an xml Applocker policy that will deny several AV product and then loaded using PowerShell Applocker commandlet.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-06-30
- **Author**: Teoderick Contreras, Splunk
- **ID**: 102af98d-0ca3-4aa4-98d6-7ab2b98b955a


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Execution |

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

* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 5
* CIS 16



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search 

```
`powershell` EventCode=4104 ScriptBlockText="*Import-Module Applocker*" ScriptBlockText="*Set-AppLockerPolicy *" ScriptBlockText="* -XMLPolicy *" 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode ScriptBlockText Computer user_id 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_powershell_import_applocker_policy_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [powershell](https://github.com/splunk/security_content/blob/develop/macros/powershell.yml)

> :information_source:
> **windows_powershell_import_applocker_policy_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* ScriptBlockText
* Computer
* EventCode


#### How To Implement
To successfully implement this analytic, you will need to enable PowerShell Script Block Logging on some or all endpoints. Additional setup here https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell.

#### Known False Positives
administrators may execute this command that may cause some false positive.

#### Associated Analytic story
* [Azorult](/stories/azorult)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | A PowerShell script contains Import Applocker Policy command $ScriptBlockText$ with EventCode $EventCode$ in host $Computer$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://app.any.run/tasks/a6f2ffe2-e6e2-4396-ae2e-04ea0143f2d8/](https://app.any.run/tasks/a6f2ffe2-e6e2-4396-ae2e-04ea0143f2d8/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/import_applocker_policy/windows-powershell-xml2.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/import_applocker_policy/windows-powershell-xml2.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_powershell_import_applocker_policy.yml) \| *version*: **1**