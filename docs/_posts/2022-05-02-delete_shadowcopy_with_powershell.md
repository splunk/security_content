---
title: "Delete ShadowCopy With PowerShell"
excerpt: "Inhibit System Recovery
"
categories:
  - Endpoint
last_modified_at: 2022-05-02
toc: true
toc_label: ""
tags:
  - Inhibit System Recovery
  - Impact
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

This following analytic detects PowerShell command to delete shadow copy using the WMIC PowerShell module. This technique was seen used by a recent adversary to deploy DarkSide Ransomware where it executed a child process of PowerShell to execute a hex encoded command to delete shadow copy. This hex encoded command was able to be decrypted by PowerShell log.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-05-02
- **Author**: Teoderick Contreras, Splunk
- **ID**: 5ee2bcd0-b2ff-11eb-bb34-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1490](https://attack.mitre.org/techniques/T1490/) | Inhibit System Recovery | Impact |

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
`powershell` EventCode=4104 ScriptBlockText= "*ShadowCopy*" (ScriptBlockText = "*Delete*" OR ScriptBlockText = "*Remove*") 
| stats count min(_time) as firstTime max(_time) as lastTime by Opcode Computer UserID EventCode ScriptBlockText 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `delete_shadowcopy_with_powershell_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [powershell](https://github.com/splunk/security_content/blob/develop/macros/powershell.yml)

> :information_source:
> **delete_shadowcopy_with_powershell_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* ScriptBlockText
* Opcode
* Computer
* UserID
* EventCode


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the powershell logs  from your endpoints. make sure you enable needed registry to monitor this event.

#### Known False Positives
unknown

#### Associated Analytic story
* [DarkSide Ransomware](/stories/darkside_ransomware)
* [Ransomware](/stories/ransomware)
* [Revil Ransomware](/stories/revil_ransomware)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 81.0 | 90 | 90 | An attempt to delete ShadowCopy was performed using PowerShell on $Computer$ by $User$. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://www.mandiant.com/resources/shining-a-light-on-darkside-ransomware-operations](https://www.mandiant.com/resources/shining-a-light-on-darkside-ransomware-operations)
* [https://www.techtarget.com/searchwindowsserver/tutorial/Set-up-PowerShell-script-block-logging-for-added-security](https://www.techtarget.com/searchwindowsserver/tutorial/Set-up-PowerShell-script-block-logging-for-added-security)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/sbl_xml.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/sbl_xml.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/delete_shadowcopy_with_powershell.yml) \| *version*: **2**