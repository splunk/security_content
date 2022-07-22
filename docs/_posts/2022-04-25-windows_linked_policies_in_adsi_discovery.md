---
title: "Windows Linked Policies In ADSI Discovery"
excerpt: "Domain Account
, Account Discovery
"
categories:
  - Endpoint
last_modified_at: 2022-04-25
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
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic utilizes PowerShell Script Block Logging (EventCode=4104) to identify the `[Adsisearcher]` type accelerator being used to query Active Directory for domain groups. Red Teams and adversaries may leverage `[Adsisearcher]` to enumerate domain organizational unit for situational awareness and Active Directory Discovery.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-04-25
- **Author**: Teoderick Contreras, Splunk
- **ID**: 510ea428-4731-4d2f-8829-a28293e427aa


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
`powershell` EventCode=4104 ScriptBlockText = "*[adsisearcher]*" ScriptBlockText = "*objectcategory=organizationalunit*" ScriptBlockText = "*findAll()*" 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode ScriptBlockText Computer user_id 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_linked_policies_in_adsi_discovery_filter`
```

#### Macros
The SPL above uses the following Macros:
* [powershell](https://github.com/splunk/security_content/blob/develop/macros/powershell.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **windows_linked_policies_in_adsi_discovery_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* ScriptBlockText
* Computer
* user_id


#### How To Implement
The following Hunting analytic requires PowerShell operational logs to be imported. Modify the powershell macro as needed to match the sourcetype or add index. This analytic is specific to 4104, or PowerShell Script Block Logging.

#### Known False Positives
Administrators or power users may use this command for troubleshooting.

#### Associated Analytic story
* [Industroyer2](/stories/industroyer2)
* [Active Directory Discovery](/stories/active_directory_discovery)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | powershell process having commandline $Message$ for user enumeration |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/](https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/)
* [https://medium.com/@pentesttas/discover-hidden-gpo-s-on-active-directory-using-ps-adsi-a284b6814c81](https://medium.com/@pentesttas/discover-hidden-gpo-s-on-active-directory-using-ps-adsi-a284b6814c81)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/adsi_discovery/windows-powershell-xml2.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/adsi_discovery/windows-powershell-xml2.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_linked_policies_in_adsi_discovery.yml) \| *version*: **1**