---
title: "Windows PowerView SPN Discovery"
excerpt: "Steal or Forge Kerberos Tickets
, Kerberoasting
"
categories:
  - Endpoint
last_modified_at: 2022-06-22
toc: true
toc_label: ""
tags:
  - Steal or Forge Kerberos Tickets
  - Kerberoasting
  - Credential Access
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic utilizes PowerShell Script Block Logging (EventCode=4104) to identify the execution of the `Get-DomainUser` or `Get-NetUSer` commandlets with specific parameters. These commandlets are part of PowerView, a PowerShell tool used to perform enumeration and discovery on Windows Active Directory networks. As the names suggest, these commandlets are used to identify domain users in a network and combining them with the `-SPN` parameter allows adversaries to discover domain accounts associated with a Service Principal Name (SPN). Red Teams and adversaries alike may leverage PowerView and these commandlets to identify accounts that can be attacked with the Kerberoasting technique.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-06-22
- **Author**: Gowthamaraj Rajendran, Splunk
- **ID**: a7093c28-796c-4ebb-9997-e2c18b870837


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1558](https://attack.mitre.org/techniques/T1558/) | Steal or Forge Kerberos Tickets | Credential Access |

| [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | Kerberoasting | Credential Access |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Reconnaissance
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
`powershell` EventCode=4104 (ScriptBlockText =*Get-NetUser* OR ScriptBlockText=*Get-DomainUser*) ScriptBlockText= *-SPN* 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode ScriptBlockText Computer 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
| `windows_powerview_spn_discovery_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [powershell](https://github.com/splunk/security_content/blob/develop/macros/powershell.yml)

> :information_source:
> **windows_powerview_spn_discovery_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* Computer
* ScriptBlockText


#### How To Implement
The following analytic requires PowerShell operational logs to be imported. Modify the powershell macro as needed to match the sourcetype or add index. This analytic is specific to 4104, or PowerShell Script Block Logging.

#### Known False Positives
False positive may include Administrators using PowerView for troubleshooting and management.

#### Associated Analytic story
* [Active Directory Kerberos Attacks](/stories/active_directory_kerberos_attacks)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 27.0 | 30 | 90 | PowerView commandlets used for SPN discovery executed on $Computer$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast)
* [https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
* [https://attack.mitre.org/techniques/T1558/003](https://attack.mitre.org/techniques/T1558/003)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.003/powerview-2/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.003/powerview-2/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_powerview_spn_discovery.yml) \| *version*: **1**