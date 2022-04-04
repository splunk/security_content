---
title: "Enumerate Users Local Group Using Telegram"
excerpt: "Account Discovery
"
categories:
  - Endpoint
last_modified_at: 2021-05-06
toc: true
toc_label: ""
tags:
  - Account Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic will detect a suspicious Telegram process enumerating all network users in a local group. This technique was seen in a Monero infected honeypot to mapped all the users on the compromised system. EventCode 4798 is generated when a process enumerates a user's security-enabled local groups on a computer or device.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-06
- **Author**: Teoderick Contreras, Splunk
- **ID**: fcd74532-ae54-11eb-a5ab-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1087](https://attack.mitre.org/techniques/T1087/) | Account Discovery | Discovery |

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
`wineventlog_security` EventCode=4798  Process_Name = "*\\telegram.exe" 
| stats count min(_time) as firstTime max(_time) as lastTime by ComputerName EventCode Process_Name  Process_ID Account_Name Account_Domain Logon_ID Security_ID Message 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `enumerate_users_local_group_using_telegram_filter`
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **enumerate_users_local_group_using_telegram_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* ComputerName
* EventCode
* Process_Name
* Process_ID
* Account_Name
* Account_Domain
* Logon_ID
* Security_ID
* Message


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the Task Schedule (Exa. Security Log EventCode 4798) endpoints. Tune and filter known instances of process like logonUI used in your environment.

#### Known False Positives
unknown

#### Associated Analytic story
* [XMRig](/stories/xmrig)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | The Telegram application has been identified enumerating local groups on $ComputerName$ by $user$. |


#### Reference

* [https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/](https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/)
* [https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4798](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4798)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/minergate/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/minergate/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/enumerate_users_local_group_using_telegram.yml) \| *version*: **1**