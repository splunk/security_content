---
title: "Enumerate Users Local Group Using Telegram"
excerpt: "Account Discovery"
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



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic will detect a suspicious Telegram process enumerating all network users in a local group. This technique was seen in a Monero infected honeypot to mapped all the users on the compromised system. EventCode 4798 is generated when a process enumerates a user&#39;s security-enabled local groups on a computer or device.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-06
- **Author**: Teoderick Contreras, Splunk
- **ID**: fcd74532-ae54-11eb-a5ab-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1087](https://attack.mitre.org/techniques/T1087/) | Account Discovery | Discovery |

#### Search

```
`wineventlog_security` EventCode=4798  Process_Name = "*\\telegram.exe" 
| stats count min(_time) as firstTime max(_time) as lastTime by ComputerName EventCode Process_Name  Process_ID Account_Name Account_Domain Logon_ID Security_ID Message 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `enumerate_users_local_group_using_telegram_filter`
```

#### Associated Analytic Story
* [XMRig](/stories/xmrig)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the Task Schedule (Exa. Security Log EventCode 4798) endpoints. Tune and filter known instances of process like logonUI used in your environment.

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


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | The Telegram application has been identified enumerating local groups on $ComputerName$ by $user$. |




#### Reference

* [https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/](https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/)
* [https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4798](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4798)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/minergate/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/minergate/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/enumerate_users_local_group_using_telegram.yml) \| *version*: **1**