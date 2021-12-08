---
title: "Mailsniper Invoke functions"
excerpt: "Email Collection, Local Email Collection"
categories:
  - Endpoint
last_modified_at: 2021-05-19
toc: true
toc_label: ""
tags:
  - Email Collection
  - Collection
  - Local Email Collection
  - Collection
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect known mailsniper.ps1 functions executed in a machine. This technique was seen in some attacker to harvest some sensitive e-mail in a compromised exchange server.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-19
- **Author**: Teoderick Contreras, Splunk
- **ID**: a36972c8-b894-11eb-9f78-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1114](https://attack.mitre.org/techniques/T1114/) | Email Collection | Collection |

| [T1114.001](https://attack.mitre.org/techniques/T1114/001/) | Local Email Collection | Collection |

#### Search

```
`powershell` EventCode=4104 Message IN ("*Invoke-GlobalO365MailSearch*", "*Invoke-GlobalMailSearch*", "*Invoke-SelfSearch*", "*Invoke-PasswordSprayOWA*", "*Invoke-PasswordSprayEWS*","*Invoke-DomainHarvestOWA*", "*Invoke-UsernameHarvestOWA*","*Invoke-OpenInboxFinder*","*Invoke-InjectGEventAPI*","*Invoke-InjectGEvent*","*Invoke-SearchGmail*", "*Invoke-MonitorCredSniper*", "*Invoke-AddGmailRule*","*Invoke-PasswordSprayEAS*","*Invoke-UsernameHarvestEAS*") 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Message ComputerName User 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `mailsniper_invoke_functions_filter`
```

#### Associated Analytic Story
* [Data Exfiltration](/stories/data_exfiltration)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the powershell logs  from your endpoints. make sure you enable needed registry to monitor this event.

#### Required field
* _time
* EventCode
* Message
* ComputerName
* User


#### Kill Chain Phase
* Exploitation


#### Known False Positives
unknown


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 90 | 80 | mailsniper.ps1 functions $Message$ executed on a $ComputerName$ by user $user$. |




#### Reference

* [https://www.blackhillsinfosec.com/introducing-mailsniper-a-tool-for-searching-every-users-email-for-sensitive-data/](https://www.blackhillsinfosec.com/introducing-mailsniper-a-tool-for-searching-every-users-email-for-sensitive-data/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/honeypots/casper/datasets1/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/honeypots/casper/datasets1/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/mailsniper_invoke_functions.yml) \| *version*: **1**