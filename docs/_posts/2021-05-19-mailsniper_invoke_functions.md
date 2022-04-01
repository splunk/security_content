---
title: "Mailsniper Invoke functions"
excerpt: "Email Collection
, Local Email Collection
"
categories:
  - Endpoint
last_modified_at: 2021-05-19
toc: true
toc_label: ""
tags:
  - Email Collection
  - Local Email Collection
  - Collection
  - Collection
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect known mailsniper.ps1 functions executed in a machine. This technique was seen in some attacker to harvest some sensitive e-mail in a compromised exchange server.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-19
- **Author**: Teoderick Contreras, Splunk
- **ID**: a36972c8-b894-11eb-9f78-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1114](https://attack.mitre.org/techniques/T1114/) | Email Collection | Collection |

| [T1114.001](https://attack.mitre.org/techniques/T1114/001/) | Local Email Collection | Collection |

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
`powershell` EventCode=4104 Message IN ("*Invoke-GlobalO365MailSearch*", "*Invoke-GlobalMailSearch*", "*Invoke-SelfSearch*", "*Invoke-PasswordSprayOWA*", "*Invoke-PasswordSprayEWS*","*Invoke-DomainHarvestOWA*", "*Invoke-UsernameHarvestOWA*","*Invoke-OpenInboxFinder*","*Invoke-InjectGEventAPI*","*Invoke-InjectGEvent*","*Invoke-SearchGmail*", "*Invoke-MonitorCredSniper*", "*Invoke-AddGmailRule*","*Invoke-PasswordSprayEAS*","*Invoke-UsernameHarvestEAS*") 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Message ComputerName User 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `mailsniper_invoke_functions_filter`
```

#### Macros
The SPL above uses the following Macros:
* [powershell](https://github.com/splunk/security_content/blob/develop/macros/powershell.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **mailsniper_invoke_functions_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* Message
* ComputerName
* User


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the powershell logs  from your endpoints. make sure you enable needed registry to monitor this event.

#### Known False Positives
unknown

#### Associated Analytic story
* [Data Exfiltration](/stories/data_exfiltration)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 90 | 80 | mailsniper.ps1 functions $Message$ executed on a $ComputerName$ by user $user$. |


#### Reference

* [https://www.blackhillsinfosec.com/introducing-mailsniper-a-tool-for-searching-every-users-email-for-sensitive-data/](https://www.blackhillsinfosec.com/introducing-mailsniper-a-tool-for-searching-every-users-email-for-sensitive-data/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/honeypots/casper/datasets1/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/honeypots/casper/datasets1/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/mailsniper_invoke_functions.yml) \| *version*: **1**