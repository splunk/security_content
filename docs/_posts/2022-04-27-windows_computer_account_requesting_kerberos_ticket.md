---
title: "Windows Computer Account Requesting Kerberos Ticket"
excerpt: "Steal or Forge Kerberos Tickets
"
categories:
  - Endpoint
last_modified_at: 2022-04-27
toc: true
toc_label: ""
tags:
  - Steal or Forge Kerberos Tickets
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies a ComputerAccount requesting a Kerberos Ticket. typically, a user account requests a Kerberos ticket. This behavior was identified with KrbUpRelay, but additional Kerberos attacks have exhibited similar behavior.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-04-27
- **Author**: Michael Haag, Splunk
- **ID**: fb3b2bb3-75a4-4279-848a-165b42624770


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1558](https://attack.mitre.org/techniques/T1558/) | Steal or Forge Kerberos Tickets | Credential Access |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Actions on Objectives


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
`wineventlog_security`  EventCode=4768 Account_Name="*$"  src_ip!="::1" 
| stats  count min(_time) as firstTime max(_time) as lastTime by dest, subject, action, Supplied_Realm_Name, user, Account_Name, src_ip 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_computer_account_requesting_kerberos_ticket_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)

> :information_source:
> **windows_computer_account_requesting_kerberos_ticket_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* dest
* subject
* action
* Supplied_Realm_Name
* user
* Account_Name
* src_ip


#### How To Implement
To successfully implement this search, you need to be ingesting Windows Security Event Logs with 4768 EventCode enabled. The Windows TA is also required.

#### Known False Positives
It is possible false positives will be present based on third party applications. Filtering may be needed.

#### Associated Analytic story
* [Active Directory Kerberos Attacks](/stories/active_directory_kerberos_attacks)
* [Local Privilege Escalation With KrbRelayUp](/stories/local_privilege_escalation_with_krbrelayup)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 50 | 70 | A Computer Account requested a Kerberos ticket on $dest$, possibly indicative of Kerberos relay attack. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://github.com/Dec0ne/KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558/krbrelayup/krbrelayup.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558/krbrelayup/krbrelayup.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_computer_account_requesting_kerberos_ticket.yml) \| *version*: **1**