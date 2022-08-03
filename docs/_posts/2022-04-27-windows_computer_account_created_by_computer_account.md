---
title: "Windows Computer Account Created by Computer Account"
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

The following analytic identifes a Computer Account creating a new Computer Account with specific a Service Principle Name - "RestrictedKrbHost". The RestrictedKrbHost service class allows client applications to use Kerberos authentication when they do not have the identity of the service but have the server name.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-04-27
- **Author**: Michael Haag, Splunk
- **ID**: 97a8dc5f-8a7c-4fed-9e3e-ec407fd0268a


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
`wineventlog_security` EventCode=4741 user_type=computer Subject_Account_Domain!="NT AUTHORITY"  Message=*RestrictedKrbHost* 
| stats  count min(_time) as firstTime max(_time) as lastTime by dest, subject, action ,src_user, user, Account_Name, Subject_Account_Name,Subject_Account_Domain 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_computer_account_created_by_computer_account_filter`
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **windows_computer_account_created_by_computer_account_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* dest
* subject
* action
* src_user
* user
* Account_Name
* Subject_Account_Name
* Subject_Account_Domain


#### How To Implement
To successfully implement this search, you need to be ingesting Windows Security Event Logs with 4741 EventCode enabled. The Windows TA is also required.

#### Known False Positives
It is possible third party applications may have a computer account that adds computer accounts, filtering may be required.

#### Associated Analytic story
* [Active Directory Kerberos Attacks](/stories/active_directory_kerberos_attacks)
* [Local Privilege Escalation With KrbRelayUp](/stories/local_privilege_escalation_with_krbrelayup)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 30.0 | 50 | 60 | A Computer Account created a Computer Account on $dest$, possibly indicative of Kerberos relay attack. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/445e4499-7e49-4f2a-8d82-aaf2d1ee3c47](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/445e4499-7e49-4f2a-8d82-aaf2d1ee3c47)
* [https://github.com/Dec0ne/KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558/krbrelayup/krbrelayup.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558/krbrelayup/krbrelayup.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_computer_account_created_by_computer_account.yml) \| *version*: **1**