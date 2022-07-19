---
title: "Windows Kerberos Local Successful Logon"
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

The following analytic identifies a local successful authentication event on a Windows endpoint using the Kerberos package. The target user security identified will be set to the built-in local Administrator account, along with the remote address as localhost - 127.0.0.1. This may be indicative of a kerberos relay attack. Upon triage, review for recently ran binaries on disk. In addition, look for new computer accounts added to Active Directory and other anomolous AD events.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-04-27
- **Author**: Michael Haag, Splunk
- **ID**: 8309c3a8-4d34-48ae-ad66-631658214653


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
`wineventlog_security`  EventCode=4624 Logon_Type=3 Authentication_Package=Kerberos action=success src_ip=127.0.0.1 
| stats count min(_time) as firstTime max(_time) as lastTime by dest, subject, action, Security_ID, user, Account_Name, src_ip 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_kerberos_local_successful_logon_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)

> :information_source:
> **windows_kerberos_local_successful_logon_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* dest
* subject
* action
* Security_ID
* user
* Account_Name
* src_ip


#### How To Implement
To successfully implement this search, you need to be ingesting Windows Security Event Logs with 4624 EventCode enabled. The Windows TA is also required.

#### Known False Positives
False positives are possible, filtering may be required to restrict to workstations vs domain controllers. Filter as needed.

#### Associated Analytic story
* [Active Directory Kerberos Attacks](/stories/active_directory_kerberos_attacks)
* [Local Privilege Escalation With KrbRelayUp](/stories/local_privilege_escalation_with_krbrelayup)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | A successful localhost Kerberos authentication event occurred on $dest$, possibly indicative of Kerberos relay attack. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://github.com/Dec0ne/KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558/krbrelayup/krbrelayup.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558/krbrelayup/krbrelayup.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_kerberos_local_successful_logon.yml) \| *version*: **1**