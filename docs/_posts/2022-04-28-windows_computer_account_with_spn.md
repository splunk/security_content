---
title: "Windows Computer Account With SPN"
excerpt: "Steal or Forge Kerberos Tickets
"
categories:
  - Endpoint
last_modified_at: 2022-04-28
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

The following analytic identifies two SPNs, HOST and RestrictedKrbHost, added using the KrbRelayUp behavior. This particular behavior has been found in other Kerberos based attacks.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-04-28
- **Author**: Michael Haag, Splunk
- **ID**: 9a3e57e7-33f4-470e-b25d-165baa6e8357


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

* Installation


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
`wineventlog_security` EventCode=4741 MSADChangedAttributes IN ("*HOST/*","*RestrictedKrbHost/*") AND New_UAC_Value=0x80 
| eval Effecting_Account=mvindex(Security_ID,1) 
| eval New_Computer_Account_Name=mvindex(Security_ID,0) 
| stats count min(_time) as firstTime max(_time) as lastTime values(EventCode),values(Account_Domain),values(Security_ID), values(Effecting_Account), values(New_Computer_Account_Name),values(SAM_Account_Name),values(DNS_Host_Name),values(MSADChangedAttributes) by dest Logon_ID subject 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_computer_account_with_spn_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)

> :information_source:
> **windows_computer_account_with_spn_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* MSADChangedAttributes
* New_UAC_Value
* Security_ID
* Account_Domain
* SAM_Account_Name
* DNS_Host_Name
* Logon_Id


#### How To Implement
To successfully implement this search, you need to be ingesting Windows Security Event Logs with 4741 EventCode enabled. The Windows TA is also required.

#### Known False Positives
It is possible third party applications may add these SPNs to Computer Accounts, filtering may be needed.

#### Associated Analytic story
* [Active Directory Kerberos Attacks](/stories/active_directory_kerberos_attacks)
* [Local Privilege Escalation With KrbRelayUp](/stories/local_privilege_escalation_with_krbrelayup)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 64.0 | 80 | 80 | A Computer Account was created with SPNs related to Kerberos on $dest$, possibly indicative of Kerberos relay attack. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://www.trustedsec.com/blog/an-attack-path-mapping-approach-to-cves-2021-42287-and-2021-42278](https://www.trustedsec.com/blog/an-attack-path-mapping-approach-to-cves-2021-42287-and-2021-42278)
* [https://github.com/Dec0ne/KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558/krbrelayup/krbrelayup.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558/krbrelayup/krbrelayup.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_computer_account_with_spn.yml) \| *version*: **1**