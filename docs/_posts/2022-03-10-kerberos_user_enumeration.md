---
title: "Kerberos User Enumeration"
excerpt: "Gather Victim Identity Information
, Email Addresses
"
categories:
  - Endpoint
last_modified_at: 2022-03-10
toc: true
toc_label: ""
tags:
  - Gather Victim Identity Information
  - Email Addresses
  - Reconnaissance
  - Reconnaissance
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic leverages Event Id 4768, A Kerberos authentication ticket (TGT) was requested, to identify one source endpoint trying to obtain an unusual number Kerberos TGT ticket for non existing users. This behavior could represent an adversary abusing the Kerberos protocol to perform a user enumeration attack against an Active Directory environment. When Kerberos is sent a TGT request with no preauthentication for an invalid username, it responds with KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN or 0x6. Red teams and adversaries alike may abuse the Kerberos protocol to validate a list of users use them to perform further attacks.\ The detection calculates the standard deviation for each host and leverages the 3-sigma statistical rule to identify an unusual number requests. To customize this analytic, users can try different combinations of the `bucket` span time and the calculation of the `upperBound` field.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-03-10
- **Author**: Mauricio Velazco, Splunk
- **ID**: d82d4af4-a0bd-11ec-9445-3e22fbd008af


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1589](https://attack.mitre.org/techniques/T1589/) | Gather Victim Identity Information | Reconnaissance |

| [T1589.002](https://attack.mitre.org/techniques/T1589/002/) | Email Addresses | Reconnaissance |

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
 `wineventlog_security` EventCode=4768 Result_Code=0x6 Account_Name!="*$" 
| bucket span=2m _time 
| stats dc(Account_Name) AS unique_accounts values(Account_Name) as tried_accounts by _time, Client_Address 
| eventstats avg(unique_accounts) as comp_avg , stdev(unique_accounts) as comp_std by Client_Address 
| eval upperBound=(comp_avg+comp_std*3) 
| eval isOutlier=if(unique_accounts > 10 and unique_accounts >= upperBound, 1, 0) 
| search isOutlier=1 
| `kerberos_user_enumeration_filter`
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)

> :information_source:
> **kerberos_user_enumeration_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* Result_Code
* Account_Name
* Client_Address


#### How To Implement
To successfully implement this search, you need to be ingesting Domain Controller and Kerberos events. The Advanced Security Audit policy setting `Audit Kerberos Authentication Service` within `Account Logon` needs to be enabled.

#### Known False Positives
Possible false positive scenarios include but are not limited to vulnerability scanners and missconfigured systems.

#### Associated Analytic story
* [Active Directory Kerberos Attacks](/stories/active_directory_kerberos_attacks)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 24.0 | 30 | 80 | Potential Kerberos based user enumeration attack $Client_Address$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://github.com/ropnop/kerbrute](https://github.com/ropnop/kerbrute)
* [https://attack.mitre.org/techniques/T1589/002/](https://attack.mitre.org/techniques/T1589/002/)
* [https://redsiege.com/tools-techniques/2020/04/user-enumeration-part-3-windows/](https://redsiege.com/tools-techniques/2020/04/user-enumeration-part-3-windows/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1589.002/kerbrute/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1589.002/kerbrute/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/kerberos_user_enumeration.yml) \| *version*: **1**