---
title: "Multiple Users Failing To Authenticate From Host Using Kerberos"
excerpt: "Password Spraying
, Brute Force
"
categories:
  - Endpoint
last_modified_at: 2021-04-08
toc: true
toc_label: ""
tags:
  - Password Spraying
  - Brute Force
  - Credential Access
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies one source endpoint failing to authenticate with multiple valid users using the Kerberos protocol. This behavior could represent an adversary performing a Password Spraying attack against an Active Directory environment using Kerberos to obtain initial access or elevate privileges. Event 4771 is generated when the Key Distribution Center fails to issue a Kerberos Ticket Granting Ticket (TGT). Failure code 0x18 stands for `wrong password provided` (the attempted user is a legitimate domain user).\
The detection calculates the standard deviation for each host and leverages the 3-sigma statistical rule to identify an unusual number of users. To customize this analytic, users can try different combinations of the `bucket` span time and the calculation of the `upperBound` field. This logic can be used for real time security monitoring as well as threat hunting exercises.\
This detection will only trigger on domain controllers, not on member servers or workstations.\
The analytics returned fields allow analysts to investigate the event further by providing fields like source ip and attempted user accounts.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2021-04-08
- **Author**: Mauricio Velazco, Splunk
- **ID**: 3a91a212-98a9-11eb-b86a-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Password Spraying | Credential Access |

| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | Credential Access |

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
`wineventlog_security` EventCode=4771 Failure_Code=0x18 Account_Name!="*$" 
| bucket span=2m _time 
| stats dc(Account_Name) AS unique_accounts values(Account_Name) as tried_accounts by _time, Client_Address 
| eventstats avg(unique_accounts) as comp_avg , stdev(unique_accounts) as comp_std by Client_Address 
| eval upperBound=(comp_avg+comp_std*3) 
| eval isOutlier=if(unique_accounts > 10 and unique_accounts >= upperBound, 1, 0) 
| search isOutlier=1 
| `multiple_users_failing_to_authenticate_from_host_using_kerberos_filter`
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)

Note that **multiple_users_failing_to_authenticate_from_host_using_kerberos_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* Result_Code
* Account_Name
* Client_Address


#### How To Implement
To successfully implement this search, you need to be ingesting Domain Controller and Kerberos events. The Advanced Security Audit policy setting `Audit Kerberos Authentication Service` within `Account Logon` needs to be enabled.

#### Known False Positives
A host failing to authenticate with multiple valid domain users is not a common behavior for legitimate systems. Possible false positive scenarios include but are not limited to vulnerability scanners, missconfigured systems and multi-user systems like Citrix farms.

#### Associated Analytic story
* [Active Directory Password Spraying](/stories/active_directory_password_spraying)
* [Active Directory Kerberos Attacks](/stories/active_directory_kerberos_attacks)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | Potential Kerberos based password spraying attack from $Client_Address$ |


#### Reference

* [https://attack.mitre.org/techniques/T1110/003/](https://attack.mitre.org/techniques/T1110/003/)
* [https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn319109(v=ws.11)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn319109(v=ws.11))
* [https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4771](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4771)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/purplesharp_valid_users_kerberos/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/purplesharp_valid_users_kerberos/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/multiple_users_failing_to_authenticate_from_host_using_kerberos.yml) \| *version*: **1**