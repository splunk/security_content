---
title: "Multiple Disabled Users Failing To Authenticate From Host Using Kerberos"
excerpt: "Password Spraying
, Brute Force
"
categories:
  - Endpoint
last_modified_at: 2021-04-14
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



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies one source endpoint failing to authenticate with multiple disabled domain users using the Kerberos protocol. This behavior could represent an adversary performing a Password Spraying attack against an Active Directory environment using Kerberos to obtain initial access or elevate privileges. As attackers progress in a breach, mistakes will be made. In certain scenarios, adversaries may execute a password spraying attack against disabled users. Event 4768 is generated every time the Key Distribution Center issues a Kerberos Ticket Granting Ticket (TGT). Failure code `0x12` stands for `clients credentials have been revoked` (account disabled, expired or locked out).\
The detection calculates the standard deviation for each host and leverages the 3-sigma statistical rule to identify an unusual number of users. To customize this analytic, users can try different combinations of the `bucket` span time and the calculation of the `upperBound` field. This logic can be used for real time security monitoring as well as threat hunting exercises.\
This detection will only trigger on domain controllers, not on member servers or workstations.\
The analytics returned fields allow analysts to investigate the event further by providing fields like source ip and attempted user accounts.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-04-14
- **Author**: Mauricio Velazco, Splunk
- **ID**: 98f22d82-9d62-11eb-9fcf-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Password Spraying | Credential Access |

| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | Credential Access |

#### Search

```
`wineventlog_security` EventCode=4768 Account_Name!="*$" Result_Code=0x12 
| bucket span=2m _time 
| stats dc(Account_Name) AS unique_accounts values(Account_Name) as tried_accounts by _time, Client_Address 
| eventstats avg(unique_accounts) as comp_avg , stdev(unique_accounts) as comp_std by Client_Address 
| eval upperBound=(comp_avg+comp_std*3) 
| eval isOutlier=if(unique_accounts > 10 and unique_accounts >= upperBound, 1, 0) 
| search isOutlier=1 
| `multiple_disabled_users_failing_to_authenticate_from_host_using_kerberos_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)

Note that `multiple_disabled_users_failing_to_authenticate_from_host_using_kerberos_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* Result_Code
* Account_Name
* Client_Address


#### How To Implement
To successfully implement this search, you need to be ingesting Domain Controller and Kerberos events. The Advanced Security Audit policy setting `Audit Kerberos Authentication Service` within `Account Logon` needs to be enabled.

#### Known False Positives
A host failing to authenticate with multiple disabled domain users is not a common behavior for legitimate systems. Possible false positive scenarios include but are not limited to vulnerability scanners, multi-user systems missconfigured systems.

#### Associated Analytic story
* [Active Directory Password Spraying](/stories/active_directory_password_spraying)
* [Active Directory Kerberos Attacks](/stories/active_directory_kerberos_attacks)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | Potential Kerberos based password spraying attack from $Client_Address$ |




#### Reference

* [https://attack.mitre.org/techniques/T1110/003/](https://attack.mitre.org/techniques/T1110/003/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/purplesharp_disabled_users_kerberos/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/purplesharp_disabled_users_kerberos/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/multiple_disabled_users_failing_to_authenticate_from_host_using_kerberos.yml) \| *version*: **1**