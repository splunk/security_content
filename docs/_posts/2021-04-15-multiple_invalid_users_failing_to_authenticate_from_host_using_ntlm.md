---
title: "Multiple Invalid Users Failing To Authenticate From Host Using NTLM"
excerpt: "Password Spraying
, Brute Force
"
categories:
  - Endpoint
last_modified_at: 2021-04-15
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

The following analytic identifies one source endpoint failing to authenticate with multiple invalid users using the NTLM protocol. This behavior could represent an adversary performing a Password Spraying attack against an Active Directory environment using NTLM to obtain initial access or elevate privileges. As attackers progress in a breach, mistakes will be made. In certain scenarios, adversaries may execute a password spraying attack using an invalid list of users. Event 4776 is generated on the computer that is authoritative for the provided credentials. For domain accounts, the domain controller is authoritative. For local accounts, the local computer is authoritative. Error code 0xC0000064 stands for `The username you typed does not exist` (the attempted user is a legitimate domain user).\
The detection calculates the standard deviation for each host and leverages the 3-sigma statistical rule to identify an unusual number of users. To customize this analytic, users can try different combinations of the `bucket` span time and the calculation of the `upperBound` field. This logic can be used for real time security monitoring as well as threat hunting exercises.\
This detection will only trigger on domain controllers, not on member servers or workstations.\
The analytics returned fields allow analysts to investigate the event further by providing fields like source workstation name and attempted user accounts.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2021-04-15
- **Author**: Mauricio Velazco, Splunk
- **ID**: 57ad5a64-9df7-11eb-a290-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Password Spraying | Credential Access |

| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | Credential Access |

#### Search

```
 `wineventlog_security` EventCode=4776 Logon_Account!="*$" 0xC0000064 action=failure 
| bucket span=2m _time 
| stats dc(Logon_Account) AS unique_accounts values(Logon_Account) as tried_accounts by _time, Source_Workstation 
| eventstats avg(unique_accounts) as comp_avg , stdev(unique_accounts) as comp_std by Source_Workstation 
| eval upperBound=(comp_avg+comp_std*3) 
| eval isOutlier=if(unique_accounts > 10 and unique_accounts >= upperBound, 1, 0) 
| search isOutlier=1 
| `multiple_invalid_users_failing_to_authenticate_from_host_using_ntlm_filter`
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)

Note that `multiple_invalid_users_failing_to_authenticate_from_host_using_ntlm_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* action
* Logon_Account
* Source_Workstation


#### How To Implement
To successfully implement this search, you need to be ingesting Domain Controller events. The Advanced Security Audit policy setting `Audit Credential Validation' within `Account Logon` needs to be enabled.

#### Known False Positives
A host failing to authenticate with multiple invalid domain users is not a common behavior for legitimate systems. Possible false positive scenarios include but are not limited to vulnerability scanners and missconfigured systems. If this detection triggers on a host other than a Domain Controller, the behavior could represent a password spraying attack against the host's local accounts.

#### Associated Analytic story
* [Active Directory Password Spraying](/stories/active_directory_password_spraying)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | Potential NTLM based password spraying attack from $Source_Workstation$ |




#### Reference

* [https://attack.mitre.org/techniques/T1110/003/](https://attack.mitre.org/techniques/T1110/003/)
* [https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-credential-validation](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-credential-validation)
* [https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4776](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4776)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/purplesharp_invalid_users_ntlm/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/purplesharp_invalid_users_ntlm/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/multiple_invalid_users_failing_to_authenticate_from_host_using_ntlm.yml) \| *version*: **1**