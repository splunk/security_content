---
title: "Suspicious Computer Account Name Change"
excerpt: "Valid Accounts
, Domain Accounts
"
categories:
  - Endpoint
last_modified_at: 2021-12-20
toc: true
toc_label: ""
tags:
  - Valid Accounts
  - Domain Accounts
  - Defense Evasion
  - Initial Access
  - Persistence
  - Privilege Escalation
  - Defense Evasion
  - Initial Access
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2021-42287
  - CVE-2021-42278
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

As part of the sAMAccountName Spoofing (CVE-2021-42278) and Domain Controller Impersonation (CVE-2021-42287) exploitation chain, adversaries need to create a new computer account name and rename it to match the name of a domain controller account without the ending '$'. In Windows Active Directory environments, computer account names always end with `$`. This analytic leverages Event Id 4781, `The name of an account was changed`, to identify a computer account rename event with a suspicious name that does not terminate with `$`. This behavior could represent an exploitation attempt of CVE-2021-42278 and CVE-2021-42287 for privilege escalation.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-12-20
- **Author**: Mauricio Velazco, Splunk
- **ID**: 35a61ed8-61c4-11ec-bc1e-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

| [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Domain Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Search

```
`wineventlog_security` EventCode=4781 Old_Account_Name="*$" New_Account_Name!="*$" 
| table _time, ComputerName, Account_Name, Old_Account_Name, New_Account_Name 
| `suspicious_computer_account_name_change_filter`
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)

Note that `suspicious_computer_account_name_change_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* ComputerName
* Account_Name
* Old_Account_Name
* New_Account_Name


#### How To Implement
To successfully implement this search, you need to be ingesting Windows event logs from your hosts. In addition, the Splunk Windows TA is needed.

#### Known False Positives
Renaming a computer account name to a name that not end with '$' is highly unsual and may not have any legitimate scenarios.

#### Associated Analytic story
* [sAMAccountName Spoofing and Domain Controller Impersonation](/stories/samaccountname_spoofing_and_domain_controller_impersonation)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 70.0 | 100 | 70 | A computer account $Old_Account_Name$ was renamed with a suspicious computer name |


#### CVE

| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2021-42287](https://nvd.nist.gov/vuln/detail/CVE-2021-42287) | Active Directory Domain Services Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-42278, CVE-2021-42282, CVE-2021-42291. | 6.5 |
| [CVE-2021-42278](https://nvd.nist.gov/vuln/detail/CVE-2021-42278) | Active Directory Domain Services Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-42282, CVE-2021-42287, CVE-2021-42291. | 6.5 |



#### Reference

* [https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html](https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html)
* [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278)
* [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.002/samaccountname_spoofing/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.002/samaccountname_spoofing/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/suspicious_computer_account_name_change.yml) \| *version*: **1**