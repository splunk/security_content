---
title: "Suspicious Computer Account Name Change"
excerpt: "Valid Accounts, Domain Accounts"
categories:
  - Endpoint
last_modified_at: 2021-12-20
toc: true
toc_label: ""
tags:
  - Valid Accounts
  - Defense Evasion
  - Persistence
  - Privilege Escalation
  - Initial Access
  - Domain Accounts
  - Defense Evasion
  - Persistence
  - Privilege Escalation
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2021-42287
  - CVE-2021-42278
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

As part of the sAMAccountName Spoofing (CVE-2021-42278) and Domain Controller Impersonation (CVE-2021-42287) exploitation chain, adversaries need to create a new computer account name and rename it to match the name of a domain controller account without the ending &#39;$&#39;. In Windows Active Directory environments, computer account names always end with `$`. This analytic leverages Event Id 4781, `The name of an account was changed`, to identify a computer account rename event with a suspicious name that does not terminate with `$`. This behavior could represent an exploitation attempt of CVE-2021-42278 and CVE-2021-42287 for privilege escalation.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-12-20
- **Author**: Mauricio Velazco, Splunk
- **ID**: 35a61ed8-61c4-11ec-bc1e-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

| [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Domain Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

#### Search

```
`wineventlog_security` EventCode=4781 Old_Account_Name="*$" New_Account_Name!="*$" 
| table _time, ComputerName, Account_Name, Old_Account_Name, New_Account_Name 
| `suspicious_computer_account_name_change_filter`
```

#### Associated Analytic Story
* [sAMAccountName Spoofing and Domain Controller Impersonation](/stories/samaccountname_spoofing_and_domain_controller_impersonation)


#### How To Implement
To successfully implement this search, you need to be ingesting Windows event logs from your hosts. In addition, the Splunk Windows TA is needed.

#### Required field
* _time
* EventCode
* ComputerName
* Account_Name
* Old_Account_Name
* New_Account_Name


#### Kill Chain Phase
* Privilege Escalation


#### Known False Positives
Renaming a computer account name to a name that not end with &#39;$&#39; is highly unsual and may not have any legitimate scenarios.


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