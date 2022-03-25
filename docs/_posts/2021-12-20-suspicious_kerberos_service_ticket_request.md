---
title: "Suspicious Kerberos Service Ticket Request"
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

As part of the sAMAccountName Spoofing (CVE-2021-42278) and Domain Controller Impersonation (CVE-2021-42287) exploitation chain, adversaries will request and obtain a Kerberos Service Ticket (TGS) with a domain controller computer account as the Service Name. This Service Ticket can be then used to take control of the domain controller on the final part of the attack. This analytic leverages Event Id 4769, `A Kerberos service ticket was requested`, to identify an unusual TGS request where the Account_Name requesting the ticket matches the Service_Name field. This behavior could represent an exploitation attempt of CVE-2021-42278 and CVE-2021-42287 for privilege escalation.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-12-20
- **Author**: Mauricio Velazco, Splunk
- **ID**: 8b1297bc-6204-11ec-b7c4-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

| [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Domain Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Search

```
 `wineventlog_security` EventCode=4769 
| eval isSuspicious = if(lower(Service_Name) = lower(mvindex(split(Account_Name,"@"),0)+"$"),1,0) 
| where isSuspicious = 1 
| table _time, Client_Address, Account_Name, Service_Name, Failure_Code, isSuspicious 
| `suspicious_kerberos_service_ticket_request_filter`
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)

Note that `suspicious_kerberos_service_ticket_request_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* Service_Name
* Account_Name
* Client_Address
* Failure_Code


#### How To Implement
To successfully implement this search, you need to be ingesting Domain Controller and Kerberos events. The Advanced Security Audit policy setting `Audit Kerberos Authentication Service` within `Account Logon` needs to be enabled.

#### Known False Positives
We have tested this detection logic with ~2 million 4769 events and did not identify false positives. However, they may be possible in certain environments. Filter as needed.

#### Associated Analytic story
* [sAMAccountName Spoofing and Domain Controller Impersonation](/stories/samaccountname_spoofing_and_domain_controller_impersonation)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 60.0 | 100 | 60 | A suspicious Kerberos Service Ticket was requested by $Account_Name$ |


#### CVE

| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2021-42287](https://nvd.nist.gov/vuln/detail/CVE-2021-42287) | Active Directory Domain Services Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-42278, CVE-2021-42282, CVE-2021-42291. | 6.5 |
| [CVE-2021-42278](https://nvd.nist.gov/vuln/detail/CVE-2021-42278) | Active Directory Domain Services Elevation of Privilege Vulnerability This CVE ID is unique from CVE-2021-42282, CVE-2021-42287, CVE-2021-42291. | 6.5 |



#### Reference

* [https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html](https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html)
* [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278)
* [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287)
* [https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.002/samaccountname_spoofing/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.002/samaccountname_spoofing/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/suspicious_kerberos_service_ticket_request.yml) \| *version*: **1**