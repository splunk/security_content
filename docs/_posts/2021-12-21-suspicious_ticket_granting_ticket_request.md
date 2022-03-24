---
title: "Suspicious Ticket Granting Ticket Request"
excerpt: "Valid Accounts
, Domain Accounts
"
categories:
  - Endpoint
last_modified_at: 2021-12-21
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
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

As part of the sAMAccountName Spoofing (CVE-2021-42278) and Domain Controller Impersonation (CVE-2021-42287) exploitation chain, adversaries will need to request a Kerberos Ticket Granting Ticket (TGT) on behalf of the newly created and renamed computer account. The TGT request will be preceded by a computer account name event. This analytic leverages Event Id 4781, `The name of an account was changed` and event Id 4768 `A Kerberos authentication ticket (TGT) was requested` to correlate a sequence of events where the new computer account on event id 4781 matches the request account on event id 4768. This behavior could represent an exploitation attempt of CVE-2021-42278 and CVE-2021-42287 for privilege escalation.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-12-21
- **Author**: Mauricio Velazco, Splunk
- **ID**: d77d349e-6269-11ec-9cfe-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

| [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Domain Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Search

```
 `wineventlog_security` (EventCode=4781 Old_Account_Name="*$" New_Account_Name!="*$") OR (EventCode=4768 Account_Name!="*$") 
| eval RenamedComputerAccount = coalesce(New_Account_Name, mvindex(Account_Name,0)) 
| transaction RenamedComputerAccount startswith=(EventCode=4781) endswith=(EventCode=4768) 
| eval short_lived=case((duration<2),"TRUE") 
| search short_lived = TRUE 
| table _time, ComputerName, EventCode, Account_Name,RenamedComputerAccount, short_lived 
|`suspicious_ticket_granting_ticket_request_filter`
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)

Note that `suspicious_ticket_granting_ticket_request_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* Old_Account_Name
* New_Account_Name
* Account_Name
* ComputerName


#### How To Implement
To successfully implement this search, you need to be ingesting Domain Controller and Kerberos events. The Advanced Security Audit policy setting `Audit Kerberos Authentication Service` within `Account Logon` needs to be enabled.

#### Known False Positives
A computer account name change event inmediately followed by a kerberos TGT request with matching fields is unsual. However, legitimate behavior may trigger it. Filter as needed.

#### Associated Analytic story
* [sAMAccountName Spoofing and Domain Controller Impersonation](/stories/samaccountname_spoofing_and_domain_controller_impersonation)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 60.0 | 100 | 60 | A suspicious TGT was requested was requested |




#### Reference

* [https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html](https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html)
* [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278)
* [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.002/samaccountname_spoofing/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.002/samaccountname_spoofing/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/suspicious_ticket_granting_ticket_request.yml) \| *version*: **1**