---
title: "O365 Suspicious Rights Delegation"
excerpt: "Remote Email Collection, Email Collection"
categories:
  - Cloud
last_modified_at: 2020-12-15
toc: true
toc_label: ""
tags:
  - Remote Email Collection
  - Collection
  - Email Collection
  - Collection
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search detects the assignment of rights to accesss content from another mailbox. This is usually only assigned to a service account.

- **Type**: TTP
- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-12-15
- **Author**: Patrick Bareiss, Splunk
- **ID**: b25d2973-303e-47c8-bacd-52b61604c6a7


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1114.002](https://attack.mitre.org/techniques/T1114/002/) | Remote Email Collection | Collection |

| [T1114](https://attack.mitre.org/techniques/T1114/) | Email Collection | Collection |

#### Search

```
`o365_management_activity` Operation=Add-MailboxPermission 
| spath input=Parameters 
| rename User AS src_user, Identity AS dest_user 
| search AccessRights=FullAccess OR AccessRights=SendAs OR AccessRights=SendOnBehalf 
| stats count earliest(_time) as firstTime latest(_time) as lastTime by user src_user dest_user Operation AccessRights 
|`security_content_ctime(firstTime)` 
|`security_content_ctime(lastTime)` 
|`o365_suspicious_rights_delegation_filter`
```

#### Associated Analytic Story
* [Office 365 Detections](/stories/office_365_detections)


#### How To Implement
You must install splunk Microsoft Office 365 add-on. This search works with o365:management:activity

#### Required field
* _time
* Operation
* Parameters


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Service Accounts


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 48.0 | 80 | 60 | User $user$ has delegated suspicious rights $AccessRights$ to user $dest_user$ that allow access to sensitive |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114.002/suspicious_rights_delegation/suspicious_rights_delegation.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114.002/suspicious_rights_delegation/suspicious_rights_delegation.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/o365_suspicious_rights_delegation.yml) \| *version*: **1**