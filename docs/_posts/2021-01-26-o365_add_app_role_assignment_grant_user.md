---
title: "O365 Add App Role Assignment Grant User"
excerpt: "Cloud Account, Create Account"
categories:
  - Cloud
last_modified_at: 2021-01-26
toc: true
toc_label: ""
tags:
  - Cloud Account
  - Persistence
  - Create Account
  - Persistence
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search detects the creation of a new Federation setting by alerting about an specific event related to its creation.

- **Type**: TTP
- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-01-26
- **Author**: Rod Soto, Splunk
- **ID**: b2c81cc6-6040-11eb-ae93-0242ac130002


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1136.003](https://attack.mitre.org/techniques/T1136/003/) | Cloud Account | Persistence |

| [T1136](https://attack.mitre.org/techniques/T1136/) | Create Account | Persistence |

#### Search

```
`o365_management_activity` Workload=AzureActiveDirectory Operation="Add app role assignment grant to user." 
| stats count min(_time) as firstTime max(_time) as lastTime values(Actor{}.ID) as Actor.ID values(Actor{}.Type) as Actor.Type by ActorIpAddress dest ResultStatus 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `o365_add_app_role_assignment_grant_user_filter`
```

#### Associated Analytic Story
* [Office 365 Detections](/stories/office_365_detections)
* [Cloud Federated Credential Abuse](/stories/cloud_federated_credential_abuse)


#### How To Implement
You must install splunk Microsoft Office 365 add-on. This search works with o365:management:activity

#### Required field
* _time
* Workload
* Operation
* Actor{}.ID
* Actor{}.Type
* ActorIpAddress
* dest
* ResultStatus


#### Kill Chain Phase
* Actions on Objective


#### Known False Positives
The creation of a new Federation is not necessarily malicious, however this events need to be followed closely, as it may indicate federated credential abuse or backdoor via federated identities at a different cloud provider.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 18.0 | 30 | 60 | User $Actor.ID$ has created a new federation setting on $dest$ from IP Address $ActorIpAddress$ |




#### Reference

* [https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf)
* [https://us-cert.cisa.gov/ncas/alerts/aa21-008a](https://us-cert.cisa.gov/ncas/alerts/aa21-008a)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.003/o365_new_federation/o365_new_federation.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.003/o365_new_federation/o365_new_federation.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/o365_add_app_role_assignment_grant_user.yml) \| *version*: **1**