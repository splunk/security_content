---
title: "O365 Added Service Principal"
excerpt: "Cloud Account
, Create Account
"
categories:
  - Cloud
last_modified_at: 2022-02-03
toc: true
toc_label: ""
tags:
  - Cloud Account
  - Create Account
  - Persistence
  - Persistence
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search detects the creation of a new Federation setting by alerting about an specific event related to its creation.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2022-02-03
- **Author**: Rod Soto, Splunk
- **ID**: 1668812a-6047-11eb-ae93-0242ac130002


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1136.003](https://attack.mitre.org/techniques/T1136/003/) | Cloud Account | Persistence |

| [T1136](https://attack.mitre.org/techniques/T1136/) | Create Account | Persistence |

#### Search

```
`o365_management_activity` Workload=AzureActiveDirectory Operation="Add service principal credentials." 
| stats min(_time) as firstTime max(_time) as lastTime values(Actor{}.ID) as Actor.ID values(ModifiedProperties{}.Name) as ModifiedProperties.Name values(ModifiedProperties{}.NewValue) as ModifiedProperties.NewValue values(Target{}.ID) as Target.ID by ActorIpAddress Operation 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `o365_added_service_principal_filter`
```

#### Macros
The SPL above uses the following Macros:
* [o365_management_activity](https://github.com/splunk/security_content/blob/develop/macros/o365_management_activity.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `o365_added_service_principal_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Workload
* signature
* Actor{}.ID
* ModifiedProperties{}.Name
* ModifiedProperties{}.NewValue
* Target{}.ID
* ActorIpAddress


#### How To Implement
You must install splunk Microsoft Office 365 add-on. This search works with o365:management:activity

#### Known False Positives
The creation of a new Federation is not necessarily malicious, however these events need to be followed closely, as it may indicate federated credential abuse or backdoor via federated identities at a different cloud provider.

#### Associated Analytic story
* [Office 365 Detections](/stories/office_365_detections)
* [Cloud Federated Credential Abuse](/stories/cloud_federated_credential_abuse)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 42.0 | 70 | 60 | User $Actor.ID$ created a new federation setting on $Target.ID$ and added service principal credentials from IP Address $ActorIpAddress$ |




#### Reference

* [https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf)
* [https://us-cert.cisa.gov/ncas/alerts/aa21-008a](https://us-cert.cisa.gov/ncas/alerts/aa21-008a)
* [https://www.splunk.com/en_us/blog/security/a-golden-saml-journey-solarwinds-continued.html](https://www.splunk.com/en_us/blog/security/a-golden-saml-journey-solarwinds-continued.html)
* [https://www.sygnia.co/golden-saml-advisory](https://www.sygnia.co/golden-saml-advisory)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.003/o365_add_service_principal/o365_add_service_principal.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.003/o365_add_service_principal/o365_add_service_principal.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/o365_added_service_principal.yml) \| *version*: **1**