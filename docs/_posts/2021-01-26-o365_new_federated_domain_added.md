---
title: "O365 New Federated Domain Added"
excerpt: "Cloud Account"
categories:
  - Cloud
last_modified_at: 2021-01-26
toc: true
tags:
  - TTP
  - T1136.003
  - Cloud Account
  - Persistence
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Actions on Objective
---

#### Description

This search detects the addition of a new Federated domain.

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **Last Updated**: 2021-01-26
- **Author**: Rod Soto, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|| [T1136.003](https://attack.mitre.org/techniques/T1136/003/) | Cloud Account | Persistence |


#### Search

```
`o365_management_activity` Workload=Exchange Operation="Add-FederatedDomain" 
| stats count min(_time) as firstTime max(_time) as lastTime values(Parameters{}.Value) as Parameters.Value by ObjectId Operation OrganizationName OriginatingServer UserId UserKey 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `o365_new_federated_domain_added_filter`
```

#### Associated Analytic Story
* [Office 365 Detections](_stories/office_365_detections)
* [Cloud Federated Credential Abuse](_stories/cloud_federated_credential_abuse)


#### How To Implement
You must install splunk Microsoft Office 365 add-on. This search works with o365:management:activity.

#### Required field
* _time
* Workload
* Operation
* Parameters{}.Value
* ObjectId
* OrganizationName
* OriginatingServer
* UserId
* UserKey


#### Kill Chain Phase
* Actions on Objective


#### Known False Positives
The creation of a new Federated domain is not necessarily malicious, however these events need to be followed closely, as it may indicate federated credential abuse or backdoor via federated identities at a similar or different cloud provider.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 64.0 | 80 | 80 |



#### Reference

* [https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf)
* [https://us-cert.cisa.gov/ncas/alerts/aa21-008a](https://us-cert.cisa.gov/ncas/alerts/aa21-008a)
* [https://www.splunk.com/en_us/blog/security/a-golden-saml-journey-solarwinds-continued.html](https://www.splunk.com/en_us/blog/security/a-golden-saml-journey-solarwinds-continued.html)
* [https://www.sygnia.co/golden-saml-advisory](https://www.sygnia.co/golden-saml-advisory)
* [https://o365blog.com/post/aadbackdoor/](https://o365blog.com/post/aadbackdoor/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.003/o365_new_federated_domain/o365_new_federated_domain.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.003/o365_new_federated_domain/o365_new_federated_domain.json)


_version_: 1