---
title: "Gsuite Drive Share In External Email"
excerpt: "Exfiltration to Cloud Storage"
categories:
  - Cloud
last_modified_at: 2021-08-16
toc: true
tags:
  - Anomaly
  - T1567.002
  - Exfiltration to Cloud Storage
  - Exfiltration
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Exfiltration
---



#### Description

This search is to detect suspicious google drive or google docs files shared outside or externally. This behavior might be a good hunting query to monitor exfitration of data made by an attacker or insider to a targetted machine.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-08-16
- **Author**: Teoderick Contreras, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | Exfiltration to Cloud Storage | Exfiltration |


#### Search

```
`gsuite_drive` NOT (email IN("", "null")) 
| rex field=parameters.owner "[^@]+@(?<src_domain>[^@]+)" 
| rex field=email "[^@]+@(?<dest_domain>[^@]+)" 
| where src_domain = "internal_test_email.com" and not dest_domain = "internal_test_email.com" 
| stats values(parameters.doc_title) as doc_title, values(parameters.doc_type) as doc_types, values(email) as dst_email_list, values(parameters.visibility) as visibility, count min(_time) as firstTime max(_time) as lastTime by parameters.owner 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `gsuite_drive_share_in_external_email_filter`
```

#### Associated Analytic Story
* [DevSecOps](_stories/devsecops)


#### How To Implement
To successfully implement this search, you need to be ingesting logs related to gsuite having the file attachment metadata like file type, file extension, source email, destination email, num of attachment and etc.

#### Required field
* _time
* parameters.doc_title
* src_domain
* dest_domain
* email
* parameters.visibility
* parameters.owner
* parameters.doc_type


#### Kill Chain Phase
* Exfiltration


#### Known False Positives
network admin or normal user may share files to customer and external team.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 9.0 | 30 | 30 |



#### Reference

* [https://www.redhat.com/en/topics/devops/what-is-devsecops](https://www.redhat.com/en/topics/devops/what-is-devsecops)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1567.002/gsuite_share_drive/gdrive_share_external.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1567.002/gsuite_share_drive/gdrive_share_external.log)


_version_: 1