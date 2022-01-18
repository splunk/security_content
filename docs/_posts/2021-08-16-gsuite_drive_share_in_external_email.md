---
title: "Gsuite Drive Share In External Email"
excerpt: "Exfiltration to Cloud Storage, Exfiltration Over Web Service"
categories:
  - Cloud
last_modified_at: 2021-08-16
toc: true
toc_label: ""
tags:
  - Exfiltration to Cloud Storage
  - Exfiltration
  - Exfiltration Over Web Service
  - Exfiltration
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Dev Sec Ops Analytics
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect suspicious google drive or google docs files shared outside or externally. This behavior might be a good hunting query to monitor exfitration of data made by an attacker or insider to a targetted machine.

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud, Dev Sec Ops Analytics
- **Datamodel**: 
- **Last Updated**: 2021-08-16
- **Author**: Teoderick Contreras, Splunk
- **ID**: f6ee02d6-fea0-11eb-b2c2-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | Exfiltration to Cloud Storage | Exfiltration |

| [T1567](https://attack.mitre.org/techniques/T1567/) | Exfiltration Over Web Service | Exfiltration |

#### Search

```
`gsuite_drive` NOT (email IN("", "null")) 
| rex field=parameters.owner "[^@]+@(?<src_domain>[^@]+)" 
| rex field=email "[^@]+@(?<dest_domain>[^@]+)" 
| where src_domain = "internal_test_email.com" and not dest_domain = "internal_test_email.com" 
| eval phase="plan" 
| eval severity="low" 
| stats values(parameters.doc_title) as doc_title, values(parameters.doc_type) as doc_types, values(email) as dst_email_list, values(parameters.visibility) as visibility, values(parameters.doc_id) as doc_id, count min(_time) as firstTime max(_time) as lastTime by parameters.owner ip_address phase severity  
| rename parameters.owner as user ip_address as src_ip 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `gsuite_drive_share_in_external_email_filter`
```

#### Associated Analytic Story
* [Dev Sec Ops](/stories/dev_sec_ops)


#### How To Implement
To successfully implement this search, you need to be ingesting logs related to gsuite having the file attachment metadata like file type, file extension, source email, destination email, num of attachment and etc. In order for the search to work for your environment, please edit the query to use your company specific email domain instead of `internal_test_email.com`.

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

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 80 | 90 | suspicious share gdrive from $parameters.owner$ to $email$ namely as $parameters.doc_title$ |




#### Reference

* [https://www.redhat.com/en/topics/devops/what-is-devsecops](https://www.redhat.com/en/topics/devops/what-is-devsecops)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1567.002/gsuite_share_drive/gdrive_share_external.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1567.002/gsuite_share_drive/gdrive_share_external.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/gsuite_drive_share_in_external_email.yml) \| *version*: **1**