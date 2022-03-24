---
title: "Gsuite Suspicious Shared File Name"
excerpt: "Spearphishing Attachment
, Phishing
"
categories:
  - Cloud
last_modified_at: 2021-08-23
toc: true
toc_label: ""
tags:
  - Spearphishing Attachment
  - Phishing
  - Initial Access
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect a shared file in google drive with suspicious file name that are commonly used by spear phishing campaign. This technique is very popular to lure the user by running a malicious document or click a malicious link within the shared file that will redirected to malicious website. This detection can also catch some normal email communication between organization and its external customer.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2021-08-23
- **Author**: Teoderick Contreras, Splunk
- **ID**: 07eed200-03f5-11ec-98fb-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Initial Access |

| [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing | Initial Access |

#### Search

```
`gsuite_drive` parameters.owner_is_team_drive=false "parameters.doc_title" IN ("*dhl*", "* ups *", "*delivery*", "*parcel*", "*label*", "*invoice*", "*postal*", "*fedex*", "* usps *", "* express *", "*shipment*", "*Banking/Tax*","*shipment*", "*new order*") parameters.doc_type IN ("document","pdf", "msexcel", "msword", "spreadsheet", "presentation") 
| rex field=parameters.owner "[^@]+@(?<source_domain>[^@]+)" 
| rex field=parameters.target_user "[^@]+@(?<dest_domain>[^@]+)" 
| where not source_domain="internal_test_email.com" and dest_domain="internal_test_email.com" 
| eval phase="plan" 
| eval severity="low" 
| stats count min(_time) as firstTime max(_time) as lastTime by email parameters.owner parameters.target_user parameters.doc_title parameters.doc_type phase severity 
| rename parameters.target_user AS user 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `gsuite_suspicious_shared_file_name_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [gsuite_drive](https://github.com/splunk/security_content/blob/develop/macros/gsuite_drive.yml)

Note that `gsuite_suspicious_shared_file_name_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* parameters.doc_title
* src_domain
* dest_domain
* email
* parameters.visibility
* parameters.owner
* parameters.doc_type


#### How To Implement
To successfully implement this search, you need to be ingesting logs related to gsuite having the file attachment metadata like file type, file extension, source email, destination email, num of attachment and etc. In order for the search to work for your environment, please edit the query to use your company specific email domain instead of `internal_test_email.com`.

#### Known False Positives
normal user or normal transaction may contain the subject and file type attachment that this detection try to search

#### Associated Analytic story
* [Dev Sec Ops](/stories/dev_sec_ops)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 21.0 | 30 | 70 | suspicious share gdrive from $parameters.owner$ to $email$ namely as $parameters.doc_title$ |




#### Reference

* [https://www.redhat.com/en/topics/devops/what-is-devsecops](https://www.redhat.com/en/topics/devops/what-is-devsecops)
* [https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-top-spear-phishing-words.pdf](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-top-spear-phishing-words.pdf)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/gdrive_susp_file_share/gdrive_susp_attach.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/gdrive_susp_file_share/gdrive_susp_attach.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/gsuite_suspicious_shared_file_name.yml) \| *version*: **1**