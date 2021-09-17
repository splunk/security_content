---
title: "Gsuite Suspicious Shared File Name"
excerpt: "Spearphishing Attachment"
categories:
  - Cloud
last_modified_at: 2021-08-23
toc: true
tags:
  - Anomaly
  - T1566.001
  - Spearphishing Attachment
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Exploitation
---

#### Description

This search is to detect a shared file in google drive with suspicious file name that are commonly used by spear phishing campaign. This technique is very popular to lure the user by running a malicious document or click a malicious link within the shared file that will redirected to malicious website. This detection can also catch some normal email communication between organization and its external customer.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **Last Updated**: 2021-08-23
- **Author**: Teoderick Contreras, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Initial Access |


#### Search

```
`gsuite_drive` parameters.owner_is_team_drive=false "parameters.doc_title" IN ("*dhl*", "* ups *", "*delivery*", "*parcel*", "*label*", "*invoice*", "*postal*", "*fedex*", "* usps *", "* express *", "*shipment*", "*Banking/Tax*","*shipment*", "*new order*") parameters.doc_type IN ("document","pdf", "msexcel", "msword", "spreadsheet", "presentation") 
| rex field=parameters.owner "[^@]+@(?<source_domain>[^@]+)" 
| rex field=parameters.target_user "[^@]+@(?<dest_domain>[^@]+)" 
| where not source_domain="internal_test_email.com" and dest_domain="internal_test_email.com" 
| stats count min(_time) as firstTime max(_time) as lastTime by email parameters.owner parameters.target_user parameters.doc_title parameters.doc_type 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `gsuite_suspicious_shared_file_name_filter`
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
* Exploitation


#### Known False Positives
normal user or normal transaction may contain the subject and file type attachment that this detection try to search



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 9.0 | 30 | 30 |



#### Reference

* [https://www.redhat.com/en/topics/devops/what-is-devsecops](https://www.redhat.com/en/topics/devops/what-is-devsecops)
* [https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-top-spear-phishing-words.pdf](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-top-spear-phishing-words.pdf)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/gdrive_susp_file_share/gdrive_susp_attach.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/gdrive_susp_file_share/gdrive_susp_attach.log)


_version_: 1