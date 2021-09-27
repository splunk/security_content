---
title: "GSuite Email Suspicious Attachment"
excerpt: "Spearphishing Attachment"
categories:
  - Cloud
last_modified_at: 2021-08-16
toc: true
tags:
  - Anomaly
  - T1566.001
  - Spearphishing Attachment
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Dev Sec Ops Analytics
  - Exploitation
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect a suspicious attachment file extension in Gsuite email that may related to spear phishing attack. This file type is commonly used by malware to lure user to click on it to execute malicious code to compromised targetted machine. But this search can also catch some normal files related to this file type that maybe send by employee or network admin.

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud, Dev Sec Ops Analytics
- **Datamodel**: 
- **Last Updated**: 2021-08-16
- **Author**: Teoderick Contreras, Splunk
- **ID**: 6d663014-fe92-11eb-ab07-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Initial Access |


#### Search

```
`gsuite_gmail` "attachment{}.file_extension_type" IN ("pl", "py", "rb", "sh", "bat", "exe", "dll", "cpl", "com", "js", "vbs", "ps1", "reg","swf", "cmd", "go") 
| eval phase="plan" 
| eval severity="medium" 
| stats count min(_time) as firstTime max(_time) as lastTime values(attachment{}.file_extension_type) as email_attachments, values(attachment{}.sha256) as attachment_sha256, values(payload_size) as payload_size by destination{}.service num_message_attachments  subject destination{}.address source.address phase severity 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `gsuite_email_suspicious_attachment_filter`
```

#### Associated Analytic Story
* [DevSecOps](/stories/devsecops)


#### How To Implement
To successfully implement this search, you need to be ingesting logs related to gsuite having the file attachment metadata like file type, file extension, source email, destination email, num of attachment and etc.

#### Required field
* _time
* attachment{}.file_extension_type
* attachment{}.sha256
* destination{}.service
* num_message_attachments
* payload_size
* subject
* destination{}.address
* source.address


#### Kill Chain Phase
* Exploitation


#### Known False Positives
network admin and normal user may send this file attachment as part of their day to day work. having a good protocol in attaching this file type to an e-mail may reduce the risk of having a spear phishing attack.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | suspicious email from $source.address$ to $destination{}.address$ |



#### Reference

* [https://www.redhat.com/en/topics/devops/what-is-devsecops](https://www.redhat.com/en/topics/devops/what-is-devsecops)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/gsuite_susp_attachment_ext/gsuite_gmail_file_ext.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/gsuite_susp_attachment_ext/gsuite_gmail_file_ext.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/gsuite_email_suspicious_attachment.yml) \| *version*: **1**