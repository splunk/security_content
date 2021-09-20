---
title: "Gsuite Email Suspicious Subject With Attachment"
excerpt: "Spearphishing Attachment"
categories:
  - Cloud
last_modified_at: 2021-08-19
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

This search is to detect a gsuite email contains suspicious subject having known file type used in spear phishing. This technique is a common and effective entry vector of attacker to compromise a network by luring the user to click or execute the suspicious attachment send from external email account because of the effective social engineering of subject related to delivery, bank and so on. On the other hand this detection may catch a normal email traffic related to legitimate transaction so better to check the email sender, spelling and etc. avoid click link or opening the attachment if you are not expecting this type of e-mail.

- **ID**: 8ef3971e-00f2-11ec-b54f-acde48001122
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-08-19
- **Author**: Teoderick Contreras, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Initial Access |


#### Search

```
`gsuite_gmail` num_message_attachments > 0 subject IN ("*dhl*", "* ups *", "*delivery*", "*parcel*", "*label*", "*invoice*", "*postal*", "* fedex *", "* usps *", "* express *", "*shipment*", "*Banking/Tax*","*shipment*", "*new order*") attachment{}.file_extension_type IN ("doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "zip", "rar", "html","htm","hta") 
| rex field=source.from_header_address "[^@]+@(?<source_domain>[^@]+)" 
| rex field=destination{}.address "[^@]+@(?<dest_domain>[^@]+)" 
| where not source_domain="internal_test_email.com" and dest_domain="internal_test_email.com" 
| stats count min(_time) as firstTime max(_time) as lastTime values(attachment{}.file_extension_type) as email_attachments, values(attachment{}.sha256) as attachment_sha256, values(payload_size) as payload_size by destination{}.service num_message_attachments  subject destination{}.address source.address 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `gsuite_email_suspicious_subject_with_attachment_filter`
```

#### Associated Analytic Story
* [DevSecOps](/stories/devsecops)


#### How To Implement
To successfully implement this search, you need to be ingesting logs related to gsuite having the file attachment metadata like file type, file extension, source email, destination email, num of attachment and etc.

#### Required field
* _time


#### Kill Chain Phase
* Exploitation


#### Known False Positives
normal user or normal transaction may contain the subject and file type attachment that this detection try to search.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 25.0 | 50 | 50 |



#### Reference

* [https://www.redhat.com/en/topics/devops/what-is-devsecops](https://www.redhat.com/en/topics/devops/what-is-devsecops)
* [https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-top-spear-phishing-words.pdf](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-top-spear-phishing-words.pdf)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/gsuite_susp_subj/gsuite_susp_subj_attach.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/gsuite_susp_subj/gsuite_susp_subj_attach.log)


_version_: 1