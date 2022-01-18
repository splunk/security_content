---
title: "Suspicious Email Attachment Extensions"
excerpt: "Spearphishing Attachment, Phishing"
categories:
  - Application
last_modified_at: 2020-07-22
toc: true
toc_label: ""
tags:
  - Spearphishing Attachment
  - Initial Access
  - Phishing
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Email
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for emails that have attachments with suspicious file extensions.

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Email](https://docs.splunk.com/Documentation/CIM/latest/User/Email)
- **Last Updated**: 2020-07-22
- **Author**: David Dorsey, Splunk
- **ID**: 473bd65f-06ca-4dfe-a2b8-ba04ab4a0084


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Initial Access |

| [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing | Initial Access |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Email where All_Email.file_name="*" by All_Email.src_user, All_Email.file_name All_Email.message_id 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `drop_dm_object_name("All_Email")` 
| `suspicious_email_attachments` 
| `suspicious_email_attachment_extensions_filter` 
```

#### Associated Analytic Story
* [Emotet Malware  DHS Report TA18-201A ](/stories/emotet_malware__dhs_report_ta18-201a_)
* [Suspicious Emails](/stories/suspicious_emails)


#### How To Implement
You need to ingest data from emails. Specifically, the sender&#39;s address and the file names of any attachments must be mapped to the Email data model. \
 **Splunk Phantom Playbook Integration**\
If Splunk Phantom is also configured in your environment, a Playbook called &#34;Suspicious Email Attachment Investigate and Delete&#34; can be configured to run when any results are found by this detection search. To use this integration, install the Phantom App for Splunk `https://splunkbase.splunk.com/app/3411/`, and add the correct hostname to the &#34;Phantom Instance&#34; field in the Adaptive Response Actions when configuring this detection search. The notable event will be sent to Phantom and the playbook will gather further information about the file attachment and its network behaviors. If Phantom finds malicious behavior and an analyst approves of the results, the email will be deleted from the user&#39;s inbox.

#### Required field
* _time
* All_Email.file_name
* All_Email.src_user
* All_Email.message_id


#### Kill Chain Phase
* Delivery


#### Known False Positives
None identified





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/application/suspicious_email_attachment_extensions.yml) \| *version*: **3**