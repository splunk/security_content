---
title: "Gsuite Email With Known Abuse Web Service Link"
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



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytics is to detect a gmail containing a link that are known to be abused by malware or attacker like pastebin, telegram and discord to deliver malicious payload. This event can encounter some normal email traffic within organization and external email that normally using this application and services.

- **ID**: 8630aa22-042b-11ec-af39-acde48001122
- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-08-23
- **Author**: Teoderick Contreras, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Initial Access |


#### Search

```
`gsuite_gmail` "link_domain{}" IN ("*pastebin.com*", "*discord*", "*telegram*","t.me") 
| rex field=source.from_header_address "[^@]+@(?<source_domain>[^@]+)" 
| rex field=destination{}.address "[^@]+@(?<dest_domain>[^@]+)" 
| where not source_domain="internal_test_email.com" and dest_domain="internal_test_email.com" 
|stats values(link_domain{}) as link_domains min(_time) as firstTime max(_time) as lastTime count by is_spam source.address source.from_header_address subject destination{}.address 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `gsuite_email_with_known_abuse_web_service_link_filter`
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
normal email contains this link that are known application within the organization or network can be catched by this detection.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | suspicious email from $source.address$ to $destination{}.address$ |



#### Reference

* [https://news.sophos.com/en-us/2021/07/22/malware-increasingly-targets-discord-for-abuse/](https://news.sophos.com/en-us/2021/07/22/malware-increasingly-targets-discord-for-abuse/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/gsuite_susp_url/gsuite_susp_url.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/gsuite_susp_url/gsuite_susp_url.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/gsuite_email_with_known_abuse_web_service_link.yml) \| *version*: **1**