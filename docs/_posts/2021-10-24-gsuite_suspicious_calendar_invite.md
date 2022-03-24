---
title: "Gsuite suspicious calendar invite"
excerpt: "Phishing
"
categories:
  - Cloud
last_modified_at: 2021-10-24
toc: true
toc_label: ""
tags:
  - Phishing
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search can help the detection of compromised accounts or internal users sending suspcious calendar invites via GSuite calendar. These invites may contain malicious links or attachments.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2021-10-24
- **Author**: Rod Soto, Teoderick Contreras
- **ID**: 03cdd68a-34fb-11ec-9bd3-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing | Initial Access |

#### Search

```
`gsuite_calendar` 
|bin span=5m _time 
|rename parameters.* as * 
|search target_calendar_id!=null email="*yourdomain.com"
| stats  count values(target_calendar_id) values(event_title) values(event_guest) by email _time 
| where count >100
| `gsuite_suspicious_calendar_invite_filter`
```

#### Macros
The SPL above uses the following Macros:
* [gsuite_calendar](https://github.com/splunk/security_content/blob/develop/macros/gsuite_calendar.yml)

Note that `gsuite_suspicious_calendar_invite_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* email
* parameters.event_title
* parameters.target_calendar_id
* parameters.event_title


#### How To Implement
In order to successfully implement this search, you need to be ingesting logs related to gsuite (gsuite:calendar:json) having the file sharing metadata like file type, source owner, destination target user, description, etc. This search can also be made more specific by selecting specific emails, subdomains timeframe, organizational units, targeted user, etc. In order for the search to work for your environment please update `yourdomain.com` value in the query with the domain relavant for your organization.

#### Known False Positives
This search will also produce normal activity statistics. Fields such as email, ip address, name, parameters.organizer_calendar_id, parameters.target_calendar_id and parameters.event_title may give away phishing intent.For more specific results use email parameter.

#### Associated Analytic story
* [Spearphishing Attachments](/stories/spearphishing_attachments)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference

* [https://www.techrepublic.com/article/how-to-avoid-the-dreaded-google-calendar-malicious-invite-issue/](https://www.techrepublic.com/article/how-to-avoid-the-dreaded-google-calendar-malicious-invite-issue/)
* [https://gcn.com/articles/2012/09/26/20-most-common-words-phishing-attacks.aspx](https://gcn.com/articles/2012/09/26/20-most-common-words-phishing-attacks.aspx)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [[]]([])



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/cloud/gsuite_suspicious_calendar_invite.yml) \| *version*: **1**