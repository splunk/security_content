---
title: "Monitor Email For Brand Abuse"
excerpt: ""
categories:
  - Application
last_modified_at: 2018-01-05
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Email
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate or build datasets for it, use at your own risk!


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for emails claiming to be sent from a domain similar to one that you want to have monitored for abuse.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Email](https://docs.splunk.com/Documentation/CIM/latest/User/Email)
- **Last Updated**: 2018-01-05
- **Author**: David Dorsey, Splunk
- **ID**: b2ea1f38-3a3e-4b8a-9cf1-82760d86a6b8

#### Search

```

| tstats `security_content_summariesonly` values(All_Email.recipient) as recipients, min(_time) as firstTime, max(_time) as lastTime from datamodel=Email by All_Email.src_user, All_Email.message_id 
| `drop_dm_object_name("All_Email")` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| eval temp=split(src_user, "@") 
| eval email_domain=mvindex(temp, 1) 
| lookup update=true brandMonitoring_lookup domain as email_domain OUTPUT domain_abuse 
| search domain_abuse=true 
| table message_id, src_user, email_domain, recipients, firstTime, lastTime 
| `monitor_email_for_brand_abuse_filter`
```

#### Associated Analytic Story
* [Brand Monitoring](/stories/brand_monitoring)
* [Suspicious Emails](/stories/suspicious_emails)


#### How To Implement
You need to ingest email header data. Specifically the sender&#39;s address (src_user) must be populated.  You also need to have run the search &#34;ESCU - DNSTwist Domain Names&#34;, which creates the permutations of the domain that will be checked for.

#### Required field
* _time
* All_Email.recipient
* All_Email.src_user
* All_Email.message_id


#### Kill Chain Phase
* Delivery


#### Known False Positives
None at this time





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/application/monitor_email_for_brand_abuse.yml) \| *version*: **2**