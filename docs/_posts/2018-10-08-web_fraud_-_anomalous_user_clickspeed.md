---
title: "Web Fraud - Anomalous User Clickspeed"
excerpt: "Valid Accounts
"
categories:
  - Deprecated
last_modified_at: 2018-10-08
toc: true
toc_label: ""
tags:
  - Valid Accounts
  - Defense Evasion
  - Initial Access
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search is used to examine web sessions to identify those where the clicks are occurring too quickly for a human or are occurring with a near-perfect cadence (high periodicity or low standard deviation), resembling a script driven session.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2018-10-08
- **Author**: Jim Apger, Splunk
- **ID**: 31337bbb-bc22-4752-b599-ef192df2dc7a


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation |

#### Search

```
`stream_http` http_content_type=text* 
| rex field=cookie "form_key=(?<session_id>\w+)" 
| streamstats window=2 current=1 range(_time) as TimeDelta by session_id 
| where TimeDelta>0 
|stats count stdev(TimeDelta) as ClickSpeedStdDev avg(TimeDelta) as ClickSpeedAvg by session_id 
| where count>5 AND (ClickSpeedStdDev<.5 OR ClickSpeedAvg<.5) 
| `web_fraud___anomalous_user_clickspeed_filter`
```

#### Macros
The SPL above uses the following Macros:
* [stream_http](https://github.com/splunk/security_content/blob/develop/macros/stream_http.yml)

Note that `web_fraud_-_anomalous_user_clickspeed_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* http_content_type
* cookie


#### How To Implement
Start with a dataset that allows you to see clickstream data for each user click on the website. That data must have a time stamp and must contain a reference to the session identifier being used by the website. This ties the clicks together into clickstreams. This value is usually found in the http cookie. With a bit of tuning, a version of this search could be used in high-volume scenarios, such as scraping, crawling, application DDOS, credit-card testing, account takeover, etc. Common data sources used for this detection are customized Apache logs, customized IIS, and Splunk Stream.

#### Known False Positives
As is common with many fraud-related searches, we are usually looking to attribute risk or synthesize relevant context with loosly written detections that simply detect anamoluous behavior.

#### Associated Analytic story
* [Web Fraud Detection](/stories/web_fraud_detection)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference

* [https://en.wikipedia.org/wiki/Session_ID](https://en.wikipedia.org/wiki/Session_ID)
* [https://en.wikipedia.org/wiki/Session_(computer_science)](https://en.wikipedia.org/wiki/Session_(computer_science))
* [https://en.wikipedia.org/wiki/HTTP_cookie](https://en.wikipedia.org/wiki/HTTP_cookie)
* [https://splunkbase.splunk.com/app/1809/](https://splunkbase.splunk.com/app/1809/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/web_fraud_-_anomalous_user_clickspeed.yml) \| *version*: **1**