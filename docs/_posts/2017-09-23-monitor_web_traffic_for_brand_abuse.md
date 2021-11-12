---
title: "Monitor Web Traffic For Brand Abuse"
excerpt: ""
categories:
  - Web
last_modified_at: 2017-09-23
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Web
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate or build datasets for it, use at your own risk!


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for Web requests to faux domains similar to the one that you want to have monitored for abuse.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2017-09-23
- **Author**: David Dorsey, Splunk
- **ID**: 134da869-e264-4a8f-8d7e-fcd0ec88f301

#### Search

```

| tstats `security_content_summariesonly` values(Web.url) as urls min(_time) as firstTime from datamodel=Web by Web.src 
| `drop_dm_object_name("Web")` 
| `security_content_ctime(firstTime)` 
| `brand_abuse_web` 
| `monitor_web_traffic_for_brand_abuse_filter`
```

#### Associated Analytic Story
* [Brand Monitoring](/stories/brand_monitoring)


#### How To Implement
You need to ingest data from your web traffic. This can be accomplished by indexing data from a web proxy, or using a network traffic analysis tool, such as Bro or Splunk Stream. You also need to have run the search &#34;ESCU - DNSTwist Domain Names&#34;, which creates the permutations of the domain that will be checked for.

#### Required field
* _time
* Web.url
* Web.src


#### Kill Chain Phase
* Delivery


#### Known False Positives
None at this time





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/web/monitor_web_traffic_for_brand_abuse.yml) \| *version*: **1**