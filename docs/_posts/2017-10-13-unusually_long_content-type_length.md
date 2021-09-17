---
title: "Unusually Long Content-Type Length"
excerpt: ""
categories:
  - Network
last_modified_at: 2017-10-13
toc: true
tags:
  - Anomaly
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Delivery
---

#### Description

This search looks for unusually long strings in the Content-Type http header that the client sends the server.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**:
- **Last Updated**: 2017-10-13
- **Author**: Bhavin Patel, Splunk



#### Search

```
`stream_http` 
| eval cs_content_type_length = len(cs_content_type) 
| where cs_content_type_length > 100 
| table endtime src_ip dest_ip cs_content_type_length cs_content_type url 
| `unusually_long_content_type_length_filter`
```

#### Associated Analytic Story
* [Apache Struts Vulnerability](_stories/apache_struts_vulnerability)


#### How To Implement
This particular search leverages data extracted from Stream:HTTP. You must configure the http stream using the Splunk Stream App on your Splunk Stream deployment server to extract the cs_content_type field.

#### Required field
* _time
* cs_content_type
* endtime
* src_ip
* dest_ip
* url


#### Kill Chain Phase
* Delivery


#### Known False Positives
Very few legitimate Content-Type fields will have a length greater than 100 characters.




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



_version_: 1