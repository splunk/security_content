---
title: "Unusually Long Content-Type Length"
excerpt: ""
categories:
  - Network
last_modified_at: 2017-10-13
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for unusually long strings in the Content-Type http header that the client sends the server.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2017-10-13
- **Author**: Bhavin Patel, Splunk
- **ID**: 57a0a2bf-353f-40c1-84dc-29293f3c35b7

#### Search

```
`stream_http` 
| eval cs_content_type_length = len(cs_content_type) 
| where cs_content_type_length > 100 
| table endtime src_ip dest_ip cs_content_type_length cs_content_type url 
| `unusually_long_content_type_length_filter`
```

#### Macros
The SPL above uses the following Macros:
* [stream_http](https://github.com/splunk/security_content/blob/develop/macros/stream_http.yml)

Note that `unusually_long_content-type_length_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* cs_content_type
* endtime
* src_ip
* dest_ip
* url


#### How To Implement
This particular search leverages data extracted from Stream:HTTP. You must configure the http stream using the Splunk Stream App on your Splunk Stream deployment server to extract the cs_content_type field.

#### Known False Positives
Very few legitimate Content-Type fields will have a length greater than 100 characters.

#### Associated Analytic story
* [Apache Struts Vulnerability](/stories/apache_struts_vulnerability)


#### Kill Chain Phase
* Delivery






#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/unusually_long_content-type_length.yml) \| *version*: **1**