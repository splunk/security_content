---
title: "Detect S3 access from a new IP"
excerpt: "Data from Cloud Storage Object
"
categories:
  - Cloud
last_modified_at: 2018-06-28
toc: true
toc_label: ""
tags:
  - Data from Cloud Storage Object
  - Collection
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks at S3 bucket-access logs and detects new or previously unseen remote IP addresses that have successfully accessed an S3 bucket.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2018-06-28
- **Author**: Bhavin Patel, Splunk
- **ID**: e6f1bb1b-f441-492b-9126-902acda217da


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage Object | Collection |

#### Search

```
`aws_s3_accesslogs` http_status=200  [search `aws_s3_accesslogs` http_status=200 
| stats earliest(_time) as firstTime latest(_time) as lastTime by bucket_name remote_ip 
| inputlookup append=t previously_seen_S3_access_from_remote_ip.csv 
| stats min(firstTime) as firstTime, max(lastTime) as lastTime by bucket_name remote_ip 
| outputlookup previously_seen_S3_access_from_remote_ip.csv 
| eval newIP=if(firstTime >= relative_time(now(), "-70m@m"), 1, 0) 
| where newIP=1 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| table bucket_name remote_ip]
| iplocation remote_ip 
|rename remote_ip as src_ip 
| table _time bucket_name src_ip City Country operation request_uri 
| `detect_s3_access_from_a_new_ip_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [aws_s3_accesslogs](https://github.com/splunk/security_content/blob/develop/macros/aws_s3_accesslogs.yml)

Note that `detect_s3_access_from_a_new_ip_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* http_status
* bucket_name
* remote_ip


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your S3 access logs' inputs. This search works best when you run the "Previously Seen S3 Bucket Access by Remote IP" support search once to create a history of previously seen remote IPs and bucket names.

#### Known False Positives
S3 buckets can be accessed from any IP, as long as it can make a successful connection. This will be a false postive, since the search is looking for a new IP within the past hour

#### Associated Analytic story
* [Suspicious AWS S3 Activities](/stories/suspicious_aws_s3_activities)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/cloud/detect_s3_access_from_a_new_ip.yml) \| *version*: **1**