---
title: "Detect S3 access from a new IP"
excerpt: "Data from Cloud Storage Object"
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

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks at S3 bucket-access logs and detects new or previously unseen remote IP addresses that have successfully accessed an S3 bucket.

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2018-06-28
- **Author**: Bhavin Patel, Splunk
- **ID**: 2a9b80d3-6340-4345-b5ad-291bq3d0daq4


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
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

#### Associated Analytic Story
* [Suspicious AWS S3 Activities](/stories/suspicious_aws_s3_activities)


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your S3 access logs&#39; inputs. This search works best when you run the &#34;Previously Seen S3 Bucket Access by Remote IP&#34; support search once to create a history of previously seen remote IPs and bucket names.

#### Required field
* _time
* http_status
* bucket_name
* remote_ip


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
S3 buckets can be accessed from any IP, as long as it can make a successful connection. This will be a false postive, since the search is looking for a new IP within the past hour





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/cloud/detect_s3_access_from_a_new_ip.yml) \| *version*: **1**