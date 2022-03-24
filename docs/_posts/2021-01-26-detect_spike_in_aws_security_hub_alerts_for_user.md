---
title: "Detect Spike in AWS Security Hub Alerts for User"
excerpt: ""
categories:
  - Cloud
last_modified_at: 2021-01-26
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for a spike in number of of AWS security Hub alerts for an AWS IAM User in 4 hours intervals.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2021-01-26
- **Author**: Bhavin Patel, Splunk
- **ID**: 2a9b80d3-6220-4345-b5ad-290bf5d0d222

#### Search

```
`aws_securityhub_finding` "findings{}.Resources{}.Type"= AwsIamUser 
| rename findings{}.Resources{}.Id as user 
| bucket span=4h _time 
| stats count AS alerts by _time user 
| eventstats avg(alerts) as total_launched_avg, stdev(alerts) as total_launched_stdev 
| eval threshold_value = 2 
| eval isOutlier=if(alerts > total_launched_avg+(total_launched_stdev * threshold_value), 1, 0) 
| search isOutlier=1 
| table _time user alerts 
|`detect_spike_in_aws_security_hub_alerts_for_user_filter`
```

#### Macros
The SPL above uses the following Macros:
* [aws_securityhub_finding](https://github.com/splunk/security_content/blob/develop/macros/aws_securityhub_finding.yml)

Note that `detect_spike_in_aws_security_hub_alerts_for_user_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* findings{}.Resources{}.Type
* indings{}.Resources{}.Id
* user


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your Security Hub inputs. The threshold_value should be tuned to your environment and schedule these searches according to the bucket span interval.

#### Known False Positives
None

#### Associated Analytic story
* [AWS Security Hub Alerts](/stories/aws_security_hub_alerts)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/cloud/detect_spike_in_aws_security_hub_alerts_for_user.yml) \| *version*: **3**