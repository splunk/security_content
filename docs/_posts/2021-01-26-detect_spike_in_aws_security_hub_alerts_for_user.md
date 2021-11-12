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

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate or build datasets for it, use at your own risk!


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for a spike in number of of AWS security Hub alerts for an AWS IAM User in 4 hours intervals.

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
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

#### Associated Analytic Story
* [AWS Security Hub Alerts](/stories/aws_security_hub_alerts)


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your Security Hub inputs. The threshold_value should be tuned to your environment and schedule these searches according to the bucket span interval.

#### Required field
* _time
* findings{}.Resources{}.Type
* indings{}.Resources{}.Id
* user


#### Kill Chain Phase


#### Known False Positives
None





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/cloud/detect_spike_in_aws_security_hub_alerts_for_user.yml) \| *version*: **3**