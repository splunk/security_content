---
title: "EC2 Instance Started With Previously Unseen Instance Type"
excerpt: ""
categories:
  - Deprecated
last_modified_at: 2020-02-07
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for EC2 instances being created with previously unseen instance types.  This search is deprecated and have been translated to use the latest Change Datamodel.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2020-02-07
- **Author**: David Dorsey, Splunk
- **ID**: 65541c80-03c7-4e05-83c8-1dcd57a2e1ad

#### Search

```
`cloudtrail` eventName=RunInstances [search `cloudtrail` eventName=RunInstances errorCode=success 
| fillnull value="m1.small" requestParameters.instanceType 
| stats earliest(_time) as earliest latest(_time) as latest by requestParameters.instanceType 
| rename requestParameters.instanceType as instanceType 
| inputlookup append=t previously_seen_ec2_instance_types.csv 
| stats min(earliest) as earliest max(latest) as latest by instanceType 
| outputlookup previously_seen_ec2_instance_types.csv 
| eval newType=if(earliest >= relative_time(now(), "-70m@m"), 1, 0) 
| `security_content_ctime(earliest)` 
| `security_content_ctime(latest)` 
| where newType=1 
| rename instanceType as requestParameters.instanceType 
| table requestParameters.instanceType] 
| spath output=user userIdentity.arn 
| rename requestParameters.instanceType as instanceType, responseElements.instancesSet.items{}.instanceId as dest 
| table _time, user, dest, instanceType 
| `ec2_instance_started_with_previously_unseen_instance_type_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)

Note that `ec2_instance_started_with_previously_unseen_instance_type_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* errorCode
* requestParameters.instanceType


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your AWS CloudTrail inputs. This search works best when you run the "Previously Seen EC2 Instance Types" support search once to create a history of previously seen instance types.

#### Known False Positives
It is possible that an admin will create a new system using a new instance type never used before. Verify with the creator that they intended to create the system with the new instance type.

#### Associated Analytic story
* [AWS Cryptomining](/stories/aws_cryptomining)


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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/ec2_instance_started_with_previously_unseen_instance_type.yml) \| *version*: **2**