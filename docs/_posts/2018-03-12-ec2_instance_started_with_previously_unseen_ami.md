---
title: "EC2 Instance Started With Previously Unseen AMI"
excerpt: ""
categories:
  - Deprecated
last_modified_at: 2018-03-12
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for EC2 instances being created with previously unseen AMIs.  This search is deprecated and have been translated to use the latest Change Datamodel.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2018-03-12
- **Author**: David Dorsey, Splunk
- **ID**: 347ec301-601b-48b9-81aa-9ddf9c829dd3

#### Search

```
`cloudtrail` eventName=RunInstances [search `cloudtrail` eventName=RunInstances errorCode=success 
| stats earliest(_time) as firstTime latest(_time) as lastTime by requestParameters.instancesSet.items{}.imageId 
| rename requestParameters.instancesSet.items{}.imageId as amiID 
| inputlookup append=t previously_seen_ec2_amis.csv 
| stats min(firstTime) as firstTime max(lastTime) as lastTime by amiID 
| outputlookup previously_seen_ec2_amis.csv 
| eval newAMI=if(firstTime >= relative_time(now(), "-70m@m"), 1, 0) 
| `security_content_ctime(firstTime)`
|`security_content_ctime(lastTime)` 
| where newAMI=1 
| rename amiID as requestParameters.instancesSet.items{}.imageId 
| table requestParameters.instancesSet.items{}.imageId] 
| rename requestParameters.instanceType as instanceType, responseElements.instancesSet.items{}.instanceId as dest, userIdentity.arn as arn, requestParameters.instancesSet.items{}.imageId as amiID 
| table firstTime, lastTime, arn, amiID, dest, instanceType 
| `ec2_instance_started_with_previously_unseen_ami_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)

Note that `ec2_instance_started_with_previously_unseen_ami_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* errorCode
* requestParameters.instancesSet.items{}.imageId


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your AWS CloudTrail inputs. This search works best when you run the "Previously Seen EC2 AMIs" support search once to create a history of previously seen AMIs.

#### Known False Positives
After a new AMI is created, the first systems created with that AMI will cause this alert to fire.  Verify that the AMI being used was created by a legitimate user.

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



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/ec2_instance_started_with_previously_unseen_ami.yml) \| *version*: **1**