---
title: "Detect New Open S3 Buckets over AWS CLI"
excerpt: "Data from Cloud Storage Object"
categories:
  - Cloud
last_modified_at: 2021-07-19
toc: true
toc_label: ""
tags:
  - Data from Cloud Storage Object
  - Collection
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for AWS CloudTrail events where a user has created an open/public S3 bucket over the aws cli.

- **Type**: TTP
- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-07-19
- **Author**: Patrick Bareiss, Splunk
- **ID**: 39c61d09-8b30-4154-922b-2d0a694ecc22


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage Object | Collection |

#### Search

```
`cloudtrail` eventSource="s3.amazonaws.com" (userAgent="[aws-cli*" OR userAgent=aws-cli* ) eventName=PutBucketAcl OR requestParameters.accessControlList.x-amz-grant-read-acp IN ("*AuthenticatedUsers","*AllUsers") OR requestParameters.accessControlList.x-amz-grant-write IN ("*AuthenticatedUsers","*AllUsers") OR requestParameters.accessControlList.x-amz-grant-write-acp IN ("*AuthenticatedUsers","*AllUsers") OR requestParameters.accessControlList.x-amz-grant-full-control IN ("*AuthenticatedUsers","*AllUsers") 
| rename requestParameters.bucketName AS bucketName 
| fillnull 
| stats count min(_time) as firstTime max(_time) as lastTime by userIdentity.userName userIdentity.principalId userAgent bucketName requestParameters.accessControlList.x-amz-grant-read requestParameters.accessControlList.x-amz-grant-read-acp requestParameters.accessControlList.x-amz-grant-write requestParameters.accessControlList.x-amz-grant-write-acp requestParameters.accessControlList.x-amz-grant-full-control 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `detect_new_open_s3_buckets_over_aws_cli_filter` 
```

#### Associated Analytic Story
* [Suspicious AWS S3 Activities](/stories/suspicious_aws_s3_activities)


#### How To Implement


#### Required field
* _time
* eventSource
* eventName
* requestParameters.accessControlList.x-amz-grant-read-acp
* requestParameters.accessControlList.x-amz-grant-write
* requestParameters.accessControlList.x-amz-grant-write-acp
* requestParameters.accessControlList.x-amz-grant-full-control
* requestParameters.bucketName
* userIdentity.userName
* userIdentity.principalId
* userAgent
* bucketName


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
While this search has no known false positives, it is possible that an AWS admin has legitimately created a public bucket for a specific purpose. That said, AWS strongly advises against granting full control to the &#34;All Users&#34; group.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 48.0 | 60 | 80 | User $userIdentity.userName$ has created an open/public bucket $bucketName$ using AWS CLI with the following permissions - $requestParameters.accessControlList.x-amz-grant-read$ $requestParameters.accessControlList.x-amz-grant-read-acp$ $requestParameters.accessControlList.x-amz-grant-write$ $requestParameters.accessControlList.x-amz-grant-write-acp$ $requestParameters.accessControlList.x-amz-grant-full-control$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1530/aws_s3_public_bucket/aws_cloudtrail_events.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1530/aws_s3_public_bucket/aws_cloudtrail_events.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/detect_new_open_s3_buckets_over_aws_cli.yml) \| *version*: **2**