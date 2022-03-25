---
title: "Detect New Open S3 buckets"
excerpt: "Data from Cloud Storage Object
"
categories:
  - Cloud
last_modified_at: 2021-07-19
toc: true
toc_label: ""
tags:
  - Data from Cloud Storage Object
  - Collection
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for AWS CloudTrail events where a user has created an open/public S3 bucket.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2021-07-19
- **Author**: Bhavin Patel, Patrick Bareiss, Splunk
- **ID**: 2a9b80d3-6340-4345-b5ad-290bf3d0dac4


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage Object | Collection |

#### Search

```
`cloudtrail` eventSource=s3.amazonaws.com eventName=PutBucketAcl 
| rex field=_raw "(?<json_field>{.+})" 
| spath input=json_field output=grantees path=requestParameters.AccessControlPolicy.AccessControlList.Grant{} 
| search grantees=* 
| mvexpand grantees 
| spath input=grantees output=uri path=Grantee.URI 
| spath input=grantees output=permission path=Permission 
| search uri IN ("http://acs.amazonaws.com/groups/global/AllUsers","http://acs.amazonaws.com/groups/global/AuthenticatedUsers") 
| search permission IN ("READ","READ_ACP","WRITE","WRITE_ACP","FULL_CONTROL") 
| rename requestParameters.bucketName AS bucketName 
| stats count min(_time) as firstTime max(_time) as lastTime by user_arn userIdentity.principalId userAgent uri permission bucketName 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `detect_new_open_s3_buckets_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)

Note that `detect_new_open_s3_buckets_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventSource
* eventName
* requestParameters.bucketName
* user_arn
* userIdentity.principalId
* userAgent
* uri
* permission


#### How To Implement
You must install the AWS App for Splunk.

#### Known False Positives
While this search has no known false positives, it is possible that an AWS admin has legitimately created a public bucket for a specific purpose. That said, AWS strongly advises against granting full control to the "All Users" group.

#### Associated Analytic story
* [Suspicious AWS S3 Activities](/stories/suspicious_aws_s3_activities)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 48.0 | 60 | 80 | User $user_arn$ has created an open/public bucket $bucketName$ with the following permissions $permission$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1530/aws_s3_public_bucket/aws_cloudtrail_events.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1530/aws_s3_public_bucket/aws_cloudtrail_events.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/detect_new_open_s3_buckets.yml) \| *version*: **3**