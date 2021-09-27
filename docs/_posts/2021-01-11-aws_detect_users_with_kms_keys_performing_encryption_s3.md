---
title: "AWS Detect Users with KMS keys performing encryption S3"
excerpt: "Data Encrypted for Impact"
categories:
  - Cloud
last_modified_at: 2021-01-11
toc: true
tags:
  - Anomaly
  - T1486
  - Data Encrypted for Impact
  - Impact
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search provides detection of users with KMS keys performing encryption specifically against S3 buckets.

- **Type**: Anomaly
- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-01-11
- **Author**: Rod Soto, Patrick Bareiss Splunk
- **ID**: 884a5f59-eec7-4f4a-948b-dbde18225fdc


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1486](https://attack.mitre.org/techniques/T1486/) | Data Encrypted for Impact | Impact |



#### Search

```
`cloudtrail` eventName=CopyObject requestParameters.x-amz-server-side-encryption="aws:kms" 
| rename requestParameters.bucketName AS bucket_name, requestParameters.x-amz-copy-source AS src_file, requestParameters.key AS dest_file 
| stats count min(_time) as firstTime max(_time) as lastTime values(src_file) AS src_file values(dest_file) AS dest_file values(userAgent) AS userAgent values(region) AS region values(src) AS src by user 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
|`aws_detect_users_with_kms_keys_performing_encryption_s3_filter`
```

#### Associated Analytic Story
* [Ransomware Cloud](/stories/ransomware_cloud)


#### How To Implement
You must install splunk AWS add on and Splunk App for AWS. This search works with AWS CloudTrail logs

#### Required field
* _time
* eventName
* requestParameters.x-amz-server-side-encryption
* requestParameters.bucketName
* requestParameters.x-amz-copy-source
* requestParameters.key
* userAgent
* region


#### Kill Chain Phase


#### Known False Positives
bucket with S3 encryption



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 15.0 | 30 | 50 | User $user$ with KMS keys is performing encryption, against S3 buckets on these files $dest_file$ |



#### Reference

* [https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/](https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/)
* [https://github.com/d1vious/git-wild-hunt](https://github.com/d1vious/git-wild-hunt)
* [https://www.youtube.com/watch?v=PgzNib37g0M](https://www.youtube.com/watch?v=PgzNib37g0M)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1486/s3_file_encryption/aws_cloudtrail_events.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1486/s3_file_encryption/aws_cloudtrail_events.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_detect_users_with_kms_keys_performing_encryption_s3.yml) \| *version*: **1**