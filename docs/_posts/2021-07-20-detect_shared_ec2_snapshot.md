---
title: "Detect shared ec2 snapshot"
excerpt: "Transfer Data to Cloud Account"
categories:
  - Cloud
last_modified_at: 2021-07-20
toc: true
toc_label: ""
tags:
  - Transfer Data to Cloud Account
  - Exfiltration
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic utilizes AWS CloudTrail events to identify when an EC2 snapshot permissions are modified to be shared with a different AWS account. This method is used by adversaries to exfiltrate the EC2 snapshot.

- **Type**: TTP
- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-07-20
- **Author**: Bhavin Patel, Splunk
- **ID**: 2a9b80d3-6340-4345-b5ad-290bf3d222c4


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1537](https://attack.mitre.org/techniques/T1537/) | Transfer Data to Cloud Account | Exfiltration |

#### Search

```
`cloudtrail` eventName=ModifySnapshotAttribute 
| rename requestParameters.createVolumePermission.add.items{}.userId as requested_account_id 
| search requested_account_id != NULL 
| eval match=if(requested_account_id==aws_account_id,"Match","No Match") 
| table _time user_arn src_ip requestParameters.attributeType requested_account_id aws_account_id match vendor_region user_agent 
| where match = "No Match" 
| `detect_shared_ec2_snapshot_filter` 
```

#### Associated Analytic Story
* [Suspicious Cloud Instance Activities](/stories/suspicious_cloud_instance_activities)
* [Data Exfiltration](/stories/data_exfiltration)


#### How To Implement
You must install splunk AWS add on and Splunk App for AWS. This search works with AWS CloudTrail logs.

#### Required field
* _time
* eventName
* user_arn
* src_ip
* requestParameters.attributeType
* aws_account_id
* vendor_region
* user_agent


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
It is possible that an AWS admin has legitimately shared a snapshot with others for  a specific purpose.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 48.0 | 60 | 80 | AWS EC2 snapshot from account $aws_account_id$ is shared with $requested_account_id$ by user $user_arn$ from $src_ip$ |




#### Reference

* [https://labs.nettitude.com/blog/how-to-exfiltrate-aws-ec2-data/](https://labs.nettitude.com/blog/how-to-exfiltrate-aws-ec2-data/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1537/aws_snapshot_exfil/aws_cloudtrail_events.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1537/aws_snapshot_exfil/aws_cloudtrail_events.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/detect_shared_ec2_snapshot.yml) \| *version*: **2**