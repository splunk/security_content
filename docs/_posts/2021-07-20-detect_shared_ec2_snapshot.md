---
title: "Detect shared ec2 snapshot"
excerpt: "Transfer Data to Cloud Account
"
categories:
  - Cloud
last_modified_at: 2021-07-20
toc: true
toc_label: ""
tags:
  - Transfer Data to Cloud Account
  - Exfiltration
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic utilizes AWS CloudTrail events to identify when an EC2 snapshot permissions are modified to be shared with a different AWS account. This method is used by adversaries to exfiltrate the EC2 snapshot.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2021-07-20
- **Author**: Bhavin Patel, Splunk
- **ID**: 2a9b80d3-6340-4345-b5ad-290bf3d222c4


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1537](https://attack.mitre.org/techniques/T1537/) | Transfer Data to Cloud Account | Exfiltration |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Actions on Objectives


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* PR.DS
* PR.AC
* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 13



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

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

#### Macros
The SPL above uses the following Macros:
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)

Note that **detect_shared_ec2_snapshot_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* user_arn
* src_ip
* requestParameters.attributeType
* aws_account_id
* vendor_region
* user_agent


#### How To Implement
You must install splunk AWS add on and Splunk App for AWS. This search works with AWS CloudTrail logs.

#### Known False Positives
It is possible that an AWS admin has legitimately shared a snapshot with others for  a specific purpose.

#### Associated Analytic story
* [Suspicious Cloud Instance Activities](/stories/suspicious_cloud_instance_activities)
* [Data Exfiltration](/stories/data_exfiltration)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 48.0 | 60 | 80 | AWS EC2 snapshot from account $aws_account_id$ is shared with $requested_account_id$ by user $user_arn$ from $src_ip$ |


#### Reference

* [https://labs.nettitude.com/blog/how-to-exfiltrate-aws-ec2-data/](https://labs.nettitude.com/blog/how-to-exfiltrate-aws-ec2-data/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1537/aws_snapshot_exfil/aws_cloudtrail_events.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1537/aws_snapshot_exfil/aws_cloudtrail_events.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/detect_shared_ec2_snapshot.yml) \| *version*: **2**