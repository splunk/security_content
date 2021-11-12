---
title: "AWS IAM Successful Group Deletion"
excerpt: "Cloud Groups, Account Manipulation, Permission Groups Discovery"
categories:
  - Cloud
last_modified_at: 2021-03-31
toc: true
toc_label: ""
tags:
  - Cloud Groups
  - Discovery
  - Account Manipulation
  - Persistence
  - Permission Groups Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Splunk Security Analytics for AWS
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following query uses IAM events to track the success of a group being deleted on AWS. This is typically not indicative of malicious behavior, but a precurser to additional events thay may unfold. Review parallel IAM events - recently added users, new groups and so forth. Inversely, review failed attempts in a similar manner.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud, Splunk Security Analytics for AWS
- **Datamodel**: 
- **Last Updated**: 2021-03-31
- **Author**: Michael Haag, Splunk
- **ID**: e776d06c-9267-11eb-819b-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1069.003](https://attack.mitre.org/techniques/T1069/003/) | Cloud Groups | Discovery |

| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Persistence |

| [T1069](https://attack.mitre.org/techniques/T1069/) | Permission Groups Discovery | Discovery |

#### Search

```
`cloudtrail` eventSource=iam.amazonaws.com eventName=DeleteGroup errorCode=success (userAgent!=*.amazonaws.com) 
| stats count min(_time) as firstTime max(_time) as lastTime values(requestParameters.groupName) as group_deleted by src eventName eventSource errorCode user_agent awsRegion userIdentity.principalId user_arn 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `aws_iam_successful_group_deletion_filter`
```

#### Associated Analytic Story
* [AWS IAM Privilege Escalation](/stories/aws_iam_privilege_escalation)


#### How To Implement
The Splunk AWS Add-on and Splunk App for AWS is required to utilize this data. The search requires AWS Cloudtrail logs.

#### Required field
* _time
* eventName
* userAgent
* errorCode
* requestParameters.groupName


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
This detection will require tuning to provide high fidelity detection capabilties. Tune based on src addresses (corporate offices, VPN terminations) or by groups of users. Not every user with AWS access should have permission to delete groups (least privilege).


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 5.0 | 10 | 50 | User $user_arn$ has sucessfully deleted mulitple groups $group_deleted$ from $src$ |




#### Reference

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/delete-group.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/delete-group.html)
* [https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteGroup.html](https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteGroup.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/aws_iam_successful_group_deletion/aws_iam_successful_group_deletion.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/aws_iam_successful_group_deletion/aws_iam_successful_group_deletion.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_iam_successful_group_deletion.yml) \| *version*: **1**