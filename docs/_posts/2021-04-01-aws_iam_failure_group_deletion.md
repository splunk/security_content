---
title: "AWS IAM Failure Group Deletion"
excerpt: "Account Manipulation
"
categories:
  - Cloud
last_modified_at: 2021-04-01
toc: true
toc_label: ""
tags:
  - Account Manipulation
  - Persistence
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This detection identifies failure attempts to delete groups. We want to identify when a group is attempting to be deleted, but either access is denied, there is a conflict or there is no group. This is indicative of administrators performing an action, but also could be suspicious behavior occurring. Review parallel IAM events - recently added users, new groups and so forth.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2021-04-01
- **Author**: Michael Haag, Splunk
- **ID**: 723b861a-92eb-11eb-93b8-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Persistence |

#### Search

```
`cloudtrail` eventSource=iam.amazonaws.com eventName=DeleteGroup errorCode IN (NoSuchEntityException,DeleteConflictException, AccessDenied) (userAgent!=*.amazonaws.com) 
| stats count min(_time) as firstTime max(_time) as lastTime values(requestParameters.groupName) as group_name by src eventName eventSource aws_account_id errorCode errorMessage userAgent eventID awsRegion userIdentity.principalId user_arn 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `aws_iam_failure_group_deletion_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)

Note that `aws_iam_failure_group_deletion_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* userAgent
* errorCode
* requestParameters.groupName


#### How To Implement
The Splunk AWS Add-on and Splunk App for AWS is required to utilize this data. The search requires AWS Cloudtrail logs.

#### Known False Positives
This detection will require tuning to provide high fidelity detection capabilties. Tune based on src addresses (corporate offices, VPN terminations) or by groups of users. Not every user with AWS access should have permission to delete groups (least privilege).

#### Associated Analytic story
* [AWS IAM Privilege Escalation](/stories/aws_iam_privilege_escalation)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 5.0 | 10 | 50 | User $user_arn$ has had mulitple failures while attempting to delete groups from $src$ |




#### Reference

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/delete-group.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/delete-group.html)
* [https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteGroup.html](https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteGroup.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/aws_iam_failure_group_deletion/aws_iam_failure_group_deletion.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/aws_iam_failure_group_deletion/aws_iam_failure_group_deletion.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_iam_failure_group_deletion.yml) \| *version*: **1**