---
title: "AWS IAM Delete Policy"
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

The following detection identifes when a policy is deleted on AWS. This does not identify whether successful or failed, but the error messages tell a story of suspicious attempts. There is a specific process to follow when deleting a policy. First, detach the policy from all users, groups, and roles that the policy is attached to, using DetachUserPolicy , DetachGroupPolicy , or DetachRolePolicy.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2021-04-01
- **Author**: Michael Haag, Splunk
- **ID**: ec3a9362-92fe-11eb-99d0-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Persistence |

#### Search

```
`cloudtrail` eventName=DeletePolicy (userAgent!=*.amazonaws.com) 
| stats count min(_time) as firstTime max(_time) as lastTime values(requestParameters.policyArn) as policyArn by src eventName eventSource aws_account_id errorCode errorMessage userAgent eventID awsRegion userIdentity.principalId userIdentity.arn 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `aws_iam_delete_policy_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)

Note that `aws_iam_delete_policy_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* userAgent
* errorCode
* requestParameters.policyArn


#### How To Implement
The Splunk AWS Add-on and Splunk App for AWS is required to utilize this data. The search requires AWS Cloudtrail logs.

#### Known False Positives
This detection will require tuning to provide high fidelity detection capabilties. Tune based on src addresses (corporate offices, VPN terminations) or by groups of users. Not every user with AWS access should have permission to delete policies (least privilege). In addition, this may be saved seperately and tuned for failed or success attempts only.

#### Associated Analytic story
* [AWS IAM Privilege Escalation](/stories/aws_iam_privilege_escalation)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 10.0 | 20 | 50 | User $user_arn$ has deleted AWS Policies from IP address $src$ by executing the following command $eventName$ |




#### Reference

* [https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeletePolicy.html](https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeletePolicy.html)
* [https://docs.aws.amazon.com/cli/latest/reference/iam/delete-policy.html](https://docs.aws.amazon.com/cli/latest/reference/iam/delete-policy.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/aws_iam_delete_policy/aws_iam_delete_policy.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/aws_iam_delete_policy/aws_iam_delete_policy.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_iam_delete_policy.yml) \| *version*: **1**