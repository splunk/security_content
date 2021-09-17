---
title: "AWS IAM Delete Policy"
excerpt: "Account Manipulation"
categories:
  - Cloud
last_modified_at: 2021-04-01
toc: true
tags:
  - Hunting
  - T1098
  - Account Manipulation
  - Persistence
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Splunk Security Analytics for AWS
  - Actions on Objectives
---

#### Description

The following detection identifes when a policy is deleted on AWS. This does not identify whether successful or failed, but the error messages tell a story of suspicious attempts. There is a specific process to follow when deleting a policy. First, detach the policy from all users, groups, and roles that the policy is attached to, using DetachUserPolicy , DetachGroupPolicy , or DetachRolePolicy.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud, Splunk Security Analytics for AWS
- **Datamodel**:
- **Last Updated**: 2021-04-01
- **Author**: Michael Haag, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Persistence |


#### Search

```
`cloudtrail` eventName=DeletePolicy (userAgent!=*.amazonaws.com) 
| stats count min(_time) as firstTime max(_time) as lastTime values(requestParameters.policyArn) as policyArn by src eventName eventSource aws_account_id errorCode errorMessage userAgent eventID awsRegion userIdentity.principalId userIdentity.arn 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `aws_iam_delete_policy_filter`
```

#### Associated Analytic Story
* [AWS IAM Privilege Escalation](_stories/aws_iam_privilege_escalation)


#### How To Implement
The Splunk AWS Add-on and Splunk App for AWS is required to utilize this data. The search requires AWS Cloudtrail logs.

#### Required field
* _time
* eventName
* userAgent
* errorCode
* requestParameters.policyArn


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
This detection will require tuning to provide high fidelity detection capabilties. Tune based on src addresses (corporate offices, VPN terminations) or by groups of users. Not every user with AWS access should have permission to delete policies (least privilege). In addition, this may be saved seperately and tuned for failed or success attempts only.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 10.0 | 20 | 50 |



#### Reference

* [https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeletePolicy.html](https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeletePolicy.html)
* [https://docs.aws.amazon.com/cli/latest/reference/iam/delete-policy.html](https://docs.aws.amazon.com/cli/latest/reference/iam/delete-policy.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/aws_iam_delete_policy/aws_iam_delete_policy.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/aws_iam_delete_policy/aws_iam_delete_policy.json)


_version_: 1