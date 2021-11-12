---
title: "aws detect attach to role policy"
excerpt: "Valid Accounts"
categories:
  - Cloud
last_modified_at: 2020-07-27
toc: true
toc_label: ""
tags:
  - Valid Accounts
  - Defense Evasion
  - Persistence
  - Privilege Escalation
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate or build datasets for it, use at your own risk!


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search provides detection of an user attaching itself to a different role trust policy. This can be used for lateral movement and escalation of privileges.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-07-27
- **Author**: Rod Soto, Splunk
- **ID**: 88fc31dd-f331-448c-9856-d3d51dd5d3a1


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access |

#### Search

```
`aws_cloudwatchlogs_eks` attach policy
| spath requestParameters.policyArn 
| table sourceIPAddress user_access_key userIdentity.arn userIdentity.sessionContext.sessionIssuer.arn eventName errorCode errorMessage status action requestParameters.policyArn userIdentity.sessionContext.attributes.mfaAuthenticated userIdentity.sessionContext.attributes.creationDate  
| `aws_detect_attach_to_role_policy_filter`
```

#### Associated Analytic Story
* [AWS Cross Account Activity](/stories/aws_cross_account_activity)


#### How To Implement
You must install splunk AWS add-on and Splunk App for AWS. This search works with cloudwatch logs

#### Required field
* _time
* requestParameters.policyArn


#### Kill Chain Phase
* Lateral Movement


#### Known False Positives
Attach to policy can create a lot of noise. This search can be adjusted to provide specific values to identify cases of abuse (i.e status=failure). The search can provide context for common users attaching themselves to higher privilege policies or even newly created policies.





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/cloud/aws_detect_attach_to_role_policy.yml) \| *version*: **1**