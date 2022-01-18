---
title: "AWS Detect Users creating keys with encrypt policy without MFA"
excerpt: "Data Encrypted for Impact"
categories:
  - Cloud
last_modified_at: 2021-01-11
toc: true
toc_label: ""
tags:
  - Data Encrypted for Impact
  - Impact
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search provides detection of KMS keys where action kms:Encrypt is accessible for everyone (also outside of your organization). This is an indicator that your account is compromised and the attacker uses the encryption key to compromise another company.

- **Type**: TTP
- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-01-11
- **Author**: Rod Soto, Patrick Bareiss Splunk
- **ID**: c79c164f-4b21-4847-98f9-cf6a9f49179e


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1486](https://attack.mitre.org/techniques/T1486/) | Data Encrypted for Impact | Impact |

#### Search

```
`cloudtrail` eventName=CreateKey OR eventName=PutKeyPolicy 
| spath input=requestParameters.policy output=key_policy_statements path=Statement{} 
| mvexpand key_policy_statements 
| spath input=key_policy_statements output=key_policy_action_1 path=Action 
| spath input=key_policy_statements output=key_policy_action_2 path=Action{} 
| eval key_policy_action=mvappend(key_policy_action_1, key_policy_action_2) 
| spath input=key_policy_statements output=key_policy_principal path=Principal.AWS 
| search key_policy_action="kms:Encrypt" AND key_policy_principal="*" 
| stats count min(_time) as firstTime max(_time) as lastTime by eventName eventSource eventID awsRegion userIdentity.principalId 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
|`aws_detect_users_creating_keys_with_encrypt_policy_without_mfa_filter`
```

#### Associated Analytic Story
* [Ransomware Cloud](/stories/ransomware_cloud)


#### How To Implement
You must install splunk AWS add on and Splunk App for AWS. This search works with AWS CloudTrail logs

#### Required field
* _time
* eventName
* eventSource
* eventID
* awsRegion
* requestParameters.policy
* userIdentity.principalId


#### Kill Chain Phase


#### Known False Positives
unknown


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | AWS account is potentially compromised and user $userIdentity.principalId$ is trying to compromise other accounts. |




#### Reference

* [https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/](https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/)
* [https://github.com/d1vious/git-wild-hunt](https://github.com/d1vious/git-wild-hunt)
* [https://www.youtube.com/watch?v=PgzNib37g0M](https://www.youtube.com/watch?v=PgzNib37g0M)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1486/aws_kms_key/aws_cloudtrail_events.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1486/aws_kms_key/aws_cloudtrail_events.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_detect_users_creating_keys_with_encrypt_policy_without_mfa.yml) \| *version*: **1**