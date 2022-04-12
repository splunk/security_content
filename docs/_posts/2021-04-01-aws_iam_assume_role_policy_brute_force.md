---
title: "AWS IAM Assume Role Policy Brute Force"
excerpt: "Cloud Infrastructure Discovery
, Brute Force
"
categories:
  - Cloud
last_modified_at: 2021-04-01
toc: true
toc_label: ""
tags:
  - Cloud Infrastructure Discovery
  - Brute Force
  - Discovery
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following detection identifies any malformed policy document exceptions with a status of `failure`. A malformed policy document exception occurs in instances where roles are attempted to be assumed, or brute forced. In a brute force attempt, using a tool like CloudSploit or Pacu, an attempt will look like `arn:aws:iam::111111111111:role/aws-service-role/rds.amazonaws.com/AWSServiceRoleForRDS`.  Meaning, when an adversary is attempting to identify a role name, multiple failures will occur. This detection focuses on the errors of a remote attempt that is failing.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2021-04-01
- **Author**: Michael Haag, Splunk
- **ID**: f19e09b0-9308-11eb-b7ec-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1580](https://attack.mitre.org/techniques/T1580/) | Cloud Infrastructure Discovery | Discovery |

| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | Credential Access |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Reconnaissance


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```
`cloudtrail` (errorCode=MalformedPolicyDocumentException) status=failure (userAgent!=*.amazonaws.com) 
| stats count min(_time) as firstTime max(_time) as lastTime values(requestParameters.policyName) as policy_name by src eventName eventSource aws_account_id errorCode requestParameters.policyDocument userAgent eventID awsRegion userIdentity.principalId user_arn 
| where count >= 2 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `aws_iam_assume_role_policy_brute_force_filter`
```

#### Macros
The SPL above uses the following Macros:
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **aws_iam_assume_role_policy_brute_force_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* userAgent
* errorCode
* requestParameters.policyName


#### How To Implement
The Splunk AWS Add-on and Splunk App for AWS is required to utilize this data. The search requires AWS Cloudtrail logs. Set the `where count` greater than a value to identify suspicious activity in your environment.

#### Known False Positives
This detection will require tuning to provide high fidelity detection capabilties. Tune based on src addresses (corporate offices, VPN terminations) or by groups of users.

#### Associated Analytic story
* [AWS IAM Privilege Escalation](/stories/aws_iam_privilege_escalation)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 28.0 | 40 | 70 | User $user_arn$ has caused multiple failures with errorCode $errorCode$, which potentially means adversary is attempting to identify a role name. |


#### Reference

* [https://www.praetorian.com/blog/aws-iam-assume-role-vulnerabilities](https://www.praetorian.com/blog/aws-iam-assume-role-vulnerabilities)
* [https://rhinosecuritylabs.com/aws/assume-worst-aws-assume-role-enumeration/](https://rhinosecuritylabs.com/aws/assume-worst-aws-assume-role-enumeration/)
* [https://www.elastic.co/guide/en/security/current/aws-iam-brute-force-of-assume-role-policy.html](https://www.elastic.co/guide/en/security/current/aws-iam-brute-force-of-assume-role-policy.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1580/aws_iam_assume_role_policy_brute_force/aws_iam_assume_role_policy_brute_force.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1580/aws_iam_assume_role_policy_brute_force/aws_iam_assume_role_policy_brute_force.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_iam_assume_role_policy_brute_force.yml) \| *version*: **1**