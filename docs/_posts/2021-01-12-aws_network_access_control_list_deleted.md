---
title: "AWS Network Access Control List Deleted"
excerpt: "Disable or Modify Cloud Firewall
, Impair Defenses
"
categories:
  - Cloud
last_modified_at: 2021-01-12
toc: true
toc_label: ""
tags:
  - Disable or Modify Cloud Firewall
  - Impair Defenses
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

Enforcing network-access controls is one of the defensive mechanisms used by cloud administrators to restrict access to a cloud instance. After the attacker has gained control of the AWS console by compromising an admin account, they can delete a network ACL and gain access to the instance from anywhere. This search will query the AWS CloudTrail logs to detect users deleting network ACLs.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2021-01-12
- **Author**: Bhavin Patel, Patrick Bareiss, Splunk
- **ID**: ada0f478-84a8-4641-a3f1-d82362d6fd75


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1562.007](https://attack.mitre.org/techniques/T1562/007/) | Disable or Modify Cloud Firewall | Defense Evasion |

| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Defense Evasion |

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

* DE.DP
* DE.AE



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 11



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```
`cloudtrail` eventName=DeleteNetworkAclEntry requestParameters.egress=false 
| fillnull 
| stats count min(_time) as firstTime max(_time) as lastTime by userName userIdentity.principalId eventName requestParameters.egress src userAgent 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `aws_network_access_control_list_deleted_filter`
```

#### Macros
The SPL above uses the following Macros:
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **aws_network_access_control_list_deleted_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* requestParameters.egress
* userName
* userIdentity.principalId
* src
* userAgent


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your AWS CloudTrail inputs.

#### Known False Positives
It's possible that a user has legitimately deleted a network ACL.

#### Associated Analytic story
* [AWS Network ACL Activity](/stories/aws_network_acl_activity)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 5.0 | 10 | 50 | User $user_arn$ from $src$ has sucessfully deleted network ACLs entry (eventName= $eventName$), such that the instance is accessible from anywhere |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.007/aws_delete_acl/aws_cloudtrail_events.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.007/aws_delete_acl/aws_cloudtrail_events.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_network_access_control_list_deleted.yml) \| *version*: **2**