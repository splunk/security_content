---
title: "AWS Network Access Control List Deleted"
excerpt: "Disable or Modify Cloud Firewall"
categories:
  - Cloud
last_modified_at: 2021-01-12
toc: true
tags:
  - Anomaly
  - T1562.007
  - Disable or Modify Cloud Firewall
  - Defense Evasion
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Actions on Objectives
---



#### Description

Enforcing network-access controls is one of the defensive mechanisms used by cloud administrators to restrict access to a cloud instance. After the attacker has gained control of the AWS console by compromising an admin account, they can delete a network ACL and gain access to the instance from anywhere. This search will query the AWS CloudTrail logs to detect users deleting network ACLs.

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-01-12
- **Author**: Bhavin Patel, Patrick Bareiss, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1562.007](https://attack.mitre.org/techniques/T1562/007/) | Disable or Modify Cloud Firewall | Defense Evasion |


#### Search

```
`cloudtrail` eventName=DeleteNetworkAclEntry requestParameters.egress=false 
| fillnull 
| stats count min(_time) as firstTime max(_time) as lastTime by userName userIdentity.principalId eventName requestParameters.egress src userAgent 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `aws_network_access_control_list_deleted_filter`
```

#### Associated Analytic Story
* [AWS Network ACL Activity](_stories/aws_network_acl_activity)


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your AWS CloudTrail inputs.

#### Required field
* _time
* eventName
* requestParameters.egress
* userName
* userIdentity.principalId
* src
* userAgent


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
It&#39;s possible that a user has legitimately deleted a network ACL.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 5.0 | 10 | 50 |



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.007/aws_delete_acl/aws_cloudtrail_events.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.007/aws_delete_acl/aws_cloudtrail_events.json)


_version_: 2