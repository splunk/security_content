---
title: "AWS Network Access Control List Created with All Open Ports"
excerpt: "Disable or Modify Cloud Firewall
, Impair Defenses
"
categories:
  - Cloud
last_modified_at: 2021-01-11
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

The search looks for AWS CloudTrail events to detect if any network ACLs were created with all the ports open to a specified CIDR.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2021-01-11
- **Author**: Bhavin Patel, Patrick Bareiss, Splunk
- **ID**: ada0f478-84a8-4641-a3f1-d82362d6bd75


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1562.007](https://attack.mitre.org/techniques/T1562/007/) | Disable or Modify Cloud Firewall | Defense Evasion |

| [T1562](https://attack.mitre.org/techniques/T1562/) | Impair Defenses | Defense Evasion |

#### Search

```
`cloudtrail` eventName=CreateNetworkAclEntry OR eventName=ReplaceNetworkAclEntry requestParameters.ruleAction=allow requestParameters.egress=false requestParameters.aclProtocol=-1 
| append [search `cloudtrail` eventName=CreateNetworkAclEntry OR eventName=ReplaceNetworkAclEntry requestParameters.ruleAction=allow requestParameters.egress=false requestParameters.aclProtocol!=-1 
| eval port_range='requestParameters.portRange.to' - 'requestParameters.portRange.from' 
| where port_range>1024] 
| fillnull 
| stats count min(_time) as firstTime max(_time) as lastTime by userName userIdentity.principalId eventName requestParameters.ruleAction requestParameters.egress requestParameters.aclProtocol requestParameters.portRange.to requestParameters.portRange.from src userAgent requestParameters.cidrBlock 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `aws_network_access_control_list_created_with_all_open_ports_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [cloudtrail](https://github.com/splunk/security_content/blob/develop/macros/cloudtrail.yml)

Note that `aws_network_access_control_list_created_with_all_open_ports_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* eventName
* requestParameters.ruleAction
* requestParameters.egress
* requestParameters.aclProtocol
* requestParameters.portRange.to
* requestParameters.portRange.from
* requestParameters.cidrBlock
* userName
* userIdentity.principalId
* userAgent


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS, version 4.4.0 or later, and configure your AWS CloudTrail inputs.

#### Known False Positives
It's possible that an admin has created this ACL with all ports open for some legitimate purpose however, this should be scoped and not allowed in production environment.

#### Associated Analytic story
* [AWS Network ACL Activity](/stories/aws_network_acl_activity)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 48.0 | 60 | 80 | User $user_arn$ has created network ACLs with all the ports open to a specified CIDR $requestParameters.cidrBlock$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.007/aws_create_acl/aws_cloudtrail_events.json](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.007/aws_create_acl/aws_cloudtrail_events.json)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/aws_network_access_control_list_created_with_all_open_ports.yml) \| *version*: **2**