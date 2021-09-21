---
title: "AWS Network ACL Activity"
last_modified_at: 2018-05-21
toc: true
tags:
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

#### Description

Monitor your AWS network infrastructure for bad configurations and malicious activity. Investigative searches help you probe deeper, when the facts warrant it.

- **ID**: 2e8948a5-5239-406b-b56b-6c50ff268af4
- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2018-05-21
- **Author**: Bhavin Patel, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AWS Network Access Control List Created with All Open Ports](/cloud/aws_network_access_control_list_created_with_all_open_ports/) | None | TTP |
| [AWS Network Access Control List Deleted](/cloud/aws_network_access_control_list_deleted/) | None | Anomaly |
| [Detect Spike in blocked Outbound Traffic from your AWS](/cloud/detect_spike_in_blocked_outbound_traffic_from_your_aws/) | None | Anomaly |

#### Reference

* [https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Appendix_NACLs.html](https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Appendix_NACLs.html)
* [https://aws.amazon.com/blogs/security/how-to-help-prepare-for-ddos-attacks-by-reducing-your-attack-surface/](https://aws.amazon.com/blogs/security/how-to-help-prepare-for-ddos-attacks-by-reducing-your-attack-surface/)



[_source_](https://github.com/splunk/security_content/tree/develop/stories/aws_network_acl_activity.yml) | _version_: **2**