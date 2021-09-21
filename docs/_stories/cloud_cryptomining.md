---
title: "Cloud Cryptomining"
last_modified_at: 2019-10-02
toc: true
tags:
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Change
---

#### Description

Monitor your cloud compute instances for activities related to cryptojacking/cryptomining. New instances that originate from previously unseen regions, users who launch abnormally high numbers of instances, or compute instances started by previously unseen users are just a few examples of potentially malicious behavior.

- **ID**: 3b96d13c-fdc7-45dd-b3ad-c132b31cdd2a
- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)
- **Last Updated**: 2019-10-02
- **Author**: David Dorsey, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Abnormally High Number Of Cloud Instances Launched](/cloud/abnormally_high_number_of_cloud_instances_launched/) | None | Anomaly |
| [Cloud Compute Instance Created By Previously Unseen User](/cloud/cloud_compute_instance_created_by_previously_unseen_user/) | None | Anomaly |
| [Cloud Compute Instance Created In Previously Unused Region](/cloud/cloud_compute_instance_created_in_previously_unused_region/) | None | Anomaly |
| [Cloud Compute Instance Created With Previously Unseen Image](/cloud/cloud_compute_instance_created_with_previously_unseen_image/) | None | Anomaly |
| [Cloud Compute Instance Created With Previously Unseen Instance Type](/cloud/cloud_compute_instance_created_with_previously_unseen_instance_type/) | None | Anomaly |

#### Reference

* [https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf](https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf)



[_source_](https://github.com/splunk/security_content/tree/develop/stories/cloud_cryptomining.yml) | _version_: **1**