---
title: "Risk Notable Merge Events"
last_modified_at: 2021-10-22
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - None
  - Risk Notable
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

This playbook finds related events based on key fields in a risk notable and allows the user to process the results and decide which events to merge into the current investigation.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [None](https://splunkbase.splunk.com/apps/#/search/None/product/soar)
- **Last Updated**: 2021-10-22
- **Author**: Kelby Shelton, Splunk
- **ID**: rn0edc96-ff2b-48b0-9f6f-53da3783fd63

#### Associated Detections


#### How To Implement
Combining the list_merge utility within the playbook with the find_related_containers utility allows for fine-tuning of related event criteria. For example, the default filtering criteria uses description, risk_object, and threat_object as the important fields and requires at least three matches before an event is considered related. There are several options to customize the associated criteria, including adding more fields in list_merge, reducing or increasing the minimum match count, or utilizing the wildcard feature of find_related_containers.

#### Playbooks
![](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/risk_notable_merge_events.png)

#### Required field


#### Reference

* [https://docs.splunk.com/Documentation/ESSOC/latest/user/Useplaybookpack](https://docs.splunk.com/Documentation/ESSOC/latest/user/Useplaybookpack)




[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/risk_notable_merge_events.yml) \| *version*: **1**