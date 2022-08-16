---
title: "Hunting"
last_modified_at: 2021-01-21
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - Splunk
  - Reversing Labs
  - CarbonBlack Response
  - Threat Grid
  - Falcon Host API
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

The hunting Playbook queries a number of internal security technologies in order to determine if any of the artifacts present in your data source have been observed in your environment.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [Splunk](https://splunkbase.splunk.com/apps/#/search/Splunk/product/soar), [Reversing Labs](https://splunkbase.splunk.com/apps/#/search/Reversing Labs/product/soar), [CarbonBlack Response](https://splunkbase.splunk.com/apps/#/search/CarbonBlack Response/product/soar), [Threat Grid](https://splunkbase.splunk.com/apps/#/search/Threat Grid/product/soar), [Falcon Host API](https://splunkbase.splunk.com/apps/#/search/Falcon Host API/product/soar)
- **Last Updated**: 2021-01-21
- **Author**: Philip Royer, Splunk
- **ID**: fb3edc76-ff2b-48b0-5f6f-63da6351ad63

#### Associated Detections


#### How To Implement
Be sure to update asset naming to reflect the asset names configured in your environment.

#### Playbooks
![](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/hunting.png)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/hunting.yml) \| *version*: **1**