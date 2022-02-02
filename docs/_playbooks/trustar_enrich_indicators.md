---
title: "TruSTAR Enrich Indicators"
last_modified_at: 2021-11-24
toc: true
toc_label: ""
tags:
  - Input
  - Splunk SOAR
  - TruSTAR
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Use TruSTAR to gather threat information about indicators in a SOAR event. Tag the indicators with the normalized priority score from TruSTAR and summarize the findings in an analyst note. This playbook is meant to be used as a child playbook executed by a parent playbook such as &#34;threat_intel_investigate&#34;.

- **Type**: Input
- **Product**: Splunk SOAR
- **Apps**: [TruSTAR](https://splunkbase.splunk.com/apps/#/search/TruSTAR/product/soar)
- **Last Updated**: 2021-11-24
- **Author**: Philip Royer, Splunk
- **ID**: fc5adc76-fd2b-48b0-5f6f-63da6423fd63

#### Associated Detections


#### How To Implement
To use this playbook as a sub-playbook of &#34;threat_intel_investigate&#34;, copy it to the local git repository and make sure it has the tags &#34;investigate&#34; and &#34;threat_intel&#34;. To use this playbook as a sub-playbook of &#34;risk_notable_enrich&#34;, copy it to local and make sure it has the tags &#34;investigate&#34; and &#34;risk_notable&#34; To control the types of indicators processed by this playbook, change the data types of the &#34;indicators&#34; input&#34;

#### Playbooks
![](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/trustar_enrich_indicators.png)

#### Required field
* indicators


#### Reference

* [https://www.splunk.com/en_us/blog/security/TruSTAR-Enrich-Indicators-soar-in-seconds.html](https://www.splunk.com/en_us/blog/security/TruSTAR-Enrich-Indicators-soar-in-seconds.html)




[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/trustar_enrich_indicators.yml) \| *version*: **1**