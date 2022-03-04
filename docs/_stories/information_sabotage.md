---
title: "Information Sabotage"
last_modified_at: 2021-11-17
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Splunk Behavioral Analytics
  - Endpoint
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might correlate to insider threat specially in terms of information sabotage.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud, Splunk Behavioral Analytics
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-11-17
- **Author**: Teoderick Contreras, Splunk
- **ID**: b71ba595-ef80-4e39-8b66-887578a7a71b

#### Narrative

Information sabotage is the type of crime many people associate with insider threat. Where the current or former employees, contractors, or business partners intentionally exceeded or misused an authorized level of access to networks, systems, or data with the intention of harming a specific individual, the organization, or the organization's data, systems, and/or daily business operations.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [High Frequency Copy Of Files In Network Share](/endpoint/high_frequency_copy_of_files_in_network_share/) | [Transfer Data to Cloud Account](/tags/#transfer-data-to-cloud-account)| Anomaly |

#### Reference

* [https://insights.sei.cmu.edu/blog/insider-threat-deep-dive-it-sabotage/](https://insights.sei.cmu.edu/blog/insider-threat-deep-dive-it-sabotage/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/information_sabotage.yml) \| *version*: **1**