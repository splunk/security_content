---
title: "Spectre And Meltdown Vulnerabilities"
last_modified_at: 2018-01-08
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Vulnerabilities
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Assess and mitigate your systems' vulnerability to Spectre and Meltdown exploitation with the searches in this Analytic Story.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Vulnerabilities](https://docs.splunk.com/Documentation/CIM/latest/User/Vulnerabilities)
- **Last Updated**: 2018-01-08
- **Author**: David Dorsey, Splunk
- **ID**: 6d3306f6-bb2b-4219-8609-8efad64032f2

#### Narrative

Meltdown and Spectre exploit critical vulnerabilities in modern CPUs that allow unintended access to data in memory. This Analytic Story will help you identify the systems can be patched for these vulnerabilities, as well as those that still need to be patched.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Spectre and Meltdown Vulnerable Systems](/deprecated/spectre_and_meltdown_vulnerable_systems/) | None| TTP |

#### Reference

* [https://meltdownattack.com/](https://meltdownattack.com/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/spectre_and_meltdown_vulnerabilities.yml) \| *version*: **1**