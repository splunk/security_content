---
title: "SQL Injection"
last_modified_at: 2017-09-19
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Web
  - Delivery
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Use the searches in this Analytic Story to help you detect structured query language (SQL) injection attempts characterized by long URLs that contain malicious parameters.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2017-09-19
- **Author**: Bhavin Patel, Splunk
- **ID**: 4f6632f5-449c-4686-80df-57625f59bab3

#### Narrative

It is very common for attackers to inject SQL parameters into vulnerable web applications, which then interpret the malicious SQL statements.\
This Analytic Story contains a search designed to identify attempts by attackers to leverage this technique to compromise a host and gain a foothold in the target environment.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [SQL Injection with Long URLs](/web/sql_injection_with_long_urls/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application)| TTP |

#### Reference

* [https://capec.mitre.org/data/definitions/66.html](https://capec.mitre.org/data/definitions/66.html)
* [https://www.incapsula.com/web-application-security/sql-injection.html](https://www.incapsula.com/web-application-security/sql-injection.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/sql_injection.yml) \| *version*: **1**