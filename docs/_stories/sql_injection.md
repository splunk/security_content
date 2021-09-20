---
title: "SQL Injection"
last_modified_at: 2017-09-19
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Web
---

#### Description

Use the searches in this Analytic Story to help you detect structured query language (SQL) injection attempts characterized by long URLs that contain malicious parameters.

- **ID**: 4f6632f5-449c-4686-80df-57625f59bab3
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2017-09-19
- **Author**: Bhavin Patel, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [SQL Injection with Long URLs](/web/sql_injection_with_long_urls/) | None | TTP |

#### Kill Chain Phase



#### Reference

* [https://capec.mitre.org/data/definitions/66.html](https://capec.mitre.org/data/definitions/66.html)
* [https://www.incapsula.com/web-application-security/sql-injection.html](https://www.incapsula.com/web-application-security/sql-injection.html)



_version_: 1