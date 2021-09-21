---
title: "Brand Monitoring"
last_modified_at: 2017-12-19
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Email
  - Web
---

#### Description

Detect and investigate activity that may indicate that an adversary is using faux domains to mislead users into interacting with malicious infrastructure. Monitor DNS, email, and web traffic for permutations of your brand name.

- **ID**: 91c676cf-0b23-438d-abee-f6335e1fce78
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Email](https://docs.splunk.com/Documentation/CIM/latest/User/Email), [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2017-12-19
- **Author**: David Dorsey, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Monitor Email For Brand Abuse](/application/monitor_email_for_brand_abuse/) | None | TTP |
| [Monitor Web Traffic For Brand Abuse](/web/monitor_web_traffic_for_brand_abuse/) | None | TTP |

#### Reference

* [https://www.zerofox.com/blog/what-is-digital-risk-monitoring/](https://www.zerofox.com/blog/what-is-digital-risk-monitoring/)
* [https://securingtomorrow.mcafee.com/consumer/family-safety/what-is-typosquatting/](https://securingtomorrow.mcafee.com/consumer/family-safety/what-is-typosquatting/)
* [https://blog.malwarebytes.com/cybercrime/2016/06/explained-typosquatting/](https://blog.malwarebytes.com/cybercrime/2016/06/explained-typosquatting/)



[_source_](https://github.com/splunk/security_content/tree/develop/stories/brand_monitoring.yml) | _version_: **1**