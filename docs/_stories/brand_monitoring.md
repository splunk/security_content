---
title: "Brand Monitoring"
last_modified_at: 2017-12-19
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Email
  - Network_Resolution
  - Web
  - Actions on Objectives
  - Delivery
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Detect and investigate activity that may indicate that an adversary is using faux domains to mislead users into interacting with malicious infrastructure. Monitor DNS, email, and web traffic for permutations of your brand name.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Email](https://docs.splunk.com/Documentation/CIM/latest/User/Email), [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution), [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2017-12-19
- **Author**: David Dorsey, Splunk
- **ID**: 91c676cf-0b23-438d-abee-f6335e1fce78

#### Narrative

While you can educate your users and customers about the risks and threats posed by typosquatting, phishing, and corporate espionage, human error is a persistent fact of life. Of course, your adversaries are all too aware of this reality and will happily leverage it for nefarious purposes whenever possible&#51;phishing with lookalike addresses, embedding faux command-and-control domains in malware, and hosting malicious content on domains that closely mimic your corporate servers. This is where brand monitoring comes in.\
You can use our adaptation of `DNSTwist`, together with the support searches in this Analytic Story, to generate permutations of specified brands and external domains. Splunk can monitor email, DNS requests, and web traffic for these permutations and provide you with early warnings and situational awareness--powerful elements of an effective defense.\
Notable events will include IP addresses, URLs, and user data. Drilling down can provide you with even more actionable intelligence, including likely geographic information, contextual searches to help you scope the problem, and investigative searches.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Monitor DNS For Brand Abuse](/deprecated/monitor_dns_for_brand_abuse/) | None| TTP |
| [Monitor Email For Brand Abuse](/application/monitor_email_for_brand_abuse/) | None| TTP |
| [Monitor Web Traffic For Brand Abuse](/web/monitor_web_traffic_for_brand_abuse/) | None| TTP |

#### Reference

* [https://www.zerofox.com/blog/what-is-digital-risk-monitoring/](https://www.zerofox.com/blog/what-is-digital-risk-monitoring/)
* [https://securingtomorrow.mcafee.com/consumer/family-safety/what-is-typosquatting/](https://securingtomorrow.mcafee.com/consumer/family-safety/what-is-typosquatting/)
* [https://blog.malwarebytes.com/cybercrime/2016/06/explained-typosquatting/](https://blog.malwarebytes.com/cybercrime/2016/06/explained-typosquatting/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/brand_monitoring.yml) \| *version*: **1**