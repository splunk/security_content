---
title: "DNS Amplification Attacks"
last_modified_at: 2016-09-13
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Resolution
---

#### Description

DNS poses a serious threat as a Denial of Service (DOS) amplifier, if it responds to `ANY` queries. This Analytic Story can help you detect attackers who may be abusing your company's DNS infrastructure to launch amplification attacks, causing Denial of Service to other victims.

- **ID**: e8afd39e-3294-11e6-b39d-a45e60c6700
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)
- **Last Updated**: 2016-09-13
- **Author**: Bhavin Patel, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Large Volume of DNS ANY Queries](/network/large_volume_of_dns_any_queries/) | None | Anomaly |

#### Reference

* [https://www.us-cert.gov/ncas/alerts/TA13-088A](https://www.us-cert.gov/ncas/alerts/TA13-088A)
* [https://www.imperva.com/learn/application-security/dns-amplification/](https://www.imperva.com/learn/application-security/dns-amplification/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/dns_amplification_attacks.yml) \| *version*: **1**