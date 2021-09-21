---
title: "Data Protection"
last_modified_at: 2017-09-14
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Resolution
---

#### Description

Fortify your data-protection arsenal--while continuing to ensure data confidentiality and integrity--with searches that monitor for and help you investigate possible signs of data exfiltration.

- **ID**: 91c676cf-0b23-438d-abee-f6335e1fce33
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)
- **Last Updated**: 2017-09-14
- **Author**: Bhavin Patel, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect hosts connecting to dynamic domain providers](/network/detect_hosts_connecting_to_dynamic_domain_providers/) | None | TTP |

#### Reference

* [https://www.cisecurity.org/controls/data-protection/](https://www.cisecurity.org/controls/data-protection/)
* [https://www.sans.org/reading-room/whitepapers/dns/splunk-detect-dns-tunneling-37022](https://www.sans.org/reading-room/whitepapers/dns/splunk-detect-dns-tunneling-37022)
* [https://umbrella.cisco.com/blog/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/](https://umbrella.cisco.com/blog/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/)



[_source_](https://github.com/splunk/security_content/tree/develop/stories/data_protection.yml) | _version_: **1**