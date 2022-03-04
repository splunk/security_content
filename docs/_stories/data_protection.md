---
title: "Data Protection"
last_modified_at: 2017-09-14
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Resolution
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Fortify your data-protection arsenal--while continuing to ensure data confidentiality and integrity--with searches that monitor for and help you investigate possible signs of data exfiltration.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)
- **Last Updated**: 2017-09-14
- **Author**: Bhavin Patel, Splunk
- **ID**: 91c676cf-0b23-438d-abee-f6335e1fce33

#### Narrative

Attackers can leverage a variety of resources to compromise or exfiltrate enterprise data. Common exfiltration techniques include remote-access channels via low-risk, high-payoff active-collections operations and close-access operations using insiders and removable media. While this Analytic Story is not a comprehensive listing of all the methods by which attackers can exfiltrate data, it provides a useful starting point.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect hosts connecting to dynamic domain providers](/network/detect_hosts_connecting_to_dynamic_domain_providers/) | [Drive-by Compromise](/tags/#drive-by-compromise) | TTP |

#### Reference

* [https://www.cisecurity.org/controls/data-protection/](https://www.cisecurity.org/controls/data-protection/)
* [https://www.sans.org/reading-room/whitepapers/dns/splunk-detect-dns-tunneling-37022](https://www.sans.org/reading-room/whitepapers/dns/splunk-detect-dns-tunneling-37022)
* [https://umbrella.cisco.com/blog/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/](https://umbrella.cisco.com/blog/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/data_protection.yml) \| *version*: **1**