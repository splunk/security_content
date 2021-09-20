---
title: "Dynamic DNS"
last_modified_at: 2018-09-06
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Resolution
---

#### Description

Detect and investigate hosts in your environment that may be communicating with dynamic domain providers. Attackers may leverage these services to help them avoid firewall blocks and deny lists.

- **ID**: 8169f17b-ef68-4b59-aae8-586907301221
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)
- **Last Updated**: 2018-09-06
- **Author**: Bhavin Patel, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [DNS Exfiltration Using Nslookup App](/endpoint/dns_exfiltration_using_nslookup_app/) | None | TTP |
| [Detect hosts connecting to dynamic domain providers](/network/detect_hosts_connecting_to_dynamic_domain_providers/) | None | TTP |
| [Excessive Usage of NSLOOKUP App](/endpoint/excessive_usage_of_nslookup_app/) | None | Anomaly |

#### Kill Chain Phase



#### Reference

* [https://www.fireeye.com/blog/threat-research/2017/09/apt33-insights-into-iranian-cyber-espionage.html](https://www.fireeye.com/blog/threat-research/2017/09/apt33-insights-into-iranian-cyber-espionage.html)
* [https://umbrella.cisco.com/blog/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/](https://umbrella.cisco.com/blog/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/)
* [http://www.noip.com/blog/2014/07/11/dynamic-dns-can-use-2/](http://www.noip.com/blog/2014/07/11/dynamic-dns-can-use-2/)
* [https://www.splunk.com/blog/2015/08/04/detecting-dynamic-dns-domains-in-splunk.html](https://www.splunk.com/blog/2015/08/04/detecting-dynamic-dns-domains-in-splunk.html)



_version_: 2