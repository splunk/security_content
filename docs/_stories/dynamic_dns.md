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

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Detect and investigate hosts in your environment that may be communicating with dynamic domain providers. Attackers may leverage these services to help them avoid firewall blocks and deny lists.

- **ID**: 8169f17b-ef68-4b59-aae8-586907301221
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)
- **Last Updated**: 2018-09-06
- **Author**: Bhavin Patel, Splunk

#### Narrative

Dynamic DNS services (DDNS) are legitimate low-cost or free services that allow users to rapidly update domain resolutions to IP infrastructure. While their usage can be benign, malicious actors can abuse DDNS to host harmful payloads or interactive-command-and-control infrastructure. These attackers will manually update or automate domain resolution changes by routing dynamic domains to IP addresses that circumvent firewall blocks and deny lists and frustrate a network defender's analytic and investigative processes. These searches will look for DNS queries made from within your infrastructure to suspicious dynamic domains and then investigate more deeply, when appropriate. While this list of top-level dynamic domains is not exhaustive, it can be dynamically updated as new suspicious dynamic domains are identified.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [DNS Exfiltration Using Nslookup App](/endpoint/dns_exfiltration_using_nslookup_app/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol), [DNS](/tags/#dns), [Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](/tags/#exfiltration-over-unencrypted/obfuscated-non-c2-protocol), [Non-Application Layer Protocol](/tags/#non-application-layer-protocol), [Exfiltration Over C2 Channel](/tags/#exfiltration-over-c2-channel), [Drive-by Compromise](/tags/#drive-by-compromise), [Transfer Data to Cloud Account](/tags/#transfer-data-to-cloud-account), [Local Email Collection](/tags/#local-email-collection), [Email Collection](/tags/#email-collection), [Email Forwarding Rule](/tags/#email-forwarding-rule), [Web Protocols](/tags/#web-protocols) | TTP |
| [Detect hosts connecting to dynamic domain providers](/network/detect_hosts_connecting_to_dynamic_domain_providers/) | [Drive-by Compromise](/tags/#drive-by-compromise) | TTP |
| [Excessive Usage of NSLOOKUP App](/endpoint/excessive_usage_of_nslookup_app/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | Anomaly |

#### Reference

* [https://www.fireeye.com/blog/threat-research/2017/09/apt33-insights-into-iranian-cyber-espionage.html](https://www.fireeye.com/blog/threat-research/2017/09/apt33-insights-into-iranian-cyber-espionage.html)
* [https://umbrella.cisco.com/blog/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/](https://umbrella.cisco.com/blog/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/)
* [http://www.noip.com/blog/2014/07/11/dynamic-dns-can-use-2/](http://www.noip.com/blog/2014/07/11/dynamic-dns-can-use-2/)
* [https://www.splunk.com/blog/2015/08/04/detecting-dynamic-dns-domains-in-splunk.html](https://www.splunk.com/blog/2015/08/04/detecting-dynamic-dns-domains-in-splunk.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/dynamic_dns.yml) \| *version*: **2**