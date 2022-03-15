---
title: "Suspicious DNS Traffic"
last_modified_at: 2017-09-18
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Resolution
  - Actions on Objectives
  - Command & Control
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Attackers often attempt to hide within or otherwise abuse the domain name system (DNS). You can thwart attempts to manipulate this omnipresent protocol by monitoring for these types of abuses.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)
- **Last Updated**: 2017-09-18
- **Author**: Rico Valdez, Splunk
- **ID**: 3c3835c0-255d-4f9e-ab84-e29ec9ec9b56

#### Narrative

Although DNS is one of the fundamental underlying protocols that make the Internet work, it is often ignored (perhaps because of its complexity and effectiveness).  However, attackers have discovered ways to abuse the protocol to meet their objectives. One potential abuse involves manipulating DNS to hijack traffic and redirect it to an IP address under the attacker's control. This could inadvertently send users intending to visit google.com, for example, to an unrelated malicious website. Another technique involves using the DNS protocol for command-and-control activities with the attacker's malicious code or to covertly exfiltrate data. The searches within this Analytic Story look for these types of abuses.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Clients Connecting to Multiple DNS Servers](/deprecated/clients_connecting_to_multiple_dns_servers/) | [Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](/tags/#exfiltration-over-unencrypted/obfuscated-non-c2-protocol)| TTP |
| [Detect Long DNS TXT Record Response](/deprecated/detect_long_dns_txt_record_response/) | [Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](/tags/#exfiltration-over-unencrypted/obfuscated-non-c2-protocol)| TTP |
| [Detection of DNS Tunnels](/deprecated/detection_of_dns_tunnels/) | [Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](/tags/#exfiltration-over-unencrypted/obfuscated-non-c2-protocol)| TTP |
| [DNS Query Requests Resolved by Unauthorized DNS Servers](/deprecated/dns_query_requests_resolved_by_unauthorized_dns_servers/) | [DNS](/tags/#dns)| TTP |
| [DNS Exfiltration Using Nslookup App](/endpoint/dns_exfiltration_using_nslookup_app/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol)| TTP |
| [Excessive Usage of NSLOOKUP App](/endpoint/excessive_usage_of_nslookup_app/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol)| Anomaly |
| [DNS Query Length Outliers - MLTK](/network/dns_query_length_outliers_-_mltk/) | [DNS](/tags/#dns), [Application Layer Protocol](/tags/#application-layer-protocol)| Anomaly |
| [Excessive DNS Failures](/network/excessive_dns_failures/) | [DNS](/tags/#dns), [Application Layer Protocol](/tags/#application-layer-protocol)| Anomaly |
| [Detect hosts connecting to dynamic domain providers](/network/detect_hosts_connecting_to_dynamic_domain_providers/) | [Drive-by Compromise](/tags/#drive-by-compromise)| TTP |
| [DNS Query Length With High Standard Deviation](/network/dns_query_length_with_high_standard_deviation/) | [Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](/tags/#exfiltration-over-unencrypted/obfuscated-non-c2-protocol), [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol)| Anomaly |

#### Reference

* [http://blogs.splunk.com/2015/10/01/random-words-on-entropy-and-dns/](http://blogs.splunk.com/2015/10/01/random-words-on-entropy-and-dns/)
* [http://www.darkreading.com/analytics/security-monitoring/got-malware-three-signs-revealed-in-dns-traffic/d/d-id/1139680](http://www.darkreading.com/analytics/security-monitoring/got-malware-three-signs-revealed-in-dns-traffic/d/d-id/1139680)
* [https://live.paloaltonetworks.com/t5/Threat-Vulnerability-Articles/What-are-suspicious-DNS-queries/ta-p/71454](https://live.paloaltonetworks.com/t5/Threat-Vulnerability-Articles/What-are-suspicious-DNS-queries/ta-p/71454)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_dns_traffic.yml) \| *version*: **1**