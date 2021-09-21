---
title: "Router and Infrastructure Security"
last_modified_at: 2017-09-12
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Authentication
  - Network_Traffic
---

#### Description

Validate the security configuration of network infrastructure and verify that only authorized users and systems are accessing critical assets. Core routing and switching infrastructure are common strategic targets for attackers.

- **ID**: 91c676cf-0b23-438d-abee-f6335e177e77
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2017-09-12
- **Author**: Bhavin Patel, Splunk

#### Narrative

Networking devices, such as routers and switches, are often overlooked as resources that attackers will leverage to subvert an enterprise. Advanced threats actors have shown a proclivity to target these critical assets as a means to siphon and redirect network traffic, flash backdoored operating systems, and implement cryptographic weakened algorithms to more easily decrypt network traffic.\
This Analytic Story helps you gain a better understanding of how your network devices are interacting with your hosts. By compromising your network devices, attackers can obtain direct access to the company's internal infrastructure&#151; effectively increasing the attack surface and accessing private services/data.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect ARP Poisoning](/network/detect_arp_poisoning/) | None | TTP |
| [Detect IPv6 Network Infrastructure Threats](/network/detect_ipv6_network_infrastructure_threats/) | None | TTP |
| [Detect New Login Attempts to Routers](/application/detect_new_login_attempts_to_routers/) | None | TTP |
| [Detect Port Security Violation](/network/detect_port_security_violation/) | None | TTP |
| [Detect Rogue DHCP Server](/network/detect_rogue_dhcp_server/) | None | TTP |
| [Detect Software Download To Network Device](/network/detect_software_download_to_network_device/) | None | TTP |
| [Detect Traffic Mirroring](/network/detect_traffic_mirroring/) | None | TTP |

#### Reference

* [https://www.fireeye.com/blog/executive-perspective/2015/09/the_new_route_toper.html](https://www.fireeye.com/blog/executive-perspective/2015/09/the_new_route_toper.html)
* [https://www.cisco.com/c/en/us/about/security-center/event-response/synful-knock.html](https://www.cisco.com/c/en/us/about/security-center/event-response/synful-knock.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/router_and_infrastructure_security.yml) \| *version*: **1**