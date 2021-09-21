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

#### Detection profiles

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