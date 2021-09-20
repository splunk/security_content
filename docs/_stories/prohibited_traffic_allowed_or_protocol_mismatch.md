---
title: "Prohibited Traffic Allowed or Protocol Mismatch"
last_modified_at: 2017-09-11
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Resolution
  - Network_Traffic
---

#### Description

Detect instances of prohibited network traffic allowed in the environment, as well as protocols running on non-standard ports. Both of these types of behaviors typically violate policy and can be leveraged by attackers.

- **ID**: 6d13121c-90f3-446d-8ac3-27efbbc65218
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2017-09-11
- **Author**: Rico Valdez, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Allow Inbound Traffic By Firewall Rule Registry](/endpoint/allow_inbound_traffic_by_firewall_rule_registry/) | None | TTP |
| [Allow Inbound Traffic In Firewall Rule](/endpoint/allow_inbound_traffic_in_firewall_rule/) | None | TTP |
| [Detect hosts connecting to dynamic domain providers](/network/detect_hosts_connecting_to_dynamic_domain_providers/) | None | TTP |
| [Enable RDP In Other Port Number](/endpoint/enable_rdp_in_other_port_number/) | None | TTP |
| [Prohibited Network Traffic Allowed](/network/prohibited_network_traffic_allowed/) | None | TTP |
| [Protocol or Port Mismatch](/network/protocol_or_port_mismatch/) | None | Anomaly |
| [TOR Traffic](/network/tor_traffic/) | None | TTP |

#### Kill Chain Phase



#### Reference

* [http://www.novetta.com/2015/02/advanced-methods-to-detect-advanced-cyber-attacks-protocol-abuse/](http://www.novetta.com/2015/02/advanced-methods-to-detect-advanced-cyber-attacks-protocol-abuse/)



_version_: 1