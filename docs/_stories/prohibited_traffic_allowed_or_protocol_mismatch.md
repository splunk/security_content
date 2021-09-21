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

#### Narrative

A traditional security best practice is to control the ports, protocols, and services allowed within your environment. By limiting the services and protocols to those explicitly approved by policy, administrators can minimize the attack surface. The combined effect allows both network defenders and security controls to focus and not be mired in superfluous traffic or data types. Looking for deviations to policy can identify attacker activity that abuses services and protocols to run on alternate or non-standard ports in the attempt to avoid detection or frustrate forensic analysts.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Allow Inbound Traffic By Firewall Rule Registry](/endpoint/allow_inbound_traffic_by_firewall_rule_registry/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Drive-by Compromise](/tags/#drive-by-compromise), [Remote Services](/tags/#remote-services), [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol), [Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](/tags/#exfiltration-over-unencrypted/obfuscated-non-c2-protocol), [Web Protocols](/tags/#web-protocols) | TTP |
| [Allow Inbound Traffic In Firewall Rule](/endpoint/allow_inbound_traffic_in_firewall_rule/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol) | TTP |
| [Detect hosts connecting to dynamic domain providers](/network/detect_hosts_connecting_to_dynamic_domain_providers/) | [Drive-by Compromise](/tags/#drive-by-compromise) | TTP |
| [Enable RDP In Other Port Number](/endpoint/enable_rdp_in_other_port_number/) | [Remote Services](/tags/#remote-services) | TTP |
| [Prohibited Network Traffic Allowed](/network/prohibited_network_traffic_allowed/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | TTP |
| [Protocol or Port Mismatch](/network/protocol_or_port_mismatch/) | [Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](/tags/#exfiltration-over-unencrypted/obfuscated-non-c2-protocol) | Anomaly |
| [TOR Traffic](/network/tor_traffic/) | [Web Protocols](/tags/#web-protocols) | TTP |

#### Reference

* [http://www.novetta.com/2015/02/advanced-methods-to-detect-advanced-cyber-attacks-protocol-abuse/](http://www.novetta.com/2015/02/advanced-methods-to-detect-advanced-cyber-attacks-protocol-abuse/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/prohibited_traffic_allowed_or_protocol_mismatch.yml) \| *version*: **1**