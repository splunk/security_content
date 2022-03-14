---
title: "Command and Control"
last_modified_at: 2018-06-01
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Resolution
  - Network_Traffic
  - Actions on Objectives
  - Command & Control
  - Delivery
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Detect and investigate tactics, techniques, and procedures leveraged by attackers to establish and operate command and control channels. Implants installed by attackers on compromised endpoints use these channels to receive instructions and send data back to the malicious operators.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2018-06-01
- **Author**: Rico Valdez, Splunk
- **ID**: 943773c6-c4de-4f38-89a8-0b92f98804d8

#### Narrative

Threat actors typically architect and implement an infrastructure to use in various ways during the course of their attack campaigns. In some cases, they leverage this infrastructure for scanning and performing reconnaissance activities. In others, they may use this infrastructure to launch actual attacks. One of the most important functions of this infrastructure is to establish servers that will communicate with implants on compromised endpoints. These servers establish a command and control channel that is used to proxy data between the compromised endpoint and the attacker. These channels relay commands from the attacker to the compromised endpoint and the output of those commands back to the attacker.\
Because this communication is so critical for an adversary, they often use techniques designed to hide the true nature of the communications. There are many different techniques used to establish and communicate over these channels. This Analytic Story provides searches that look for a variety of the techniques used for these channels, as well as indications that these channels are active, by examining logs associated with border control devices and network-access control lists.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Clients Connecting to Multiple DNS Servers](/deprecated/clients_connecting_to_multiple_dns_servers/) | [Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](/tags/#exfiltration-over-unencrypted/obfuscated-non-c2-protocol)| TTP |
| [Detect Long DNS TXT Record Response](/deprecated/detect_long_dns_txt_record_response/) | [Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](/tags/#exfiltration-over-unencrypted/obfuscated-non-c2-protocol)| TTP |
| [Detection of DNS Tunnels](/deprecated/detection_of_dns_tunnels/) | [Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](/tags/#exfiltration-over-unencrypted/obfuscated-non-c2-protocol)| TTP |
| [DNS Query Requests Resolved by Unauthorized DNS Servers](/deprecated/dns_query_requests_resolved_by_unauthorized_dns_servers/) | [DNS](/tags/#dns)| TTP |
| [DNS Exfiltration Using Nslookup App](/endpoint/dns_exfiltration_using_nslookup_app/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol)| TTP |
| [Excessive Usage of NSLOOKUP App](/endpoint/excessive_usage_of_nslookup_app/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol)| Anomaly |
| [Detect Spike in blocked Outbound Traffic from your AWS](/cloud/detect_spike_in_blocked_outbound_traffic_from_your_aws/) | None| Anomaly |
| [Detect Large Outbound ICMP Packets](/network/detect_large_outbound_icmp_packets/) | [Non-Application Layer Protocol](/tags/#non-application-layer-protocol)| TTP |
| [DNS Query Length Outliers - MLTK](/network/dns_query_length_outliers_-_mltk/) | [DNS](/tags/#dns), [Application Layer Protocol](/tags/#application-layer-protocol)| Anomaly |
| [Excessive DNS Failures](/network/excessive_dns_failures/) | [DNS](/tags/#dns), [Application Layer Protocol](/tags/#application-layer-protocol)| Anomaly |
| [Prohibited Network Traffic Allowed](/network/prohibited_network_traffic_allowed/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol)| TTP |
| [Protocol or Port Mismatch](/network/protocol_or_port_mismatch/) | [Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](/tags/#exfiltration-over-unencrypted/obfuscated-non-c2-protocol), [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol)| Anomaly |
| [TOR Traffic](/network/tor_traffic/) | [Application Layer Protocol](/tags/#application-layer-protocol), [Web Protocols](/tags/#web-protocols)| TTP |
| [Detect hosts connecting to dynamic domain providers](/network/detect_hosts_connecting_to_dynamic_domain_providers/) | [Drive-by Compromise](/tags/#drive-by-compromise)| TTP |
| [DNS Query Length With High Standard Deviation](/network/dns_query_length_with_high_standard_deviation/) | [Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](/tags/#exfiltration-over-unencrypted/obfuscated-non-c2-protocol), [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol)| Anomaly |
| [Multiple Archive Files Http Post Traffic](/network/multiple_archive_files_http_post_traffic/) | [Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](/tags/#exfiltration-over-unencrypted/obfuscated-non-c2-protocol), [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol)| TTP |
| [Plain HTTP POST Exfiltrated Data](/network/plain_http_post_exfiltrated_data/) | [Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](/tags/#exfiltration-over-unencrypted/obfuscated-non-c2-protocol), [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol)| TTP |

#### Reference

* [https://attack.mitre.org/wiki/Command_and_Control](https://attack.mitre.org/wiki/Command_and_Control)
* [https://searchsecurity.techtarget.com/feature/Command-and-control-servers-The-puppet-masters-that-govern-malware](https://searchsecurity.techtarget.com/feature/Command-and-control-servers-The-puppet-masters-that-govern-malware)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/command_and_control.yml) \| *version*: **1**