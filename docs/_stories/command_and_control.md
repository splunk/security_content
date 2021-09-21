---
title: "Command and Control"
last_modified_at: 2018-06-01
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

Detect and investigate tactics, techniques, and procedures leveraged by attackers to establish and operate command and control channels. Implants installed by attackers on compromised endpoints use these channels to receive instructions and send data back to the malicious operators.

- **ID**: 943773c6-c4de-4f38-89a8-0b92f98804d8
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2018-06-01
- **Author**: Rico Valdez, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [DNS Exfiltration Using Nslookup App](/endpoint/dns_exfiltration_using_nslookup_app/) | None | TTP |
| [DNS Query Length Outliers - MLTK](/network/dns_query_length_outliers_-_mltk/) | None | Anomaly |
| [DNS Query Length With High Standard Deviation](/network/dns_query_length_with_high_standard_deviation/) | None | Anomaly |
| [Detect Large Outbound ICMP Packets](/network/detect_large_outbound_icmp_packets/) | None | TTP |
| [Detect Spike in blocked Outbound Traffic from your AWS](/cloud/detect_spike_in_blocked_outbound_traffic_from_your_aws/) | None | Anomaly |
| [Detect hosts connecting to dynamic domain providers](/network/detect_hosts_connecting_to_dynamic_domain_providers/) | None | TTP |
| [Excessive DNS Failures](/network/excessive_dns_failures/) | None | Anomaly |
| [Excessive Usage of NSLOOKUP App](/endpoint/excessive_usage_of_nslookup_app/) | None | Anomaly |
| [Multiple Archive Files Http Post Traffic](/network/multiple_archive_files_http_post_traffic/) | None | TTP |
| [Plain HTTP POST Exfiltrated Data](/network/plain_http_post_exfiltrated_data/) | None | TTP |
| [Prohibited Network Traffic Allowed](/network/prohibited_network_traffic_allowed/) | None | TTP |
| [Protocol or Port Mismatch](/network/protocol_or_port_mismatch/) | None | Anomaly |
| [TOR Traffic](/network/tor_traffic/) | None | TTP |

#### Reference

* [https://attack.mitre.org/wiki/Command_and_Control](https://attack.mitre.org/wiki/Command_and_Control)
* [https://searchsecurity.techtarget.com/feature/Command-and-control-servers-The-puppet-masters-that-govern-malware](https://searchsecurity.techtarget.com/feature/Command-and-control-servers-The-puppet-masters-that-govern-malware)



[_source_](https://github.com/splunk/security_content/tree/develop/stories/command_and_control.yml) | _version_: **1**