---
title: "DNS Amplification Attacks"
last_modified_at: 2016-09-13
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Resolution
  - Actions on Objectives
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

DNS poses a serious threat as a Denial of Service (DOS) amplifier, if it responds to `ANY` queries. This Analytic Story can help you detect attackers who may be abusing your company's DNS infrastructure to launch amplification attacks, causing Denial of Service to other victims.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)
- **Last Updated**: 2016-09-13
- **Author**: Bhavin Patel, Splunk
- **ID**: a563972b-d2e2-4978-b6ca-6e83e24af4d3

#### Narrative

The Domain Name System (DNS) is the protocol used to map domain names to IP addresses. It has been proven to work very well for its intended function. However if DNS is misconfigured, servers can be abused by attackers to levy amplification or redirection attacks against victims. Because DNS responses to `ANY` queries are so much larger than the queries themselves--and can be made with a UDP packet, which does not require a handshake--attackers can spoof the source address of the packet and cause much more data to be sent to the victim than if they sent the traffic themselves. The `ANY` requests are will be larger than normal DNS server requests, due to the fact that the server provides significant details, such as MX records and associated IP addresses. A large volume of this traffic can result in a DOS on the victim's machine. This misconfiguration leads to two possible victims, the first being the DNS servers participating in an attack and the other being the hosts that are the targets of the DOS attack.\
The search in this story can help you to detect if attackers are abusing your company's DNS infrastructure to launch DNS amplification attacks causing Denial of Service to other victims.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Large Volume of DNS ANY Queries](/network/large_volume_of_dns_any_queries/) | [Network Denial of Service](/tags/#network-denial-of-service), [Reflection Amplification](/tags/#reflection-amplification)| Anomaly |

#### Reference

* [https://www.us-cert.gov/ncas/alerts/TA13-088A](https://www.us-cert.gov/ncas/alerts/TA13-088A)
* [https://www.imperva.com/learn/application-security/dns-amplification/](https://www.imperva.com/learn/application-security/dns-amplification/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/dns_amplification_attacks.yml) \| *version*: **1**