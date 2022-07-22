---
title: "Use of Cleartext Protocols"
last_modified_at: 2017-09-15
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Traffic
  - Actions on Objectives
  - Reconnaissance
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that detect cleartext network protocols that may leak credentials or should otherwise be encrypted.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2017-09-15
- **Author**: Bhavin Patel, Splunk
- **ID**: 826e6431-aeef-41b4-9fc0-6d0985d65a21

#### Narrative

Various legacy protocols operate by default in the clear, without the protections of encryption. This potentially leaks sensitive information that can be exploited by passively sniffing network traffic. Depending on the protocol, this information could be highly sensitive, or could allow for session hijacking. In addition, these protocols send authentication information, which would allow for the harvesting of usernames and passwords that could potentially be used to authenticate and compromise secondary systems.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Protocols passing authentication in cleartext](/network/protocols_passing_authentication_in_cleartext/) | None| TTP |

#### Reference

* [https://www.monkey.org/~dugsong/dsniff/](https://www.monkey.org/~dugsong/dsniff/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/use_of_cleartext_protocols.yml) \| *version*: **1**