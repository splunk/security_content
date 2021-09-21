---
title: "Use of Cleartext Protocols"
last_modified_at: 2017-09-15
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Traffic
---

#### Description

Leverage searches that detect cleartext network protocols that may leak credentials or should otherwise be encrypted.

- **ID**: 826e6431-aeef-41b4-9fc0-6d0985d65a21
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2017-09-15
- **Author**: Bhavin Patel, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Protocols passing authentication in cleartext](/network/protocols_passing_authentication_in_cleartext/) | None | TTP |

#### Reference

* [https://www.monkey.org/~dugsong/dsniff/](https://www.monkey.org/~dugsong/dsniff/)



[_source_](https://github.com/splunk/security_content/tree/develop/stories/use_of_cleartext_protocols.yml) | _version_: **1**