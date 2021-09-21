---
title: "Meterpreter"
last_modified_at: 2021-06-08
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Meterpreter provides red teams, pen testers and threat actors interactive access to a compromised host to run commands, upload payloads, download files, and other actions.

- **ID**: d5f8e298-c85a-11eb-9fea-acde48001122
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-06-08
- **Author**: Michael Hart

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Excessive number of taskhost processes](/endpoint/excessive_number_of_taskhost_processes/) | None | Anomaly |

#### Reference

* [https://www.offensive-security.com/metasploit-unleashed/about-meterpreter/](https://www.offensive-security.com/metasploit-unleashed/about-meterpreter/)
* [https://doubleoctopus.com/security-wiki/threats-and-tools/meterpreter/](https://doubleoctopus.com/security-wiki/threats-and-tools/meterpreter/)
* [https://www.rapid7.com/products/metasploit/](https://www.rapid7.com/products/metasploit/)



[_source_](https://github.com/splunk/security_content/tree/develop/stories/meterpreter.yml) | _version_: **1**