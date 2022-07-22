---
title: "Network Discovery"
last_modified_at: 2022-02-14
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Reconnaissance
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the network discovery, including looking for network configuration, settings such as IP, MAC address, firewall settings and many more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-02-14
- **Author**: Teoderick Contreras, Splunk
- **ID**: af228995-f182-49d7-90b3-2a732944f00f

#### Narrative

Adversaries may use the information from System Network Configuration Discovery during automated discovery to shape follow-on behaviors, including determining certain access within the target network and what actions to do next.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Linux System Network Discovery](/endpoint/linux_system_network_discovery/) | [System Network Configuration Discovery](/tags/#system-network-configuration-discovery)| Anomaly |

#### Reference

* [https://attack.mitre.org/techniques/T1016/](https://attack.mitre.org/techniques/T1016/)
* [https://www.welivesecurity.com/wp-content/uploads/2021/01/ESET_Kobalos.pdf](https://www.welivesecurity.com/wp-content/uploads/2021/01/ESET_Kobalos.pdf)
* [https://researchcenter.paloaltonetworks.com/2018/09/unit42-xbash-combines-botnet-ransomware-coinmining-worm-targets-linux-windows/](https://researchcenter.paloaltonetworks.com/2018/09/unit42-xbash-combines-botnet-ransomware-coinmining-worm-targets-linux-windows/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/network_discovery.yml) \| *version*: **1**