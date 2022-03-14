---
title: "Windows Discovery Techniques"
last_modified_at: 2021-03-04
toc: true
toc_label: ""
tags:
  - Splunk Behavioral Analytics
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Reconnaissance
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitors for behaviors associated with adversaries discovering objects in the environment that can be leveraged in the progression of the attack.

- **Product**: Splunk Behavioral Analytics, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-03-04
- **Author**: Michael Hart, Splunk
- **ID**: f7aba570-7d59-11eb-825e-acde48001122

#### Narrative

Attackers may not have much if any insight into their target's environment before the initial compromise.  Once a foothold has been established, attackers will start enumerating objects in the environment (accounts, services, network shares, etc.) that can be used to achieve their objectives.  This Analytic Story provides searches to help identify activities consistent with adversaries gaining knowledge of compromised Windows environments.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Net Localgroup Discovery](/endpoint/net_localgroup_discovery/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups)| Hunting |

#### Reference

* [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)
* [https://cyberd.us/penetration-testing](https://cyberd.us/penetration-testing)
* [https://attack.mitre.org/software/S0521/](https://attack.mitre.org/software/S0521/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_discovery_techniques.yml) \| *version*: **1**