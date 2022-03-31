---
title: "Allow Inbound Traffic In Firewall Rule"
excerpt: "Remote Desktop Protocol
, Remote Services
"
categories:
  - Endpoint
last_modified_at: 2021-05-19
toc: true
toc_label: ""
tags:
  - Remote Desktop Protocol
  - Remote Services
  - Lateral Movement
  - Lateral Movement
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies suspicious PowerShell command to allow inbound traffic inbound to a specific local port within the public profile. This technique was seen in some attacker want to have a remote access to a machine by allowing the traffic in firewall rule.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-05-19
- **Author**: Teoderick Contreras, Splunk
- **ID**: a5d85486-b89c-11eb-8267-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Desktop Protocol | Lateral Movement |

| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | Lateral Movement |

#### Search

```
`powershell` EventCode=4104 Message = "*firewall*" Message = "*Inbound*" Message = "*Allow*"  Message = "*-LocalPort*" 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Message ComputerName User 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `allow_inbound_traffic_in_firewall_rule_filter`
```

#### Macros
The SPL above uses the following Macros:
* [powershell](https://github.com/splunk/security_content/blob/develop/macros/powershell.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `allow_inbound_traffic_in_firewall_rule_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* Message
* ComputerName
* User


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the powershell logs  from your endpoints. make sure you enable needed registry to monitor this event.

#### Known False Positives
administrator may allow inbound traffic in certain network or machine.

#### Associated Analytic story
* [Prohibited Traffic Allowed or Protocol Mismatch](/stories/prohibited_traffic_allowed_or_protocol_mismatch)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 3.0 | 10 | 30 | Suspicious firewall modification detected on endpoint $ComputerName$ by user $user$. |




#### Reference

* [https://docs.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule?view=windowsserver2019-ps](https://docs.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule?view=windowsserver2019-ps)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/honeypots/casper/datasets1/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/honeypots/casper/datasets1/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/allow_inbound_traffic_in_firewall_rule.yml) \| *version*: **1**