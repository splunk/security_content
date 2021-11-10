---
title: "Allow Inbound Traffic By Firewall Rule Registry"
excerpt: "Remote Desktop Protocol, Remote Services"
categories:
  - Endpoint
last_modified_at: 2021-05-26
toc: true
toc_label: ""
tags:
  - Remote Desktop Protocol
  - Lateral Movement
  - Remote Services
  - Lateral Movement
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic detects a potential suspicious modification of firewall rule registry allowing inbound traffic in specific port with public profile. This technique was identified when an adversary wants to grant remote access to a machine by allowing the traffic in a firewall rule.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-26
- **Author**: Teoderick Contreras, Splunk
- **ID**: 0a46537c-be02-11eb-92ca-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Desktop Protocol | Lateral Movement |

| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | Lateral Movement |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path= "*\\System\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules\\*" Registry.registry_value_name = "*
|Action=Allow
|*" Registry.registry_value_name = "*
|Dir=In
|*" Registry.registry_value_name = "*
|Profile=Public
|*" Registry.registry_value_name = "*
|LPort=*" by Registry.registry_path Registry.registry_key_name Registry.user Registry.registry_value_name Registry.dest 
| `drop_dm_object_name(Registry)` 
| `security_content_ctime(firstTime)` 
|`security_content_ctime(lastTime)` 
| `allow_inbound_traffic_by_firewall_rule_registry_filter`
```

#### Associated Analytic Story
* [Prohibited Traffic Allowed or Protocol Mismatch](/stories/prohibited_traffic_allowed_or_protocol_mismatch)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Registry` node. Also make sure that this registry was included in your config files ex. sysmon config to be monitored.

#### Required field
* _time
* Registry.registry_path
* Registry.registry_value_name
* Registry.registry_key_name
* Registry.dest
* Registry.user


#### Kill Chain Phase
* Exploitation


#### Known False Positives
network admin may add/remove/modify public inbound firewall rule that may cause this rule to be triggered.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 3.0 | 10 | 30 | Suspicious firewall modifications were detected via the registry on endpoint $dest$ by user $user$. |




#### Reference

* [https://docs.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule?view=windowsserver2019-ps](https://docs.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule?view=windowsserver2019-ps)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/honeypots/casper/datasets1/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/honeypots/casper/datasets1/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/allow_inbound_traffic_by_firewall_rule_registry.yml) \| *version*: **1**