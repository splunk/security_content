---
title: "Protocol or Port Mismatch"
excerpt: "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol"
categories:
  - Network
last_modified_at: 2020-07-21
toc: true
tags:
  - Anomaly
  - T1048.003
  - Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol
  - Exfiltration
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Traffic
  - Command and Control
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate or build datasets for it, use at your own risk!


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for network traffic on common ports where a higher layer protocol does not match the port that is being used. For example, this search should identify cases where protocols other than HTTP are running on TCP port 80. This can be used by attackers to circumvent firewall restrictions, or as an attempt to hide malicious communications over ports and protocols that are typically allowed and not well inspected.

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2020-07-21
- **Author**: Rico Valdez, Splunk
- **ID**: 54dc1265-2f74-4b6d-b30d-49eb506a31b3


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1048.003](https://attack.mitre.org/techniques/T1048/003/) | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | Exfiltration |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where (All_Traffic.app=dns NOT All_Traffic.dest_port=53) OR ((All_Traffic.app=web-browsing OR All_Traffic.app=http) NOT (All_Traffic.dest_port=80 OR All_Traffic.dest_port=8080 OR All_Traffic.dest_port=8000)) OR (All_Traffic.app=ssl NOT (All_Traffic.dest_port=443 OR All_Traffic.dest_port=8443)) OR (All_Traffic.app=smtp NOT All_Traffic.dest_port=25) by All_Traffic.src_ip, All_Traffic.dest_ip, All_Traffic.app, All_Traffic.dest_port 
|`security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `drop_dm_object_name("All_Traffic")` 
| `protocol_or_port_mismatch_filter`
```

#### Associated Analytic Story
* [Prohibited Traffic Allowed or Protocol Mismatch](/stories/prohibited_traffic_allowed_or_protocol_mismatch)
* [Command and Control](/stories/command_and_control)


#### How To Implement
Running this search properly requires a technology that can inspect network traffic and identify common protocols. Technologies such as Bro and Palo Alto Networks firewalls are two examples that will identify protocols via inspection, and not just assume a specific protocol based on the transport protocol and ports.

#### Required field
* _time
* All_Traffic.app
* All_Traffic.dest_port
* All_Traffic.src_ip
* All_Traffic.dest_ip


#### Kill Chain Phase
* Command and Control


#### Known False Positives
None identified




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/protocol_or_port_mismatch.yml) \| *version*: **2**