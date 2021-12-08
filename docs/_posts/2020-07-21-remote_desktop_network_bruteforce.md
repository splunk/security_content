---
title: "Remote Desktop Network Bruteforce"
excerpt: "Remote Desktop Protocol, Remote Services"
categories:
  - Network
last_modified_at: 2020-07-21
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
  - Network_Traffic
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate or build datasets for it, use at your own risk!


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for RDP application network traffic and filters any source/destination pair generating more than twice the standard deviation of the average traffic.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2020-07-21
- **Author**: Jose Hernandez, Splunk
- **ID**: a98727cc-286b-4ff2-b898-41df64695923


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Desktop Protocol | Lateral Movement |

| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | Lateral Movement |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.app=rdp by All_Traffic.src All_Traffic.dest All_Traffic.dest_port 
| eventstats stdev(count) AS stdev avg(count) AS avg p50(count) AS p50 
| where count>(avg + stdev*2) 
| rename All_Traffic.src AS src All_Traffic.dest AS dest 
| table firstTime lastTime src dest count avg p50 stdev 
| `remote_desktop_network_bruteforce_filter`
```

#### Associated Analytic Story
* [SamSam Ransomware](/stories/samsam_ransomware)
* [Ryuk Ransomware](/stories/ryuk_ransomware)


#### How To Implement
You must ensure that your network traffic data is populating the Network_Traffic data model.

#### Required field
* _time
* All_Traffic.app
* All_Traffic.src
* All_Traffic.dest
* All_Traffic.dest_port


#### Kill Chain Phase
* Reconnaissance
* Delivery


#### Known False Positives
RDP gateways may have unusually high amounts of traffic from all other hosts&#39; RDP applications in the network.





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/remote_desktop_network_bruteforce.yml) \| *version*: **2**