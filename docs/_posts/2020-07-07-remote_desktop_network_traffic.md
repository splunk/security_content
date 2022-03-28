---
title: "Remote Desktop Network Traffic"
excerpt: "Remote Desktop Protocol
, Remote Services
"
categories:
  - Network
last_modified_at: 2020-07-07
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
  - Network_Traffic
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for network traffic on TCP/3389, the default port used by remote desktop. While remote desktop traffic is not uncommon on a network, it is usually associated with known hosts. This search will ignore common RDP sources and common RDP destinations so you can focus on the uncommon uses of remote desktop on your network.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)

- **Last Updated**: 2020-07-07
- **Author**: David Dorsey, Splunk
- **ID**: 272b8407-842d-4b3d-bead-a704584003d3


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Desktop Protocol | Lateral Movement |

| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | Lateral Movement |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.dest_port=3389 AND All_Traffic.dest_category!=common_rdp_destination AND All_Traffic.src_category!=common_rdp_source by All_Traffic.src All_Traffic.dest All_Traffic.dest_port 
| `drop_dm_object_name("All_Traffic")` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `remote_desktop_network_traffic_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `remote_desktop_network_traffic_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* All_Traffic.dest_port
* All_Traffic.dest_category
* All_Traffic.src_category
* All_Traffic.src
* All_Traffic.dest
* All_Traffic.dest_port


#### How To Implement
To successfully implement this search you need to identify systems that commonly originate remote desktop traffic and that commonly receive remote desktop traffic. You can use the included support search "Identify Systems Creating Remote Desktop Traffic" to identify systems that originate the traffic and the search "Identify Systems Receiving Remote Desktop Traffic" to identify systems that receive a lot of remote desktop traffic. After identifying these systems, you will need to add the "common_rdp_source" or "common_rdp_destination" category to that system depending on the usage, using the Enterprise Security Assets and Identities framework.  This can be done by adding an entry in the assets.csv file located in SA-IdentityManagement/lookups.

#### Known False Positives
Remote Desktop may be used legitimately by users on the network.

#### Associated Analytic story
* [SamSam Ransomware](/stories/samsam_ransomware)
* [Ryuk Ransomware](/stories/ryuk_ransomware)
* [Hidden Cobra Malware](/stories/hidden_cobra_malware)
* [Active Directory Lateral Movement](/stories/active_directory_lateral_movement)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/remote_desktop_network_traffic.yml) \| *version*: **3**