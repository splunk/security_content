---
title: "Detect Software Download To Network Device"
excerpt: "TFTP Boot, Pre-OS Boot"
categories:
  - Network
last_modified_at: 2020-10-28
toc: true
toc_label: ""
tags:
  - TFTP Boot
  - Defense Evasion
  - Persistence
  - Pre-OS Boot
  - Defense Evasion
  - Persistence
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Traffic
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Adversaries may abuse netbooting to load an unauthorized network device operating system from a Trivial File Transfer Protocol (TFTP) server. TFTP boot (netbooting) is commonly used by network administrators to load configuration-controlled network device images from a centralized management server. Netbooting is one option in the boot sequence and can be used to centralize, manage, and control device images.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2020-10-28
- **Author**: Mikael Bjerkeland, Splunk
- **ID**: cc590c66-f65f-48f2-986a-4797244762f8


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1542.005](https://attack.mitre.org/techniques/T1542/005/) | TFTP Boot | Defense Evasion, Persistence |

| [T1542](https://attack.mitre.org/techniques/T1542/) | Pre-OS Boot | Defense Evasion, Persistence |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where (All_Traffic.transport=udp AND All_Traffic.dest_port=69) OR (All_Traffic.transport=tcp AND All_Traffic.dest_port=21) OR (All_Traffic.transport=tcp AND All_Traffic.dest_port=22) AND All_Traffic.dest_category!=common_software_repo_destination AND All_Traffic.src_category=network OR All_Traffic.src_category=router OR All_Traffic.src_category=switch by All_Traffic.src All_Traffic.dest All_Traffic.dest_port 
| `drop_dm_object_name("All_Traffic")` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `detect_software_download_to_network_device_filter`
```

#### Associated Analytic Story
* [Router and Infrastructure Security](/stories/router_and_infrastructure_security)


#### How To Implement
This search looks for Network Traffic events to TFTP, FTP or SSH/SCP ports from network devices. Make sure to tag any network devices as network, router or switch in order for this detection to work. If the TFTP traffic doesn&#39;t traverse a firewall nor packet inspection, these events will not be logged. This is typically an issue if the TFTP server is on the same subnet as the network device. There is also a chance of the network device loading software using a DHCP assigned IP address (netboot) which is not in the Asset inventory.

#### Required field
* _time
* All_Traffic.transport
* All_Traffic.dest_port
* All_Traffic.dest_category
* All_Traffic.src_category
* All_Traffic.src
* All_Traffic.dest


#### Kill Chain Phase
* Delivery


#### Known False Positives
This search will also report any legitimate attempts of software downloads to network devices as well as outbound SSH sessions from network devices.





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/detect_software_download_to_network_device.yml) \| *version*: **1**