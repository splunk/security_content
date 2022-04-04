---
title: "Linux System Network Discovery"
excerpt: "System Network Configuration Discovery
"
categories:
  - Endpoint
last_modified_at: 2022-02-11
toc: true
toc_label: ""
tags:
  - System Network Configuration Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to look for possible enumeration of local network configuration. This technique is commonly used as part of recon of adversaries or threat actor to know some network information for its next or further attack. This anomaly detections may capture normal event made by administrator during auditing or testing network connection of specific host or network to network.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-02-11
- **Author**: Teoderick Contreras, Splunk
- **ID**: 535cb214-8b47-11ec-a2c7-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1016](https://attack.mitre.org/techniques/T1016/) | System Network Configuration Discovery | Discovery |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Reconnaissance


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 5
* CIS 16



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` count values(Processes.process_name) as process_name_list values(Processes.process) as process_list values(Processes.process_id) as process_id_list values(Processes.parent_process_id) as parent_process_id_list values(Processes.process_guid) as process_guid_list dc(Processes.process_name) as process_name_count from datamodel=Endpoint.Processes where Processes.process_name IN ("arp", "ifconfig", "ip", "netstat", "firewall-cmd", "ufw", "iptables", "ss", "route") by _time span=30m Processes.dest Processes.user 
| where process_name_count >=4 
| `drop_dm_object_name(Processes)`
| `linux_system_network_discovery_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that **linux_system_network_discovery_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_id


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you can use the Add-on for Linux Sysmon from Splunkbase.

#### Known False Positives
Administrator or network operator can execute this command. Please update the filter macros to remove false positives.

#### Associated Analytic story
* [Network Discovery](/stories/network_discovery)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 9.0 | 30 | 30 | A commandline $process$ executed on $dest$ |


#### Reference

* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1016/atomic_red_team/linux_net_discovery/sysmon_linux.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1016/atomic_red_team/linux_net_discovery/sysmon_linux.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/linux_system_network_discovery.yml) \| *version*: **1**