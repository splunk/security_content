---
title: "Detect Outbound SMB Traffic"
excerpt: "File Transfer Protocols
, Application Layer Protocol
"
categories:
  - Network
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - File Transfer Protocols
  - Application Layer Protocol
  - Command And Control
  - Command And Control
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Traffic
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for outbound SMB connections made by hosts within your network to the Internet. SMB traffic is used for Windows file-sharing activity. One of the techniques often used by attackers involves retrieving the credential hash using an SMB request made to a compromised server controlled by the threat actor.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2020-07-21
- **Author**: Bhavin Patel, Stuart Hopkins from Splunk
- **ID**: 1bed7774-304a-4e8f-9d72-d80e45ff492b


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1071.002](https://attack.mitre.org/techniques/T1071/002/) | File Transfer Protocols | Command And Control |

| [T1071](https://attack.mitre.org/techniques/T1071/) | Application Layer Protocol | Command And Control |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Actions on Objectives
* Command & Control


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

* CIS 12



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` earliest(_time) as start_time latest(_time) as end_time values(All_Traffic.action) as action values(All_Traffic.app) as app values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port values(sourcetype) as sourcetype count from datamodel=Network_Traffic where ((All_Traffic.dest_port=139 OR All_Traffic.dest_port=445 OR All_Traffic.app="smb") AND NOT (All_Traffic.action="blocked" OR All_Traffic.dest_category="internal" OR All_Traffic.dest_ip=10.0.0.0/8 OR All_Traffic.dest_ip=172.16.0.0/12 OR All_Traffic.dest_ip=192.168.0.0/16 OR All_Traffic.dest_ip=100.64.0.0/10)) by All_Traffic.src_ip 
| `drop_dm_object_name("All_Traffic")` 
| `security_content_ctime(start_time)` 
| `security_content_ctime(end_time)` 
| `detect_outbound_smb_traffic_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **detect_outbound_smb_traffic_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* All_Traffic.action
* All_Traffic.app
* All_Traffic.dest_ip
* All_Traffic.dest_port
* sourcetype
* All_Traffic.dest_category
* All_Traffic.src_ip


#### How To Implement
In order to run this search effectively, we highly recommend that you leverage the Assets and Identity framework. It is important that you have good understanding of how your network segments are designed, and be able to distinguish internal from external address space. Add a category named `internal` to the CIDRs that host the companys assets in `assets_by_cidr.csv` lookup file, which is located in `$SPLUNK_HOME/etc/apps/SA-IdentityManagement/lookups/`. More information on updating this lookup can be found here: https://docs.splunk.com/Documentation/ES/5.0.0/Admin/Addassetandidentitydata. This search also requires you to be ingesting your network traffic and populating the Network_Traffic data model

#### Known False Positives
It is likely that the outbound Server Message Block (SMB) traffic is legitimate, if the company's internal networks are not well-defined in the Assets and Identity Framework. Categorize the internal CIDR blocks as `internal` in the lookup file to avoid creating notable events for traffic destined to those CIDR blocks. Any other network connection that is going out to the Internet should be investigated and blocked. Best practices suggest preventing external communications of all SMB versions and related protocols at the network boundary.

#### Associated Analytic story
* [Hidden Cobra Malware](/stories/hidden_cobra_malware)
* [DHS Report TA18-074A](/stories/dhs_report_ta18-074a)
* [NOBELIUM Group](/stories/nobelium_group)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/detect_outbound_smb_traffic.yml) \| *version*: **3**