---
title: "Detect Large Outbound ICMP Packets"
excerpt: "Non-Application Layer Protocol
"
categories:
  - Network
last_modified_at: 2018-06-01
toc: true
toc_label: ""
tags:
  - Non-Application Layer Protocol
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

This search looks for outbound ICMP packets with a packet size larger than 1,000 bytes. Various threat actors have been known to use ICMP as a command and control channel for their attack infrastructure. Large ICMP packets from an endpoint to a remote host may be indicative of this activity.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2018-06-01
- **Author**: Rico Valdez, Splunk
- **ID**: e9c102de-4d43-42a7-b1c8-8062ea297419


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol | Command And Control |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Command & Control


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* DE.AE



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 9
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

| tstats `security_content_summariesonly` count earliest(_time) as firstTime latest(_time) as lastTime values(All_Traffic.action) values(All_Traffic.bytes) from datamodel=Network_Traffic where All_Traffic.action !=blocked All_Traffic.dest_category !=internal (All_Traffic.protocol=icmp OR All_Traffic.transport=icmp) All_Traffic.bytes > 1000 by All_Traffic.src_ip All_Traffic.dest_ip 
| `drop_dm_object_name("All_Traffic")` 
| search ( dest_ip!=10.0.0.0/8 AND dest_ip!=172.16.0.0/12 AND dest_ip!=192.168.0.0/16) 
| `security_content_ctime(firstTime)`
|`security_content_ctime(lastTime)` 
| `detect_large_outbound_icmp_packets_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **detect_large_outbound_icmp_packets_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* All_Traffic.action
* All_Traffic.bytes
* All_Traffic.dest_category
* All_Traffic.protocol
* All_Traffic.transport
* All_Traffic.src_ip
* All_Traffic.dest_ip


#### How To Implement
In order to run this search effectively, we highly recommend that you leverage the Assets and Identity framework. It is important that you have a good understanding of how your network segments are designed and that you are able to distinguish internal from external address space. Add a category named `internal` to the CIDRs that host the company's assets in the `assets_by_cidr.csv` lookup file, which is located in `$SPLUNK_HOME/etc/apps/SA-IdentityManagement/lookups/`. More information on updating this lookup can be found here: https://docs.splunk.com/Documentation/ES/5.0.0/Admin/Addassetandidentitydata. This search also requires you to be ingesting your network traffic and populating the Network_Traffic data model

#### Known False Positives
ICMP packets are used in a variety of ways to help troubleshoot networking issues and ensure the proper flow of traffic. As such, it is possible that a large ICMP packet could be perfectly legitimate. If large ICMP packets are associated with command and control traffic, there will typically be a large number of these packets observed over time. If the search is providing a large number of false positives, you can modify the macro `detect_large_outbound_icmp_packets_filter` to adjust the byte threshold or add specific IP addresses to an allow list.

#### Associated Analytic story
* [Command and Control](/stories/command_and_control)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/detect_large_outbound_icmp_packets.yml) \| *version*: **2**