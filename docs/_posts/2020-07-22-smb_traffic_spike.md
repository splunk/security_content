---
title: "SMB Traffic Spike"
excerpt: "SMB/Windows Admin Shares
, Remote Services
"
categories:
  - Network
last_modified_at: 2020-07-22
toc: true
toc_label: ""
tags:
  - SMB/Windows Admin Shares
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

This search looks for spikes in the number of Server Message Block (SMB) traffic connections.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2020-07-22
- **Author**: David Dorsey, Splunk
- **ID**: 7f5fb3e1-4209-4914-90db-0ec21b936378


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB/Windows Admin Shares | Lateral Movement |

| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | Lateral Movement |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Actions on Objectives


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

* CIS 8



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` count from datamodel=Network_Traffic where All_Traffic.dest_port=139 OR All_Traffic.dest_port=445 OR All_Traffic.app=smb by _time span=1h, All_Traffic.src 
| `drop_dm_object_name("All_Traffic")` 
| eventstats max(_time) as maxtime 
| stats count as num_data_samples max(eval(if(_time >= relative_time(maxtime, "-70m@m"), count, null))) as count avg(eval(if(_time<relative_time(maxtime, "-70m@m"), count, null))) as avg stdev(eval(if(_time<relative_time(maxtime, "-70m@m"), count, null))) as stdev by src 
| eval upperBound=(avg+stdev*2), isOutlier=if(count > upperBound AND num_data_samples >=50, 1, 0) 
| where isOutlier=1 
| table src count 
| `smb_traffic_spike_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that **smb_traffic_spike_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* All_Traffic.dest_port
* All_Traffic.app
* All_Traffic.src


#### How To Implement
This search requires you to be ingesting your network traffic logs and populating the `Network_Traffic` data model.

#### Known False Positives
A file server may experience high-demand loads that could cause this analytic to trigger.

#### Associated Analytic story
* [Emotet Malware  DHS Report TA18-201A ](/stories/emotet_malware__dhs_report_ta18-201a_)
* [Hidden Cobra Malware](/stories/hidden_cobra_malware)
* [Ransomware](/stories/ransomware)
* [DHS Report TA18-074A](/stories/dhs_report_ta18-074a)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/smb_traffic_spike.yml) \| *version*: **3**