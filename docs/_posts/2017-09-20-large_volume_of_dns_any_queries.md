---
title: "Large Volume of DNS ANY Queries"
excerpt: "Network Denial of Service
, Reflection Amplification
"
categories:
  - Network
last_modified_at: 2017-09-20
toc: true
toc_label: ""
tags:
  - Network Denial of Service
  - Reflection Amplification
  - Impact
  - Impact
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Resolution
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The search is used to identify attempts to use your DNS Infrastructure for DDoS purposes via a DNS amplification attack leveraging ANY queries.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)
- **Last Updated**: 2017-09-20
- **Author**: Bhavin Patel, Splunk
- **ID**: 8fa891f7-a533-4b3c-af85-5aa2e7c1f1eb


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1498](https://attack.mitre.org/techniques/T1498/) | Network Denial of Service | Impact |

| [T1498.002](https://attack.mitre.org/techniques/T1498/002/) | Reflection Amplification | Impact |

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

* PR.PT
* DE.AE
* PR.IP



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 11
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

| tstats `security_content_summariesonly` count from datamodel=Network_Resolution where nodename=DNS "DNS.message_type"="QUERY" "DNS.record_type"="ANY" by "DNS.dest" 
| `drop_dm_object_name("DNS")` 
| where count>200 
| `large_volume_of_dns_any_queries_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that **large_volume_of_dns_any_queries_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* DNS.message_type
* DNS.record_type
* DNS.dest


#### How To Implement
To successfully implement this search you must ensure that DNS data is populating the Network_Resolution data model.

#### Known False Positives
Legitimate ANY requests may trigger this search, however it is unusual to see a large volume of them under typical circumstances. You may modify the threshold in the search to better suit your environment.

#### Associated Analytic story
* [DNS Amplification Attacks](/stories/dns_amplification_attacks)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/large_volume_of_dns_any_queries.yml) \| *version*: **1**