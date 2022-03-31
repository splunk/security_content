---
title: "DNS Query Requests Resolved by Unauthorized DNS Servers"
excerpt: "DNS
"
categories:
  - Deprecated
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - DNS
  - Command And Control
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Resolution
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search will detect DNS requests resolved by unauthorized DNS servers. Legitimate DNS servers should be identified in the Enterprise Security Assets and Identity Framework.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)
- **Last Updated**: 2020-07-21
- **Author**: Bhavin Patel, Splunk
- **ID**: 1a67f15a-f4ff-4170-84e9-08cf6f75d6f6


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | DNS | Command And Control |

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

* ID.AM
* PR.DS
* PR.IP
* DE.AE
* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 1
* CIS 3
* CIS 8
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

| tstats `security_content_summariesonly` count from datamodel=Network_Resolution where DNS.dest_category != dns_server AND DNS.src_category != dns_server by DNS.src DNS.dest 
| `drop_dm_object_name("DNS")` 
| `dns_query_requests_resolved_by_unauthorized_dns_servers_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that **dns_query_requests_resolved_by_unauthorized_dns_servers_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* DNS.dest_category
* DNS.src_category
* DNS.src
* DNS.dest


#### How To Implement
To successfully implement this search you will need to ensure that DNS data is populating the Network_Resolution data model. It also requires that your DNS servers are identified correctly in the Assets and Identity table of Enterprise Security.

#### Known False Positives
Legitimate DNS activity can be detected in this search. Investigate, verify and update the list of authorized DNS servers as appropriate.

#### Associated Analytic story
* [DNS Hijacking](/stories/dns_hijacking)
* [Suspicious DNS Traffic](/stories/suspicious_dns_traffic)
* [Host Redirection](/stories/host_redirection)
* [Command and Control](/stories/command_and_control)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/dns_query_requests_resolved_by_unauthorized_dns_servers.yml) \| *version*: **3**