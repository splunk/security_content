---
title: "DNS Query Length With High Standard Deviation"
excerpt: "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol"
categories:
  - Network
last_modified_at: 2021-07-21
toc: true
tags:
  - Anomaly
  - T1048.003
  - Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol
  - Exfiltration
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Resolution
  - Command and Control
---



[Try in Splunk Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search allows you to identify DNS requests and compute the standard deviation on the length of the names being resolved, then filter on two times the standard deviation to show you those queries that are unusually large for your environment.

- **ID**: 1a67f15a-f4ff-4170-84e9-08cf6f75d6f5
- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)
- **Last Updated**: 2021-07-21
- **Author**: Bhavin Patel, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1048.003](https://attack.mitre.org/techniques/T1048/003/) | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | Exfiltration |


#### Search

```

| tstats `security_content_summariesonly` count from datamodel=Network_Resolution where NOT DNS.message_type IN("Pointer","PTR") by DNS.query 
| `drop_dm_object_name("DNS")` 
| eval query_length = len(query) 
| table query query_length record_type count 
| eventstats stdev(query_length) AS stdev avg(query_length) AS avg p50(query_length) AS p50
| where query_length>(avg+stdev*2) 
| eval z_score=(query_length-avg)/stdev 
| `dns_query_length_with_high_standard_deviation_filter` 
```

#### Associated Analytic Story
* [Hidden Cobra Malware](/stories/hidden_cobra_malware)
* [Suspicious DNS Traffic](/stories/suspicious_dns_traffic)
* [Command and Control](/stories/command_and_control)


#### How To Implement
To successfully implement this search, you will need to ensure that DNS data is populating the Network_Resolution data model.

#### Required field
* _time
* DNS.query


#### Kill Chain Phase
* Command and Control


#### Known False Positives
It&#39;s possible there can be long domain names that are legitimate.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | A dns query $query$ with 2 time standard deviation of name len of the dns query in host  $host$ |



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1048.003/long_dns_queries/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1048.003/long_dns_queries/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/network/dns_query_length_with_high_standard_deviation.yml) \| *version*: **3**