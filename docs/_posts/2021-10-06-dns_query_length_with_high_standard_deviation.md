---
title: "DNS Query Length With High Standard Deviation"
excerpt: "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol
, Exfiltration Over Alternative Protocol
"
categories:
  - Network
last_modified_at: 2021-10-06
toc: true
toc_label: ""
tags:
  - Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol
  - Exfiltration Over Alternative Protocol
  - Exfiltration
  - Exfiltration
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Resolution
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search allows you to identify DNS requests and compute the standard deviation on the length of the names being resolved, then filter on two times the standard deviation to show you those queries that are unusually large for your environment.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-10-06
- **Author**: Bhavin Patel, Splunk
- **ID**: 1a67f15a-f4ff-4170-84e9-08cf6f75d6f5


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1048.003](https://attack.mitre.org/techniques/T1048/003/) | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | Exfiltration |

| [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol | Exfiltration |

#### Search

```

| tstats `security_content_summariesonly` count from datamodel=Network_Resolution where NOT DNS.message_type IN("Pointer","PTR") by DNS.query 
| `drop_dm_object_name("DNS")` 
| eval tlds=split(query,".") 
| eval tld=mvindex(tlds,-1) 
| eval tld_len=len(tld) 
| search tld_len<=24 
| eval query_length = len(query) 
| table query query_length record_type count 
| eventstats stdev(query_length) AS stdev avg(query_length) AS avg p50(query_length) AS p50
| where query_length>(avg+stdev*2) 
| eval z_score=(query_length-avg)/stdev 
| `dns_query_length_with_high_standard_deviation_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `dns_query_length_with_high_standard_deviation_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* DNS.query


#### How To Implement
To successfully implement this search, you will need to ensure that DNS data is populating the Network_Resolution data model.

#### Known False Positives
It's possible there can be long domain names that are legitimate.

#### Associated Analytic story
* [Hidden Cobra Malware](/stories/hidden_cobra_malware)
* [Suspicious DNS Traffic](/stories/suspicious_dns_traffic)
* [Command and Control](/stories/command_and_control)


#### Kill Chain Phase
* Command & Control



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | A dns query $query$ with 2 time standard deviation of name len of the dns query in host  $host$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1048.003/long_dns_queries/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1048.003/long_dns_queries/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/network/dns_query_length_with_high_standard_deviation.yml) \| *version*: **4**