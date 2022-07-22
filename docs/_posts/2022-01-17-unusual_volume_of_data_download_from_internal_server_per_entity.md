---
title: "Unusual Volume of Data Download from Internal Server Per Entity"
excerpt: "Data from Information Repositories, Data from Network Shared Drive"
categories:
  - Network
last_modified_at: 2022-01-17
toc: true
toc_label: ""
tags:
  - Data from Information Repositories
  - Collection
  - Data from Network Shared Drive
  - Collection
  - Splunk Behavioral Analytics
  - Network_Traffic
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Insider might conduct information collection before data exfiltration, and unusual volume of data download from internal server is an indicator of such potential threat. This detection evaluates the total bytes downloaded from internal servers at specific time window per entity level, and then flagged these that are higher than 99.999% percentile as an anamaly. A behavior will be reported as long as the downloaded byte volume is unusual even though that operation is benign, which causes false positive. It is therefore advised to adjust threshold and time window based on detection performance whenever necessary. It should be noted that seasonality is not modeled in the current approach.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2022-01-17
- **Author**: Xiao Lin, Splunk
- **ID**: cca028f4-77dd-11ec-bc09-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1213](https://attack.mitre.org/techniques/T1213/) | Data from Information Repositories | Collection |

| [T1039](https://attack.mitre.org/techniques/T1039/) | Data from Network Shared Drive | Collection |

#### Search

```

| from read_ssa_enriched_events() 
| eval sourcetype = ucast(map_get(input_event, "sourcetype"), "string", null) 
| eval timestamp = parse_long(ucast(map_get(input_event, "_time"), "string", null)) 
| where sourcetype == "pan:traffic" 
| eval src_device_scope =ucast(map_get(input_event, "src_device_scope"), "string", null) 
| eval dest_device_scope=ucast(map_get(input_event, "dest_device_scope"), "string", null) 
| where src_device_scope IS NOT NULL AND dest_device_scope IS NOT NULL 
| eval dest_device = ucast(map_get(input_event, "dest_device_ips"), "collection<string>", [])[0] 
| where dest_device IS NOT NULL AND dest_device_scope == "INTERNAL" 
| eval src_device  = ucast(map_get(input_event, "src_device_ips"), "collection<string>", [])[0] 
| where src_device IS NOT NULL AND src_device_scope == "INTERNAL" 
| eval bytes_in = ucast(map_get(input_event, "bytes_in"), "integer", 0) 
| eval download_bytes = cast(bytes_in, "double") 
| eval tenant = ucast(map_get(input_event, "_tenant"), "string", null) 
| eval event_id = ucast(map_get(input_event, "event_id"), "string", null) 
| adaptive_threshold algorithm="quantile" value="download_bytes" entity="dest_device" window=86400000L 
| where label AND quantile>0.99999 
| eval end_time = timestamp 
| eval start_time = end_time - 86400000 
| eval body = create_map(["event_id", event_id, "tenant", tenant]) 
| eval entities=mvappend(dest_device) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `unusual_volume_of_data_download_from_internal_server_per_entity_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* dest_device_scope
* bytes_in
* src_device_ips


#### How To Implement
Ingest PAN traffic logs

#### Known False Positives
Benign large volume data download might be flagged as (false) positive.

#### Associated Analytic story
* [Insider Threat](/stories/insider_threat)


#### Kill Chain Phase
* Weaponization



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | $src_device_ip downloaded unusually amount of data from internal server within one day |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://github.com/twitter/AnomalyDetection](https://github.com/twitter/AnomalyDetection)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://github.com/splunk/attack_data/blob/master/datasets/suspicious_behaviour/unusual_data_download/unusual_volume_data_download.txt](https://github.com/splunk/attack_data/blob/master/datasets/suspicious_behaviour/unusual_data_download/unusual_volume_data_download.txt)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/unusual_volume_of_data_download_from_internal_server_per_entity.yml) \| *version*: **1**