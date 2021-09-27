---
title: "Hosts receiving high volume of network traffic from email server"
excerpt: "Remote Email Collection"
categories:
  - Network
last_modified_at: 2020-07-21
toc: true
tags:
  - Anomaly
  - T1114.002
  - Remote Email Collection
  - Collection
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Traffic
  - Actions on Objectives
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate or build datasets for it, use at your own risk!


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for an increase of data transfers from your email server to your clients. This could be indicative of a malicious actor collecting data using your email server.

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2020-07-21
- **Author**: Bhavin Patel, Splunk
- **ID**: 7f5fb3e1-4209-4914-90db-0ec21b556368


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1114.002](https://attack.mitre.org/techniques/T1114/002/) | Remote Email Collection | Collection |


#### Search

```

| tstats `security_content_summariesonly` sum(All_Traffic.bytes_in) as bytes_in from datamodel=Network_Traffic where All_Traffic.dest_category=email_server by All_Traffic.src_ip _time span=1d 
| `drop_dm_object_name("All_Traffic")` 
| eventstats avg(bytes_in) as avg_bytes_in stdev(bytes_in) as stdev_bytes_in 
| eventstats count as num_data_samples avg(eval(if(_time < relative_time(now(), "@d"), bytes_in, null))) as per_source_avg_bytes_in stdev(eval(if(_time < relative_time(now(), "@d"), bytes_in, null))) as per_source_stdev_bytes_in by src_ip 
| eval minimum_data_samples = 4, deviation_threshold = 3 
| where num_data_samples >= minimum_data_samples AND bytes_in > (avg_bytes_in + (deviation_threshold * stdev_bytes_in)) AND bytes_in > (per_source_avg_bytes_in + (deviation_threshold * per_source_stdev_bytes_in)) AND _time >= relative_time(now(), "@d") 
| eval num_standard_deviations_away_from_server_average = round(abs(bytes_in - avg_bytes_in) / stdev_bytes_in, 2), num_standard_deviations_away_from_client_average = round(abs(bytes_in - per_source_avg_bytes_in) / per_source_stdev_bytes_in, 2) 
| table src_ip, _time, bytes_in, avg_bytes_in, per_source_avg_bytes_in, num_standard_deviations_away_from_server_average, num_standard_deviations_away_from_client_average 
| `hosts_receiving_high_volume_of_network_traffic_from_email_server_filter`
```

#### Associated Analytic Story
* [Collection and Staging](/stories/collection_and_staging)


#### How To Implement
This search requires you to be ingesting your network traffic and populating the Network_Traffic data model.  Your email servers must be categorized as &#34;email_server&#34; for the search to work, as well. You may need to adjust the deviation_threshold and minimum_data_samples values based on the network traffic in your environment. The &#34;deviation_threshold&#34; field is a multiplying factor to control how much variation you&#39;re willing to tolerate. The &#34;minimum_data_samples&#34; field is the minimum number of connections of data samples required for the statistic to be valid.

#### Required field
* _time
* All_Traffic.bytes_in
* All_Traffic.dest_category
* All_Traffic.src_ip


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
The false-positive rate will vary based on how you set the deviation_threshold and data_samples values. Our recommendation is to adjust these values based on your network traffic to and from your email servers.




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/hosts_receiving_high_volume_of_network_traffic_from_email_server.yml) \| *version*: **2**