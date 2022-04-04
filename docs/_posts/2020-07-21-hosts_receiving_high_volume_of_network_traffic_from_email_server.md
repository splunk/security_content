---
title: "Hosts receiving high volume of network traffic from email server"
excerpt: "Remote Email Collection
, Email Collection
"
categories:
  - Network
last_modified_at: 2020-07-21
toc: true
toc_label: ""
tags:
  - Remote Email Collection
  - Email Collection
  - Collection
  - Collection
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Traffic
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for an increase of data transfers from your email server to your clients. This could be indicative of a malicious actor collecting data using your email server.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2020-07-21
- **Author**: Bhavin Patel, Splunk
- **ID**: 7f5fb3e1-4209-4914-90db-0ec21b556368


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1114.002](https://attack.mitre.org/techniques/T1114/002/) | Remote Email Collection | Collection |

| [T1114](https://attack.mitre.org/techniques/T1114/) | Email Collection | Collection |

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
* DE.CM
* DE.AE



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 7



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

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

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that **hosts_receiving_high_volume_of_network_traffic_from_email_server_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* All_Traffic.bytes_in
* All_Traffic.dest_category
* All_Traffic.src_ip


#### How To Implement
This search requires you to be ingesting your network traffic and populating the Network_Traffic data model.  Your email servers must be categorized as "email_server" for the search to work, as well. You may need to adjust the deviation_threshold and minimum_data_samples values based on the network traffic in your environment. The "deviation_threshold" field is a multiplying factor to control how much variation you're willing to tolerate. The "minimum_data_samples" field is the minimum number of connections of data samples required for the statistic to be valid.

#### Known False Positives
The false-positive rate will vary based on how you set the deviation_threshold and data_samples values. Our recommendation is to adjust these values based on your network traffic to and from your email servers.

#### Associated Analytic story
* [Collection and Staging](/stories/collection_and_staging)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/hosts_receiving_high_volume_of_network_traffic_from_email_server.yml) \| *version*: **2**