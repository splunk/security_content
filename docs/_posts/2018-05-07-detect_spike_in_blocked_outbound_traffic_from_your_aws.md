---
title: "Detect Spike in blocked Outbound Traffic from your AWS"
excerpt: ""
categories:
  - Cloud
last_modified_at: 2018-05-07
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

###  WARNING THIS IS A EXPERIMENTAL object
We have not been able to test, simulate, or build datasets for this object. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search will detect spike in blocked outbound network connections originating from within your AWS environment.  It will also update the cache file that factors in the latest data.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2018-05-07
- **Author**: Bhavin Patel, Splunk
- **ID**: d3fffa37-492f-487b-a35d-c60fcb2acf01


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">

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

* DE.AE
* DE.CM
* PR.AC



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 11



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```
`cloudwatchlogs_vpcflow` action=blocked (src_ip=10.0.0.0/8 OR src_ip=172.16.0.0/12 OR src_ip=192.168.0.0/16) ( dest_ip!=10.0.0.0/8 AND dest_ip!=172.16.0.0/12 AND dest_ip!=192.168.0.0/16)  [search  `cloudwatchlogs_vpcflow` action=blocked (src_ip=10.0.0.0/8 OR src_ip=172.16.0.0/12 OR src_ip=192.168.0.0/16) ( dest_ip!=10.0.0.0/8 AND dest_ip!=172.16.0.0/12 AND dest_ip!=192.168.0.0/16)  
| stats count as numberOfBlockedConnections by src_ip 
| inputlookup baseline_blocked_outbound_connections append=t 
| fields - latestCount 
| stats values(*) as * by src_ip 
| rename numberOfBlockedConnections as latestCount 
| eval newAvgBlockedConnections=avgBlockedConnections + (latestCount-avgBlockedConnections)/720 
| eval newStdevBlockedConnections=sqrt(((pow(stdevBlockedConnections, 2)*719 + (latestCount-newAvgBlockedConnections)*(latestCount-avgBlockedConnections))/720)) 
| eval avgBlockedConnections=coalesce(newAvgBlockedConnections, avgBlockedConnections), stdevBlockedConnections=coalesce(newStdevBlockedConnections, stdevBlockedConnections), numDataPoints=if(isnull(latestCount), numDataPoints, numDataPoints+1) 
| table src_ip, latestCount, numDataPoints, avgBlockedConnections, stdevBlockedConnections 
| outputlookup baseline_blocked_outbound_connections 
| eval dataPointThreshold = 5, deviationThreshold = 3 
| eval isSpike=if((latestCount > avgBlockedConnections+deviationThreshold*stdevBlockedConnections) AND numDataPoints > dataPointThreshold, 1, 0) 
| where isSpike=1 
| table src_ip] 
| stats values(dest_ip) as "Blocked Destination IPs", values(interface_id) as "resourceId" count as numberOfBlockedConnections, dc(dest_ip) as uniqueDestConnections by src_ip 
| `detect_spike_in_blocked_outbound_traffic_from_your_aws_filter`
```

#### Macros
The SPL above uses the following Macros:
* [cloudwatchlogs_vpcflow](https://github.com/splunk/security_content/blob/develop/macros/cloudwatchlogs_vpcflow.yml)

Note that **detect_spike_in_blocked_outbound_traffic_from_your_aws_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Lookups
The SPL above uses the following Lookups:

* [baseline_blocked_outbound_connections](https://github.com/splunk/security_content/blob/develop/lookups/baseline_blocked_outbound_connections.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/baseline_blocked_outbound_connections.csv)
* [baseline_blocked_outbound_connections](https://github.com/splunk/security_content/blob/develop/lookups/baseline_blocked_outbound_connections.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/baseline_blocked_outbound_connections.csv)

#### Required field
* _time
* action
* src_ip
* dest_ip


#### How To Implement
You must install the AWS App for Splunk (version 5.1.0 or later) and Splunk Add-on for AWS (version 4.4.0 or later), then configure your VPC Flow logs. You can modify `dataPointThreshold` and `deviationThreshold` to better fit your environment. The `dataPointThreshold` variable is the number of data points required to meet the definition of "spike." The `deviationThreshold` variable is the number of standard deviations away from the mean that the value must be to be considered a spike. This search works best when you run the "Baseline of Blocked Outbound Connection" support search once to create a history of previously seen blocked outbound connections.

#### Known False Positives
The false-positive rate may vary based on the values of`dataPointThreshold` and `deviationThreshold`. Additionally, false positives may result when AWS administrators roll out policies enforcing network blocks, causing sudden increases in the number of blocked outbound connections.

#### Associated Analytic story
* [AWS Network ACL Activity](/stories/aws_network_acl_activity)
* [Suspicious AWS Traffic](/stories/suspicious_aws_traffic)
* [Command and Control](/stories/command_and_control)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |


#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/cloud/detect_spike_in_blocked_outbound_traffic_from_your_aws.yml) \| *version*: **1**