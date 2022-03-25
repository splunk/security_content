---
title: "SMB Traffic Spike - MLTK"
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

This search uses the Machine Learning Toolkit (MLTK) to identify spikes in the number of Server Message Block (SMB) connections.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)

- **Last Updated**: 2020-07-22
- **Author**: Rico Valdez, Splunk
- **ID**: d25773ba-9ad8-48d1-858e-07ad0bbeb828


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB/Windows Admin Shares | Lateral Movement |

| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | Lateral Movement |

#### Search

```

| tstats `security_content_summariesonly` count values(All_Traffic.dest_ip) as dest values(All_Traffic.dest_port) as port from datamodel=Network_Traffic where All_Traffic.dest_port=139 OR All_Traffic.dest_port=445 OR All_Traffic.app=smb by _time span=1h, All_Traffic.src 
| eval HourOfDay=strftime(_time, "%H") 
| eval DayOfWeek=strftime(_time, "%A") 
| `drop_dm_object_name(All_Traffic)` 
| apply smb_pdfmodel threshold=0.001 
| rename "IsOutlier(count)" as isOutlier 
| search isOutlier > 0 
| sort -count 
| table _time src dest port count 
| `smb_traffic_spike___mltk_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `smb_traffic_spike_-_mltk_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* All_Traffic.dest_ip
* All_Traffic.dest_port
* All_Traffic.app
* All_Traffic.src


#### How To Implement
To successfully implement this search, you will need to ensure that DNS data is populating the Network_Resolution data model. In addition, the Machine Learning Toolkit (MLTK) version 4.2 or greater must be installed on your search heads, along with any required dependencies. Finally, the support search "Baseline of SMB Traffic - MLTK" must be executed before this detection search, because it builds a machine-learning (ML) model over the historical data used by this search. It is important that this search is run in the same app context as the associated support search, so that the model created by the support search is available for use. You should periodically re-run the support search to rebuild the model with the latest data available in your environment.\
This search produces a field (Number of events,count) that are not yet supported by ES Incident Review and therefore cannot be viewed when a notable event is raised. This field contributes additional context to the notable. To see the additional metadata, add the following field, if not already present, to Incident Review - Event Attributes (Configure > Incident Management > Incident Review Settings > Add New Entry): \
1. **Label:** Number of events, **Field:** count\
Detailed documentation on how to create a new field within Incident Review is found here: `https://docs.splunk.com/Documentation/ES/5.3.0/Admin/Customizenotables#Add_a_field_to_the_notable_event_details`

#### Known False Positives
If you are seeing more results than desired, you may consider reducing the value of the threshold in the search. You should also periodically re-run the support search to re-build the ML model on the latest data. Please update the `smb_traffic_spike_mltk_filter` macro to filter out false positive results

#### Associated Analytic story
* [Emotet Malware  DHS Report TA18-201A ](/stories/emotet_malware__dhs_report_ta18-201a_)
* [Hidden Cobra Malware](/stories/hidden_cobra_malware)
* [Ransomware](/stories/ransomware)
* [DHS Report TA18-074A](/stories/dhs_report_ta18-074a)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/smb_traffic_spike_-_mltk.yml) \| *version*: **3**