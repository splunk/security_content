---
title: "DNS Query Length Outliers - MLTK"
excerpt: "DNS, Application Layer Protocol"
categories:
  - Network
last_modified_at: 2020-01-22
toc: true
toc_label: ""
tags:
  - DNS
  - Command And Control
  - Application Layer Protocol
  - Command And Control
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Resolution
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search allows you to identify DNS requests that are unusually large for the record type being requested in your environment.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)
- **Last Updated**: 2020-01-22
- **Author**: Rico Valdez, Splunk
- **ID**: 85fbcfe8-9718-4911-adf6-7000d077a3a9


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | DNS | Command And Control |

| [T1071](https://attack.mitre.org/techniques/T1071/) | Application Layer Protocol | Command And Control |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as start_time max(_time) as end_time values(DNS.src) as src values(DNS.dest) as dest from datamodel=Network_Resolution by DNS.query DNS.record_type 
| search DNS.record_type=* 
|  `drop_dm_object_name(DNS)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| eval query_length = len(query) 
| apply dns_query_pdfmodel threshold=0.01 
| rename "IsOutlier(query_length)" as isOutlier 
| search isOutlier > 0 
| sort -query_length 
| table start_time end_time query record_type count src dest query_length 
| `dns_query_length_outliers___mltk_filter` 
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `dns_query_length_outliers_-_mltk_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* DNS.src
* DNS.dest
* DNS.query
* DNS.record_type


#### How To Implement
To successfully implement this search, you will need to ensure that DNS data is populating the Network_Resolution data model. In addition, the Machine Learning Toolkit (MLTK) version 4.2 or greater must be installed on your search heads, along with any required dependencies. Finally, the support search &#34;Baseline of DNS Query Length - MLTK&#34; must be executed before this detection search, because it builds a machine-learning (ML) model over the historical data used by this search. It is important that this search is run in the same app context as the associated support search, so that the model created by the support search is available for use. You should periodically re-run the support search to rebuild the model with the latest data available in your environment.\
This search produces fields (`query`,`query_length`,`count`) that are not yet supported by ES Incident Review and therefore cannot be viewed when a notable event is raised. These fields contribute additional context to the notable. To see the additional metadata, add the following fields, if not already present, to Incident Review - Event Attributes (Configure &gt; Incident Management &gt; Incident Review Settings &gt; Add New Entry):\\n1. **Label:** DNS Query, **Field:** query\
1. \
1. **Label:** DNS Query Length, **Field:** query_length\
1. \
1. **Label:** Number of events, **Field:** count\
Detailed documentation on how to create a new field within Incident Review may be found here: `https://docs.splunk.com/Documentation/ES/5.3.0/Admin/Customizenotables#Add_a_field_to_the_notable_event_details`

#### Known False Positives
If you are seeing more results than desired, you may consider reducing the value for threshold in the search. You should also periodically re-run the support search to re-build the ML model on the latest data.

#### Associated Analytic story
* [Hidden Cobra Malware](/stories/hidden_cobra_malware)
* [Suspicious DNS Traffic](/stories/suspicious_dns_traffic)
* [Command and Control](/stories/command_and_control)


#### Kill Chain Phase
* Command and Control




Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/network/dns_query_length_outliers_-_mltk.yml) \| *version*: **2**