---
title: "Spike in File Writes"
excerpt: ""
categories:
  - Endpoint
last_modified_at: 2020-03-16
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The search looks for a sharp increase in the number of files written to a particular host

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-03-16
- **Author**: David Dorsey, Splunk
- **ID**: fdb0f805-74e4-4539-8c00-618927333aae

#### Search

```

| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Filesystem where Filesystem.action=created by _time span=1h, Filesystem.dest 
| `drop_dm_object_name(Filesystem)` 
| eventstats max(_time) as maxtime 
| stats count as num_data_samples max(eval(if(_time >= relative_time(maxtime, "-1d@d"), count, null))) as "count" avg(eval(if(_time<relative_time(maxtime, "-1d@d"), count,null))) as avg stdev(eval(if(_time<relative_time(maxtime, "-1d@d"), count, null))) as stdev by "dest" 
| eval upperBound=(avg+stdev*4), isOutlier=if((count > upperBound) AND num_data_samples >=20, 1, 0) 
| search isOutlier=1 
| `spike_in_file_writes_filter` 
```

#### Associated Analytic Story
* [SamSam Ransomware](/stories/samsam_ransomware)
* [Ryuk Ransomware](/stories/ryuk_ransomware)
* [Ransomware](/stories/ransomware)


#### How To Implement
In order to implement this search, you must populate the Endpoint file-system data model node. This is typically populated via endpoint detection and response product, such as Carbon Black or endpoint data sources such as Sysmon. The data used for this search is typically generated via logs that report reads and writes to the file system.

#### Required field
* _time
* Filesystem.action
* Filesystem.dest


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
It is important to understand that if you happen to install any new applications on your hosts or are copying a large number of files, you can expect to see a large increase of file modifications.





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/spike_in_file_writes.yml) \| *version*: **3**