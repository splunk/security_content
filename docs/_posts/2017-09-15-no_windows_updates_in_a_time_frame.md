---
title: "No Windows Updates in a time frame"
excerpt: ""
categories:
  - Application
last_modified_at: 2017-09-15
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Updates
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for Windows endpoints that have not generated an event indicating a successful Windows update in the last 60 days. Windows updates are typically released monthly and applied shortly thereafter. An endpoint that has not successfully applied an update in this time frame indicates the endpoint is not regularly being patched for some reason.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Updates](https://docs.splunk.com/Documentation/CIM/latest/User/Updates)
- **Last Updated**: 2017-09-15
- **Author**: Bhavin Patel, Splunk
- **ID**: 1a77c08c-2f56-409c-a2d3-7d64617edd4f

#### Search

```

| tstats `security_content_summariesonly` max(_time) as lastTime from datamodel=Updates where Updates.status=Installed Updates.vendor_product="Microsoft Windows" by Updates.dest Updates.status Updates.vendor_product 
| rename Updates.dest as Host 
| rename Updates.status as "Update Status" 
| rename Updates.vendor_product as Product 
| eval isOutlier=if(lastTime <= relative_time(now(), "-60d@d"), 1, 0)  
| `security_content_ctime(lastTime)`  
| search isOutlier=1 
| rename lastTime as "Last Update Time", 
| table Host, "Update Status", Product, "Last Update Time" 
| `no_windows_updates_in_a_time_frame_filter`
```

#### Associated Analytic Story
* [Monitor for Updates](/stories/monitor_for_updates)


#### How To Implement
To successfully implement this search, it requires that the &#39;Update&#39; data model is being populated. This can be accomplished by ingesting Windows events or the Windows Update log via a universal forwarder on the Windows endpoints you wish to monitor. The Windows add-on should be also be installed and configured to properly parse Windows events in Splunk. There may be other data sources which can populate this data model, including vulnerability management systems.

#### Required field
* _time
* Updates.status
* Updates.vendor_product
* Updates.dest


#### Kill Chain Phase


#### Known False Positives
None identified





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/application/no_windows_updates_in_a_time_frame.yml) \| *version*: **1**