---
title: "Suspicious Curl Network Connection"
excerpt: "Ingress Tool Transfer"
categories:
  - Endpoint
last_modified_at: 2021-02-22
toc: true
toc_label: ""
tags:
  - Ingress Tool Transfer
  - Command And Control
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the use of a curl contacting suspicious remote domains to checkin to command and control servers or download further implants. In the context of Silver Sparrow, curl is identified contacting s3.amazonaws.com. This particular behavior is common with MacOS adware-malicious software.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-02-22
- **Author**: Michael Haag, Splunk
- **ID**: 3f613dc0-21f2-4063-93b1-5d3c15eef22f


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | Command And Control |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=curl Processes.process=s3.amazonaws.com by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `suspicious_curl_network_connection_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `suspicious_curl_network_connection_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.process_name
* Processes.process
* Processes.dest
* Processes.user
* Processes.parent_process
* Processes.process_id
* Processes.parent_process_id


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Known False Positives
Unknown. Filter as needed.

#### Associated Analytic story
* [Silver Sparrow](/stories/silver_sparrow)
* [Ingress Tool Transfer](/stories/ingress_tool_transfer)


#### Kill Chain Phase
* Actions on Objectives




Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://redcanary.com/blog/clipping-silver-sparrows-wings/](https://redcanary.com/blog/clipping-silver-sparrows-wings/)
* [https://marcosantadev.com/manage-plist-files-plistbuddy/](https://marcosantadev.com/manage-plist-files-plistbuddy/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/suspicious_curl_network_connection.yml) \| *version*: **1**