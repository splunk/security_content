---
title: "Detect Rare Executables"
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
  - Endpoint
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search will return a table of rare processes, the names of the systems running them, and the users who initiated each process.

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-03-16
- **Author**: Bhavin Patel, Splunk
- **ID**: 44fddcb2-8d3b-454c-874e-7c6de5a4f7ac

#### Search

```

| tstats `security_content_summariesonly` count values(Processes.dest) as dest values(Processes.user) as user min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes by Processes.process_name  
| rename Processes.process_name as process 
| rex field=user "(?<user_domain>.*)\\\\(?<user_name>.*)" 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| search [
| tstats count from datamodel=Endpoint.Processes by Processes.process_name 
| rare Processes.process_name limit=30 
| rename Processes.process_name as process
| `filter_rare_process_allow_list`
| table process ] 
| `detect_rare_executables_filter` 
```

#### Associated Analytic Story
* [Emotet Malware  DHS Report TA18-201A ](/stories/emotet_malware__dhs_report_ta18-201a_)
* [Unusual Processes](/stories/unusual_processes)
* [Cloud Federated Credential Abuse](/stories/cloud_federated_credential_abuse)


#### How To Implement
To successfully implement this search, you must be ingesting data that records process activity from your hosts and populating the endpoint data model with the resultant dataset. The macro `filter_rare_process_allow_list` searches two lookup files for allowed processes.  These consist of `rare_process_allow_list_default.csv` and `rare_process_allow_list_local.csv`. To add your own processes to the allow list, add them to `rare_process_allow_list_local.csv`. If you wish to remove an entry from the default lookup file, you will have to modify the macro itself to set the allow_list value for that process to false. You can modify the limit parameter and search scheduling to better suit your environment.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.process_name


#### Kill Chain Phase
* Installation
* Command and Control
* Actions on Objectives


#### Known False Positives
Some legitimate processes may be only rarely executed in your environment. As these are identified, update `rare_process_allow_list_local.csv` to filter them out of your search results.





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/detect_rare_executables.yml) \| *version*: **5**