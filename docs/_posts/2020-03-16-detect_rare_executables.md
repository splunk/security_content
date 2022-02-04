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

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
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

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [filter_rare_process_allow_list](https://github.com/splunk/security_content/blob/develop/macros/filter_rare_process_allow_list.yml)

Note that `detect_rare_executables_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Lookups
The SPL above uses the following Lookups:

* [lookup_rare_process_allow_list_default](https://github.com/splunk/security_content/blob/develop/lookups/lookup_rare_process_allow_list_default.yml) with [data](https://github.com/splunk/security_content/blob/develop/lookups/rare_process_allow_list_default.csv)
* [lookup_rare_process_allow_list_local](https://github.com/splunk/security_content/blob/develop/lookups/lookup_rare_process_allow_list_local.yml) with [data](https://github.com/splunk/security_content/blob/develop/lookups/rare_process_allow_list_local.csv)

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.process_name


#### How To Implement
To successfully implement this search, you must be ingesting data that records process activity from your hosts and populating the endpoint data model with the resultant dataset. The macro `filter_rare_process_allow_list` searches two lookup files for allowed processes.  These consist of `rare_process_allow_list_default.csv` and `rare_process_allow_list_local.csv`. To add your own processes to the allow list, add them to `rare_process_allow_list_local.csv`. If you wish to remove an entry from the default lookup file, you will have to modify the macro itself to set the allow_list value for that process to false. You can modify the limit parameter and search scheduling to better suit your environment.

#### Known False Positives
Some legitimate processes may be only rarely executed in your environment. As these are identified, update `rare_process_allow_list_local.csv` to filter them out of your search results.

#### Kill Chain Phase
* Installation
* Command and Control
* Actions on Objectives






#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/detect_rare_executables.yml) \| *version*: **5**