---
title: "Unusually Long Command Line - MLTK"
excerpt: ""
categories:
  - Endpoint
last_modified_at: 2019-05-08
toc: true
tags:
  - Anomaly
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Actions on Objectives
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate or build datasets for it, use at your own risk!


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Command lines that are extremely long may be indicative of malicious activity on your hosts. This search leverages the Machine Learning Toolkit (MLTK) to help identify command lines with lengths that are unusual for a given user.

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2019-05-08
- **Author**: Rico Valdez, Splunk
- **ID**: 57edaefa-a73b-45e5-bbae-f39c1473f941



#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes by Processes.user Processes.dest Processes.process_name Processes.process 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval processlen=len(process) 
| search user!=unknown 
| apply cmdline_pdfmodel threshold=0.01 
| rename "IsOutlier(processlen)" as isOutlier 
| search isOutlier > 0 
| table firstTime lastTime user dest process_name process processlen count 
| `unusually_long_command_line___mltk_filter`
```

#### Associated Analytic Story
* [Suspicious Command-Line Executions](/stories/suspicious_command-line_executions)
* [Unusual Processes](/stories/unusual_processes)
* [Possible Backdoor Activity Associated With MUDCARP Espionage Campaigns](/stories/possible_backdoor_activity_associated_with_mudcarp_espionage_campaigns)
* [Ransomware](/stories/ransomware)


#### How To Implement
You must be ingesting endpoint data that monitors command lines and populates the Endpoint data model in the Processes node. The command-line arguments are mapped to the &#34;process&#34; field in the Endpoint data model. In addition, MLTK version &gt;= 4.2 must be installed on your search heads, along with any required dependencies. Finally, the support search &#34;Baseline of Command Line Length - MLTK&#34; must be executed before this detection search, as it builds an ML model over the historical data used by this search. It is important that this search is run in the same app context as the associated support search, so that the model created by the support search is available for use. You should periodically re-run the support search to rebuild the model with the latest data available in your environment.

#### Required field
* _time
* Processes.user
* Processes.dest
* Processes.process_name
* Processes.process


#### Kill Chain Phase
* Actions on Objectives


#### Known False Positives
Some legitimate applications use long command lines for installs or updates. You should review identified command lines for legitimacy. You may modify the first part of the search to omit legitimate command lines from consideration. If you are seeing more results than desired, you may consider changing the value of threshold in the search to a smaller value. You should also periodically re-run the support search to re-build the ML model on the latest data. You may get unexpected results if the user identified in the results is not present in the data used to build the associated model.




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/unusually_long_command_line_-_mltk.yml) \| *version*: **1**