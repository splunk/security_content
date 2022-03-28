---
title: "Potentially malicious code on commandline"
excerpt: "Windows Command Shell
"
categories:
  - Endpoint
last_modified_at: 2022-01-14
toc: true
toc_label: ""
tags:
  - Windows Command Shell
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic uses a pretrained machine learning text classifier to detect potentially malicious commandlines.  The model identifies unusual combinations of keywords found in samples of commandlines where adversaries executed powershell code, primarily for C2 communication.  For example, adversaries will leverage IO capabilities such as "streamreader" and "webclient", threading capabilties such as "mutex" locks, programmatic constructs like "function" and "catch", and cryptographic operations like "computehash".  Although observing one of these keywords in a commandline script is possible, combinations of keywords observed in attack data are not typically found in normal usage of the commandline.  The model will output a score where all values above zero are suspicious, anything greater than one particularly so.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2022-01-14
- **Author**: Michael Hart, Splunk
- **ID**: 9c53c446-757e-11ec-871d-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Windows Command Shell | Execution |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel="Endpoint.Processes" by Processes.parent_process_name Processes.process_name Processes.process Processes.user Processes.dest  
| `drop_dm_object_name(Processes)`  
| where len(process) > 200 
| `potentially_malicious_code_on_cmdline_tokenize_score` 
| apply unusual_commandline_detection 
| eval score='predicted(unusual_cmdline_logits)', process=orig_process 
| fields - unusual_cmdline* predicted(unusual_cmdline_logits) orig_process 
| where score > 0.5 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `potentially_malicious_code_on_commandline_filter`
```

#### Macros
The SPL above uses the following Macros:
* [potentially_malicious_code_on_cmdline_tokenize_score](https://github.com/splunk/security_content/blob/develop/macros/potentially_malicious_code_on_cmdline_tokenize_score.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `potentially_malicious_code_on_commandline_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.process
* Processes.parent_process_name
* Processes.process_name
* Processes.parent_process
* Processes.user
* Processes.dest


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.  You will also need to install the Machine Learning Toolkit version 5.3 or above to apply the pretrained model.

#### Known False Positives
This model is an anomaly detector that identifies usage of APIs and scripting constructs that are correllated with malicious activity.  These APIs and scripting constructs are part of the programming langauge and advanced scripts may generate false positives.

#### Associated Analytic story
* [Suspicious Command-Line Executions](/stories/suspicious_command-line_executions)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 12.0 | 60 | 20 | Unusual command-line execution with hallmarks of malicious activity run by $user$ found on $dest$ with commandline $process$ |




#### Reference

* [https://attack.mitre.org/techniques/T1059/003/](https://attack.mitre.org/techniques/T1059/003/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/malicious_cmd_line_samples/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/malicious_cmd_line_samples/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/potentially_malicious_code_on_commandline.yml) \| *version*: **1**