---
title: "Potentially malicious code on commandline"
excerpt: "Windows Command Shell"
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



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic uses a pretrained machine learning text classifier to detect potentially malicious commandlines.  The model identifies unusual combinations of keywords found in samples of commandlines where adversaries executed powershell code, primarily for C2 communication.  For example, adversaries will leverage IO capabilities such as &#34;streamreader&#34; and &#34;webclient&#34;, threading capabilties such as &#34;mutex&#34; locks, programmatic constructs like &#34;function&#34; and &#34;catch&#34;, and cryptographic operations like &#34;computehash&#34;.  Although observing one of these keywords in a commandline script is possible, combinations of keywords observed in attack data are not typically found in normal usage of the commandline.  The model will output a score where all values above zero are suspicious, anything greater than one particularly so.

- **Type**: Anomaly
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-01-14
- **Author**: Michael Hart, Splunk
- **ID**: 9c53c446-757e-11ec-871d-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
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

#### Associated Analytic Story
* [Suspicious Command-Line Executions](/stories/suspicious_command-line_executions)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.  You will also need to install the Machine Learning Toolkit version 5.3 or above to apply the pretrained model.

#### Required field
* _time
* Processes.process
* Processes.parent_process_name
* Processes.process_name
* Processes.parent_process
* Processes.user
* Processes.dest


#### Kill Chain Phase
* Exploitation


#### Known False Positives
This model is an anomaly detector that identifies usage of APIs and scripting constructs that are correllated with malicious activity.  These APIs and scripting constructs are part of the programming langauge and advanced scripts may generate false positives.


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