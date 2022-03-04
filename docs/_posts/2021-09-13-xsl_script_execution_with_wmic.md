---
title: "XSL Script Execution With WMIC"
excerpt: "XSL Script Processing
"
categories:
  - Endpoint
last_modified_at: 2021-09-13
toc: true
toc_label: ""
tags:

  - XSL Script Processing
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect a suspicious wmic.exe process or renamed wmic process to execute malicious xsl file. This technique was seen in FIN7 to execute its malicous jscript using the .xsl as the loader with the help of wmic.exe process. This TTP is really a good indicator for you to hunt further for FIN7 or other attacker that known to used this technique.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-13
- **Author**: Teoderick Contreras, Splunk
- **ID**: 004e32e2-146d-11ec-a83f-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1220](https://attack.mitre.org/techniques/T1220/) | XSL Script Processing | Defense Evasion |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_wmic` Processes.process = "*os get*" Processes.process="*/format:*" Processes.process = "*.xsl*" by Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process_id Processes.process Processes.dest Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `xsl_script_execution_with_wmic_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [process_wmic](https://github.com/splunk/security_content/blob/develop/macros/process_wmic.yml)

Note that `xsl_script_execution_with_wmic_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.parent_process_name
* Processes.parent_process
* Processes.process_name
* Processes.process_id
* Processes.process
* Processes.dest
* Processes.user


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
unknown

#### Associated Analytic story
* [FIN7](/stories/fin7)
* [Suspicious WMI Use](/stories/suspicious_wmi_use)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ utilizing wmic to load a XSL script. |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html)
* [https://attack.mitre.org/groups/G0046/](https://attack.mitre.org/groups/G0046/)
* [https://web.archive.org/web/20190814201250/https://subt0x11.blogspot.com/2018/04/wmicexe-whitelisting-bypass-hacking.html](https://web.archive.org/web/20190814201250/https://subt0x11.blogspot.com/2018/04/wmicexe-whitelisting-bypass-hacking.html)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1220/T1220.md#atomic-test-3---wmic-bypass-using-local-xsl-file](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1220/T1220.md#atomic-test-3---wmic-bypass-using-local-xsl-file)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/fin7/fin7_macro_js_1/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/fin7/fin7_macro_js_1/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/xsl_script_execution_with_wmic.yml) \| *version*: **1**