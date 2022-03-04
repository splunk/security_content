---
title: "Wget Download and Bash Execution"
excerpt: "Ingress Tool Transfer
"
categories:
  - Endpoint
last_modified_at: 2021-12-11
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



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the use of wget on Linux or MacOS attempting to download a file from a remote source and pipe it to bash. This is typically found with coinminers and most recently with CVE-2021-44228, a vulnerability in Log4j.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-12-11
- **Author**: Michael Haag, Splunk
- **ID**: 35682718-5a85-11ec-b8f7-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | Command And Control |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=wget (Processes.process="*-q *" OR Processes.process="*--quiet*"  AND Processes.process="*-O- *") OR (Processes.process="*
|*" AND Processes.process="*bash*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `wget_download_and_bash_execution_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `wget_download_and_bash_execution_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.parent_process
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_path
* Processes.process_path
* Processes.parent_process_id


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon for Linux, you will need to ensure mapping is occurring correctly. If the EDR is not parsing the pipe bash in the command-line, modifying the analytic will be required. Add parent process name (Processes.parent_process_name) as needed to filter.

#### Known False Positives
False positives should be limited, however filtering may be required.

#### Associated Analytic story
* [Ingress Tool Transfer](/stories/ingress_tool_transfer)
* [Log4Shell CVE-2021-44228](/stories/log4shell_cve-2021-44228)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $process_name$ was identified on endpoint $dest$ attempting to download a remote file and run it with bash. |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://www.huntress.com/blog/rapid-response-critical-rce-vulnerability-is-affecting-java](https://www.huntress.com/blog/rapid-response-critical-rce-vulnerability-is-affecting-java)
* [https://www.lunasec.io/docs/blog/log4j-zero-day/](https://www.lunasec.io/docs/blog/log4j-zero-day/)
* [https://gist.github.com/nathanqthai/01808c569903f41a52e7e7b575caa890](https://gist.github.com/nathanqthai/01808c569903f41a52e7e7b575caa890)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/atomic_red_team/linux-sysmon_curlwget.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/atomic_red_team/linux-sysmon_curlwget.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/wget_download_and_bash_execution.yml) \| *version*: **1**