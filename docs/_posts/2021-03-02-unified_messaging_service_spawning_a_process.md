---
title: "Unified Messaging Service Spawning a Process"
excerpt: "Exploit Public-Facing Application
"
categories:
  - Endpoint
last_modified_at: 2021-03-02
toc: true
toc_label: ""
tags:
  - Exploit Public-Facing Application
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2021-26857
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This detection identifies Microsoft Exchange Server's Unified Messaging services, umworkerprocess.exe and umservice.exe, spawning a child process, indicating possible exploitation of CVE-2021-26857 vulnerability. The query filters out werfault.exe and wermgr.exe mostly due to potential false positives, however, if there is an excessive amount of "wermgr.exe" or "WerFault.exe" failures, it may be due to the active exploitation. During triage, identify any additional suspicious parallel processes. Identify any recent out of place file modifications. Review Exchange logs following Microsofts guide. To contain, perform egress filtering or restrict public access to Exchange. In final, patch the vulnerablity and monitor.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-03-02
- **Author**: Michael Haag, Splunk
- **ID**: f1126df0-7bd5-11eb-988f-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Initial Access |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="umworkerprocess.exe" OR Processes.parent_process_name="UMService.exe" (Processes.process_name!="wermgr.exe" OR Processes.process_name!="werfault.exe") by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `unified_messaging_service_spawning_a_process_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `unified_messaging_service_spawning_a_process_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
Unknown. Tune out child processes as needed to limit volume of false positives.

#### Associated Analytic story
* [HAFNIUM Group](/stories/hafnium_group)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 70 | 80 | Possible CVE-2021-26857 exploitation on $dest$ |


#### CVE

| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2021-26857](https://nvd.nist.gov/vuln/detail/CVE-2021-26857) | Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, CVE-2021-26854, CVE-2021-26855, CVE-2021-26858, CVE-2021-27065, CVE-2021-27078. | 6.8 |



#### Reference

* [https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/](https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/)
* [https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/](https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/)
* [https://blog.rapid7.com/2021/03/03/rapid7s-insightidr-enables-detection-and-response-to-microsoft-exchange-0-day/](https://blog.rapid7.com/2021/03/03/rapid7s-insightidr-enables-detection-and-response-to-microsoft-exchange-0-day/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.003/windows-sysmon_umservices.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.003/windows-sysmon_umservices.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/unified_messaging_service_spawning_a_process.yml) \| *version*: **1**