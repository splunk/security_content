---
title: "Linux pkexec Privilege Escalation"
excerpt: "Exploitation for Privilege Escalation
"
categories:
  - Endpoint
last_modified_at: 2022-01-28
toc: true
toc_label: ""
tags:

  - Exploitation for Privilege Escalation
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies `pkexec` spawning with no command-line arguments. A vulnerability in Polkit's pkexec component identified as CVE-2021-4034 (PwnKit) which is present in the default configuration of all major Linux distributions and can be exploited to gain full root privileges on the system.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-01-28
- **Author**: Michael Haag, Splunk
- **ID**: 03e22c1c-8086-11ec-ac2e-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1068](https://attack.mitre.org/techniques/T1068/) | Exploitation for Privilege Escalation | Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes where Processes.process_name=pkexec by _time Processes.dest Processes.process_id Processes.parent_process_name Processes.process_name Processes.process Processes.process_path 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| regex process="(^.{1}$)" 
| `linux_pkexec_privilege_escalation_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `linux_pkexec_privilege_escalation_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.parent_process
* Processes.original_file_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_path
* Processes.process_path
* Processes.parent_process_id


#### How To Implement
Depending on the EDR product in use, there are multiple ways to "null" the command-line field, Processes.process. Two that may be useful `process="(^.{0}$)"` or `| where isnull(process)`. To generate data for this behavior, Sysmon for Linux was utilized. To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
False positives may be present, filter as needed.

#### Associated Analytic story
* [Linux Privilege Escalation](/stories/linux_privilege_escalation)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 56.0 | 80 | 70 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ related to a local privilege escalation in polkit pkexec. |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://www.reddit.com/r/crowdstrike/comments/sdfeig/20220126_cool_query_friday_hunting_pwnkit_local/](https://www.reddit.com/r/crowdstrike/comments/sdfeig/20220126_cool_query_friday_hunting_pwnkit_local/)
* [https://linux.die.net/man/1/pkexec](https://linux.die.net/man/1/pkexec)
* [https://www.bleepingcomputer.com/news/security/linux-system-service-bug-gives-root-on-all-major-distros-exploit-released/](https://www.bleepingcomputer.com/news/security/linux-system-service-bug-gives-root-on-all-major-distros-exploit-released/)
* [https://access.redhat.com/security/security-updates/#/?q=polkit&p=1&sort=portal_publication_date%20desc&rows=10&portal_advisory_type=Security%20Advisory&documentKind=PortalProduct](https://access.redhat.com/security/security-updates/#/?q=polkit&p=1&sort=portal_publication_date%20desc&rows=10&portal_advisory_type=Security%20Advisory&documentKind=PortalProduct)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1068/zoom_child_process/linux-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1068/zoom_child_process/linux-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/linux_pkexec_privilege_escalation.yml) \| *version*: **1**