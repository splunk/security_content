---
title: "Linux Setuid Using Setcap Utility"
excerpt: "Setuid and Setgid
, Abuse Elevation Control Mechanism
"
categories:
  - Endpoint
last_modified_at: 2021-12-21
toc: true
toc_label: ""
tags:
  - Setuid and Setgid
  - Abuse Elevation Control Mechanism
  - Defense Evasion
  - Privilege Escalation
  - Defense Evasion
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic looks for suspicious setcap utility execution to enable SUID bit. This allows a user to temporarily gain root access, usually in order to run a program. For example, only the root account is allowed to change the password information contained in the password database; If the SUID bit appears as an s, the file's owner also has execute permission to the file; if it appears as an S, the file's owner does not have execute permission. The second specialty permission is the SGID, or set group id bit. It is similar to the SUID bit, except it can temporarily change group membership, usually to execute a program. The SGID bit is set if an s or an S appears in the group section of permissions.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2021-12-21
- **Author**: Teoderick Contreras, Splunk
- **ID**: 9d96022e-6250-11ec-9a19-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1548.001](https://attack.mitre.org/techniques/T1548/001/) | Setuid and Setgid | Defense Evasion, Privilege Escalation |

| [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism | Defense Evasion, Privilege Escalation |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name = setcap OR Processes.process = "*setcap *") AND Processes.process IN ("* cap_setuid=ep *", "* cap_setuid+ep *", "* cap_net_bind_service+p *", "* cap_net_raw+ep *", "* cap_dac_read_search+ep *") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.process_guid 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `linux_setuid_using_setcap_utility_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `linux_setuid_using_setcap_utility_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_id


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you can use the Add-on for Linux Sysmon from Splunkbase.

#### Known False Positives
Administrator or network operator can execute this command. Please update the filter macros to remove false positives.

#### Associated Analytic story
* [Linux Privilege Escalation](/stories/linux_privilege_escalation)
* [Linux Persistence Techniques](/stories/linux_persistence_techniques)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | A commandline $process$ that may set suid or sgid on $dest$ |




#### Reference

* [https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/](https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.001/linux_setcap/sysmon_linux.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.001/linux_setcap/sysmon_linux.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/linux_setuid_using_setcap_utility.yml) \| *version*: **1**