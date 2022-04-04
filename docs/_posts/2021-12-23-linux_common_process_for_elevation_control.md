---
title: "Linux Common Process For Elevation Control"
excerpt: "Setuid and Setgid
, Abuse Elevation Control Mechanism
"
categories:
  - Endpoint
last_modified_at: 2021-12-23
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

This analytic is to look for possible elevation control access using a common known process in linux platform to change the attribute and file ownership. This technique is commonly abused by adversaries, malware author and red teamers to gain persistence or privilege escalation on the target or compromised host. This common process is used to modify file attribute, file ownership or SUID. This tools can be used in legitimate purposes so filter is needed.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-12-23
- **Author**: Teoderick Contreras, Splunk
- **ID**: 66ab15c0-63d0-11ec-9e70-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1548.001](https://attack.mitre.org/techniques/T1548/001/) | Setuid and Setgid | Defense Evasion, Privilege Escalation |

| [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism | Defense Evasion, Privilege Escalation |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Exploitation


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 5
* CIS 16



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("chmod", "chown", "fchmod", "fchmodat", "fchown", "fchownat", "fremovexattr", "fsetxattr", "lchown", "lremovexattr", "lsetxattr", "removexattr", "setuid", "setgid", "setreuid", "setregid", "chattr") OR Processes.process IN ("*chmod *", "*chown *", "*fchmod *", "*fchmodat *", "*fchown *", "*fchownat *", "*fremovexattr *", "*fsetxattr *", "*lchown *", "*lremovexattr *", "*lsetxattr *", "*removexattr *", "*setuid *", "*setgid *", "*setreuid *", "*setregid *", "*setcap *", "*chattr *") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.process_guid 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `linux_common_process_for_elevation_control_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **linux_common_process_for_elevation_control_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 9.0 | 30 | 30 | A commandline $process$ with process $process_name$ on $dest$ |


#### Reference

* [https://attack.mitre.org/techniques/T1548/001/](https://attack.mitre.org/techniques/T1548/001/)
* [https://github.com/Neo23x0/auditd/blob/master/audit.rules#L285-L297](https://github.com/Neo23x0/auditd/blob/master/audit.rules#L285-L297)
* [https://github.com/bfuzzy1/auditd-attack/blob/master/auditd-attack/auditd-attack.rules#L269-L270](https://github.com/bfuzzy1/auditd-attack/blob/master/auditd-attack/auditd-attack.rules#L269-L270)
* [https://github.com/microsoft/MSTIC-Sysmon/blob/main/linux/configs/attack-based/privilege_escalation/T1548.001_ElevationControl_CommonProcesses.xml](https://github.com/microsoft/MSTIC-Sysmon/blob/main/linux/configs/attack-based/privilege_escalation/T1548.001_ElevationControl_CommonProcesses.xml)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.001/chmod_uid/sysmon_linux.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.001/chmod_uid/sysmon_linux.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/linux_common_process_for_elevation_control.yml) \| *version*: **1**