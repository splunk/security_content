---
title: "Linux Possible Ssh Key File Creation"
excerpt: "SSH Authorized Keys
, Account Manipulation
"
categories:
  - Endpoint
last_modified_at: 2022-01-11
toc: true
toc_label: ""
tags:
  - SSH Authorized Keys
  - Account Manipulation
  - Persistence
  - Persistence
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to look for possible ssh key file creation on ~/.ssh/ folder. This technique is commonly abused by threat actors and adversaries to gain persistence and privilege escalation to the targeted host. by creating ssh private and public key and passing the public key to the attacker server. threat actor can access remotely the machine using openssh daemon service.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2022-01-11
- **Author**: Teoderick Contreras, Splunk
- **ID**: c04ef40c-72da-11ec-8eac-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1098.004](https://attack.mitre.org/techniques/T1098/004/) | SSH Authorized Keys | Persistence |

| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | Persistence |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("*/.ssh*") by Filesystem.dest Filesystem.file_name Filesystem.process_guid Filesystem.file_path 
| `drop_dm_object_name(Filesystem)` 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `linux_possible_ssh_key_file_creation_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `linux_possible_ssh_key_file_creation_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Filesystem.dest
* Filesystem.file_create_time
* Filesystem.file_name
* Filesystem.process_guid
* Filesystem.file_path


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the file name, file path, and process_guid executions from your endpoints. If you are using Sysmon, you can use the Add-on for Linux Sysmon from Splunkbase.

#### Known False Positives
Administrator or network operator can create file in ~/.ssh folders for automation purposes. Please update the filter macros to remove false positives.

#### Associated Analytic story
* [Linux Privilege Escalation](/stories/linux_privilege_escalation)
* [Linux Persistence Techniques](/stories/linux_persistence_techniques)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 36.0 | 60 | 60 | A file $file_name$ is created in $file_path$ on $dest$ |




#### Reference

* [https://www.hackingarticles.in/ssh-penetration-testing-port-22/](https://www.hackingarticles.in/ssh-penetration-testing-port-22/)
* [https://attack.mitre.org/techniques/T1098/004/](https://attack.mitre.org/techniques/T1098/004/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.004/ssh_authorized_keys/sysmon_linux.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.004/ssh_authorized_keys/sysmon_linux.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/linux_possible_ssh_key_file_creation.yml) \| *version*: **1**