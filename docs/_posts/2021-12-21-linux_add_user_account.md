---
title: "Linux Add User Account"
excerpt: "Local Account, Create Account"
categories:
  - Endpoint
last_modified_at: 2021-12-21
toc: true
toc_label: ""
tags:
  - Local Account
  - Persistence
  - Create Account
  - Persistence
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic looks for commands to create user accounts on the linux platform. This technique is commonly abuse by adversaries, malware author and red teamers to persist on the targeted or compromised host by creating new user with an elevated privilege. This Hunting query may catch normal creation of user by administrator so filter is needed.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-12-21
- **Author**: Teoderick Contreras, Splunk
- **ID**: 51fbcaf2-6259-11ec-b0f3-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Local Account | Persistence |

| [T1136](https://attack.mitre.org/techniques/T1136/) | Create Account | Persistence |

#### Search

```

| tstats `security_content_summariesonly` count from datamodel=Endpoint.Processes where Processes.process_name IN ("useradd", "adduser") OR Processes.process IN ("*useradd *", "*adduser *") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.process_guid 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `linux_add_user_account_filter`
```

#### Associated Analytic Story
* [Linux Privilege Escalation](/stories/linux_privilege_escalation)
* [Linux Persistence Techniques](/stories/linux_persistence_techniques)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you can use the Add-on for Linux Sysmon from Splunkbase.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_id


#### Kill Chain Phase
* Privilege Escalation


#### Known False Positives
Administrator or network operator can execute this command. Please update the filter macros to remove false positives.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | A commandline $process$ that may create user account on $dest$ |




#### Reference

* [https://linuxize.com/post/how-to-create-users-in-linux-using-the-useradd-command/](https://linuxize.com/post/how-to-create-users-in-linux-using-the-useradd-command/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.003/linux_adduser/sysmon_linux.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1548.003/linux_adduser/sysmon_linux.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/linux_add_user_account.yml) \| *version*: **1**