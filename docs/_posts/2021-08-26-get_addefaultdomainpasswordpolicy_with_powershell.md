---
title: "Get ADDefaultDomainPasswordPolicy with Powershell"
excerpt: "Password Policy Discovery"
categories:
  - Endpoint
last_modified_at: 2021-08-26
toc: true
toc_label: ""
tags:
  - Password Policy Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic looks for the execution of `powershell.exe` executing the Get-ADDefaultDomainPasswordPolicy commandlet used to obtain the password policy in a Windows domain. Red Teams and adversaries alike may use PowerShell to enumerate domain policies for situational awareness and Active Directory Discovery.

- **Type**: Hunting
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-08-26
- **Author**: Teoderick Contreras, Splunk
- **ID**: 36e46ebe-065a-11ec-b4c7-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1201](https://attack.mitre.org/techniques/T1201/) | Password Policy Discovery | Discovery |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="cmd.exe" OR Processes.process_name="powershell*") AND Processes.process = "*Get-ADDefaultDomainPasswordPolicy*" by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.parent_process_name 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `get_addefaultdomainpasswordpolicy_with_powershell_filter`
```

#### Associated Analytic Story
* [Active Directory Discovery](/stories/active_directory_discovery)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances where renamed rundll32.exe may be used.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_id
* Processes.parent_process_name


#### Kill Chain Phase
* Reconnaissance


#### Known False Positives
Administrators or power users may use this command for troubleshooting.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 9.0 | 30 | 30 | an instance of process $process_name$ with commandline $process$ in $dest$ |




#### Reference

* [https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)
* [https://attack.mitre.org/techniques/T1201/](https://attack.mitre.org/techniques/T1201/)
* [https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-addefaultdomainpasswordpolicy?view=windowsserver2019-ps](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-addefaultdomainpasswordpolicy?view=windowsserver2019-ps)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1201/pwd_policy_discovery/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1201/pwd_policy_discovery/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/get_addefaultdomainpasswordpolicy_with_powershell.yml) \| *version*: **1**