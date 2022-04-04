---
title: "Svchost LOLBAS Execution Process Spawn"
excerpt: "Scheduled Task/Job
, Scheduled Task
"
categories:
  - Endpoint
last_modified_at: 2021-11-22
toc: true
toc_label: ""
tags:
  - Scheduled Task/Job
  - Scheduled Task
  - Execution
  - Persistence
  - Privilege Escalation
  - Execution
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies `svchost.exe` spawning a LOLBAS execution process. When adversaries execute code on remote endpoints abusing the Task Scheduler and creating a malicious remote scheduled task, the executed command is spawned as a child process of `svchost.exe`. The LOLBAS project documents Windows native binaries that can be abused by threat actors to perform tasks like executing malicious code. Looking for child processes of svchost.exe that are part of the LOLBAS project can help defenders identify lateral movement activity.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-11-22
- **Author**: Mauricio Velazco, Splunk
- **ID**: 09e5c72a-4c0d-11ec-aa29-3e22fbd008af


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |

| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task | Execution, Persistence, Privilege Escalation |

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



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name=svchost.exe) (Processes.process_name IN ("Regsvcs.exe", "Ftp.exe", "OfflineScannerShell.exe", "Rasautou.exe", "Schtasks.exe", "Xwizard.exe", "Pnputil.exe", "Atbroker.exe", "Pcwrun.exe", "Ttdinject.exe","Mshta.exe", "Bitsadmin.exe", "Certoc.exe", "Ieexec.exe", "Microsoft.Workflow.Compiler.exe", "Runscripthelper.exe", "Forfiles.exe", "Msbuild.exe", "Register-cimprovider.exe", "Tttracer.exe", "Ie4uinit.exe", "Bash.exe", "Hh.exe", "SettingSyncHost.exe", "Cmstp.exe", "Stordiag.exe", "Scriptrunner.exe", "Odbcconf.exe", "Extexport.exe", "Msdt.exe", "WorkFolders.exe", "Diskshadow.exe", "Mavinject.exe", "Regasm.exe", "Gpscript.exe", "Regsvr32.exe", "Msiexec.exe", "Wuauclt.exe", "Presentationhost.exe", "Wmic.exe", "Runonce.exe", "Syncappvpublishingserver.exe", "Verclsid.exe", "Infdefaultinstall.exe", "Installutil.exe", "Netsh.exe", "Wab.exe", "Dnscmd.exe", "At.exe", "Pcalua.exe", "Msconfig.exe")) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `svchost_lolbas_execution_process_spawn_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **svchost_lolbas_execution_process_spawn_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints.

#### Known False Positives
Legitimate applications may trigger this behavior, filter as needed.

#### Associated Analytic story
* [Active Directory Lateral Movement](/stories/active_directory_lateral_movement)
* [Living Off The Land](/stories/living_off_the_land)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 54.0 | 90 | 60 | Svchost.exe spawned a LOLBAS process on $dest |


#### Reference

* [https://attack.mitre.org/techniques/T1053/005/](https://attack.mitre.org/techniques/T1053/005/)
* [https://www.ired.team/offensive-security/persistence/t1053-schtask](https://www.ired.team/offensive-security/persistence/t1053-schtask)
* [https://lolbas-project.github.io/](https://lolbas-project.github.io/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/lateral_movement_lolbas/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/lateral_movement_lolbas/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/svchost_lolbas_execution_process_spawn.yml) \| *version*: **1**