---
title: "Wmiprsve LOLBAS Execution Process Spawn"
excerpt: "Windows Management Instrumentation"
categories:
  - Endpoint
last_modified_at: 2021-11-22
toc: true
toc_label: ""
tags:
  - Windows Management Instrumentation
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies `wmiprsve.exe` spawning a LOLBAS execution process. When adversaries execute code on remote endpoints abusing Windows Management Instrumentation (WMI), the executed command is spawned as a child process of `wmiprvse.exe`. The LOLBAS project documents Windows native binaries that can be abused by threat actors to perform tasks like executing malicious code. Looking for child processes of wmiprvse.exe that are part of the LOLBAS project can help defenders identify lateral movement activity.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-11-22
- **Author**: Mauricio Velazco, Splunk
- **ID**: 95a455f0-4c04-11ec-b8ac-3e22fbd008af


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1047](https://attack.mitre.org/techniques/T1047/) | Windows Management Instrumentation | Execution |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name=wmiprvse.exe) (Processes.process_name IN ("Regsvcs.exe", "Ftp.exe", "OfflineScannerShell.exe", "Rasautou.exe", "Schtasks.exe", "Xwizard.exe", "Dllhost.exe", "Pnputil.exe", "Atbroker.exe", "Pcwrun.exe", "Ttdinject.exe","Mshta.exe", "Bitsadmin.exe", "Certoc.exe", "Ieexec.exe", "Microsoft.Workflow.Compiler.exe", "Runscripthelper.exe", "Forfiles.exe", "Msbuild.exe", "Register-cimprovider.exe", "Tttracer.exe", "Ie4uinit.exe", "Bash.exe", "Hh.exe", "SettingSyncHost.exe", "Cmstp.exe", "Mmc.exe", "Stordiag.exe", "Scriptrunner.exe", "Odbcconf.exe", "Extexport.exe", "Msdt.exe", "WorkFolders.exe", "Diskshadow.exe", "Mavinject.exe", "Regasm.exe", "Gpscript.exe", "Rundll32.exe", "Regsvr32.exe", "Msiexec.exe", "Wuauclt.exe", "Presentationhost.exe", "Wmic.exe", "Runonce.exe", "Syncappvpublishingserver.exe", "Verclsid.exe", "Infdefaultinstall.exe", "Explorer.exe", "Installutil.exe", "Netsh.exe", "Wab.exe", "Dnscmd.exe", "At.exe", "Pcalua.exe", "Msconfig.exe")) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `wmiprsve_lolbas_execution_process_spawn_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `wmiprsve_lolbas_execution_process_spawn_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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


#### Kill Chain Phase
* Lateral Movement



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 54.0 | 90 | 60 | Wmiprsve.exe spawned a LOLBAS process on $dest$. |




#### Reference

* [https://attack.mitre.org/techniques/T1047/](https://attack.mitre.org/techniques/T1047/)
* [https://www.ired.team/offensive-security/lateral-movement/t1047-wmi-for-lateral-movement](https://www.ired.team/offensive-security/lateral-movement/t1047-wmi-for-lateral-movement)
* [https://lolbas-project.github.io/](https://lolbas-project.github.io/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1047/lateral_movement_lolbas/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1047/lateral_movement_lolbas/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/wmiprsve_lolbas_execution_process_spawn.yml) \| *version*: **1**