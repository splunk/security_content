---
title: "Mmc LOLBAS Execution Process Spawn"
excerpt: "Remote Services
, Distributed Component Object Model
"
categories:
  - Endpoint
last_modified_at: 2021-11-23
toc: true
toc_label: ""
tags:
  - Remote Services
  - Distributed Component Object Model
  - Lateral Movement
  - Lateral Movement
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies `mmc.exe` spawning a LOLBAS execution process. When adversaries execute code on remote endpoints abusing the DCOM protocol and the MMC20 COM object, the executed command is spawned as a child processs of `mmc.exe`. The LOLBAS project documents Windows native binaries that can be abused by threat actors to perform tasks like executing malicious code. Looking for child processes of mmc.exe that are part of the LOLBAS project can help defenders identify lateral movement activity.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-11-23
- **Author**: Mauricio Velazco, Splunk
- **ID**: f6601940-4c74-11ec-b9b7-3e22fbd008af


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | Lateral Movement |

| [T1021.003](https://attack.mitre.org/techniques/T1021/003/) | Distributed Component Object Model | Lateral Movement |

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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name=mmc.exe) (Processes.process_name IN ("Regsvcs.exe", "Ftp.exe", "OfflineScannerShell.exe", "Rasautou.exe", "Schtasks.exe", "Xwizard.exe", "Dllhost.exe", "Pnputil.exe", "Atbroker.exe", "Pcwrun.exe", "Ttdinject.exe","Mshta.exe", "Bitsadmin.exe", "Certoc.exe", "Ieexec.exe", "Microsoft.Workflow.Compiler.exe", "Runscripthelper.exe", "Forfiles.exe", "Msbuild.exe", "Register-cimprovider.exe", "Tttracer.exe", "Ie4uinit.exe", "Bash.exe", "Hh.exe", "SettingSyncHost.exe", "Cmstp.exe", "Mmc.exe", "Stordiag.exe", "Scriptrunner.exe", "Odbcconf.exe", "Extexport.exe", "Msdt.exe", "WorkFolders.exe", "Diskshadow.exe", "Mavinject.exe", "Regasm.exe", "Gpscript.exe", "Rundll32.exe", "Regsvr32.exe", "Msiexec.exe", "Wuauclt.exe", "Presentationhost.exe", "Wmic.exe", "Runonce.exe", "Syncappvpublishingserver.exe", "Verclsid.exe", "Infdefaultinstall.exe", "Explorer.exe", "Installutil.exe", "Netsh.exe", "Wab.exe", "Dnscmd.exe", "At.exe", "Pcalua.exe", "Msconfig.exe")) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `mmc_lolbas_execution_process_spawn_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **mmc_lolbas_execution_process_spawn_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
| 54.0 | 90 | 60 | Mmc.exe spawned a LOLBAS process on $dest |


#### Reference

* [https://attack.mitre.org/techniques/T1021/003/](https://attack.mitre.org/techniques/T1021/003/)
* [https://www.cybereason.com/blog/dcom-lateral-movement-techniques](https://www.cybereason.com/blog/dcom-lateral-movement-techniques)
* [https://lolbas-project.github.io/](https://lolbas-project.github.io/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.003/lateral_movement_lolbas/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.003/lateral_movement_lolbas/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/mmc_lolbas_execution_process_spawn.yml) \| *version*: **1**