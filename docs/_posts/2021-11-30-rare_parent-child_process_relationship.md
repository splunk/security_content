---
title: "Rare Parent-Child Process Relationship"
excerpt: "Exploitation for Client Execution, Command and Scripting Interpreter, Scheduled Task/Job, Software Deployment Tools"
categories:
  - Endpoint
last_modified_at: 2021-11-30
toc: true
toc_label: ""
tags:
  - Exploitation for Client Execution
  - Execution
  - Command and Scripting Interpreter
  - Execution
  - Scheduled Task/Job
  - Execution
  - Persistence
  - Privilege Escalation
  - Software Deployment Tools
  - Execution
  - Lateral Movement
  - Splunk Behavioral Analytics
  - Endpoint_Processes
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

An attacker may use LOLBAS tools spawned from vulnerable applications not typically used by system administrators. This analytic leverages the Splunk Streaming ML DSP plugin to find rare parent/child relationships. The list of application has been extracted from https://github.com/LOLBAS-Project/LOLBAS/tree/master/yml/OSBinaries

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2021-11-30
- **Author**: Peter Gael, Splunk; Ignacio Bermudez Corrales, Splunk
- **ID**: cf090c78-bcc6-11eb-8529-0242ac130003


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1203](https://attack.mitre.org/techniques/T1203/) | Exploitation for Client Execution | Execution |

| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |

| [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |

| [T1072](https://attack.mitre.org/techniques/T1072/) | Software Deployment Tools | Execution, Lateral Movement |

#### Search

```

| from read_ssa_enriched_events() 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)) 
| eval parent_process=lower(ucast(map_get(input_event, "parent_process_name"), "string", null)), parent_process_name=mvindex(split(parent_process, "\\"), -1), process_name=lower(ucast(map_get(input_event, "process_name"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), dest_user_id=ucast(map_get(input_event, "dest_user_id"), "string", null), dest_device_id=ucast(map_get(input_event, "dest_device_id"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where parent_process_name!=null 
| select parent_process_name, process_name, cmd_line, timestamp, dest_device_id, dest_user_id 
| conditional_anomaly conditional="parent_process_name" target="process_name" 
| where (process_name="powershell.exe" OR process_name="regsvcs.exe" OR process_name="ftp.exe" OR process_name="dfsvc.exe" OR process_name="rasautou.exe" OR process_name="schtasks.exe" OR process_name="xwizard.exe" OR process_name="findstr.exe" OR process_name="esentutl.exe" OR process_name="cscript.exe" OR process_name="reg.exe" OR process_name="csc.exe" OR process_name="atbroker.exe" OR process_name="print.exe" OR process_name="pcwrun.exe" OR process_name="vbc.exe" OR process_name="rpcping.exe" OR process_name="wsreset.exe" OR process_name="ilasm.exe" OR process_name="certutil.exe" OR process_name="replace.exe" OR process_name="mshta.exe" OR process_name="bitsadmin.exe" OR process_name="wscript.exe" OR process_name="ieexec.exe" OR process_name="cmd.exe" OR process_name="microsoft.workflow.compiler.exe" OR process_name="runscripthelper.exe" OR process_name="makecab.exe" OR process_name="forfiles.exe" OR process_name="desktopimgdownldr.exe" OR process_name="control.exe" OR process_name="msbuild.exe" OR process_name="register-cimprovider.exe" OR process_name="tttracer.exe" OR process_name="ie4uinit.exe" OR process_name="sc.exe" OR process_name="bash.exe" OR process_name="hh.exe" OR process_name="cmstp.exe" OR process_name="mmc.exe" OR process_name="jsc.exe" OR process_name="scriptrunner.exe" OR process_name="odbcconf.exe" OR process_name="extexport.exe" OR process_name="msdt.exe" OR process_name="diskshadow.exe" OR process_name="extrac32.exe" OR process_name="eventvwr.exe" OR process_name="mavinject.exe" OR process_name="regasm.exe" OR process_name="gpscript.exe" OR process_name="rundll32.exe" OR process_name="regsvr32.exe" OR process_name="regedit.exe" OR process_name="msiexec.exe" OR process_name="gfxdownloadwrapper.exe" OR process_name="presentationhost.exe" OR process_name="regini.exe" OR process_name="wmic.exe" OR process_name="runonce.exe" OR process_name="syncappvpublishingserver.exe" OR process_name="verclsid.exe" OR process_name="psr.exe" OR process_name="infdefaultinstall.exe" OR process_name="explorer.exe" OR process_name="expand.exe" OR process_name="installutil.exe" OR process_name="netsh.exe" OR process_name="wab.exe" OR process_name="dnscmd.exe" OR process_name="at.exe" OR process_name="pcalua.exe" OR process_name="cmdkey.exe" OR process_name="msconfig.exe") 
| eval input = (-1)*log(output) 
| adaptive_threshold algorithm="gaussian" threshold=0.001 window=604800000L 
| where label AND input > mean 
| eval start_time = timestamp, end_time = timestamp, entities = mvappend(dest_device_id, dest_user_id), body = create_map(["process_name", process_name, "parent_process_name", parent_process_name, "input", input, "mean", mean, "variance", variance, "output", output, "cmd_line", cmd_line]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `rare_parent-child_process_relationship_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* process
* process_name
* parent_process_name
* _time
* dest_device_id
* dest_user_id
* cmd_line


#### How To Implement
Collect endpoint data such as sysmon or 4688 events.

#### Known False Positives
Some custom tools used by administrators could be used rarely to launch remotely applications. This might trigger false positives at the beginning when it has not collected yet enough data to construct the baseline.

#### Associated Analytic story
* [Unusual Processes](/stories/unusual_processes)


#### Kill Chain Phase
* Exploitation




Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://github.com/LOLBAS-Project/LOLBAS/tree/master/yml/OSBinaries](https://github.com/LOLBAS-Project/LOLBAS/tree/master/yml/OSBinaries)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/rare_parent-child_process_relationship.yml) \| *version*: **2**