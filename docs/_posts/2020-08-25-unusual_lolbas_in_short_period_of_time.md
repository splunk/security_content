---
title: "Unusual LOLBAS in short period of time"
excerpt: "Command and Scripting Interpreter, Scheduled Task/Job"
categories:
  - Endpoint
last_modified_at: 2020-08-25
toc: true
toc_label: ""
tags:
  - Command and Scripting Interpreter
  - Execution
  - Scheduled Task/Job
  - Execution
  - Persistence
  - Privilege Escalation
  - Splunk Behavioral Analytics
  - Endpoint_Processes
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Attacker activity may compromise executing several LOLBAS applications in conjunction to accomplish their objectives. We are looking for more than usual LOLBAS applications over a window of time, by building profiles per machine.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2020-08-25
- **Author**: Ignacio Bermudez Corrales, Splunk
- **ID**: 59c0dd70-169c-4900-9a1f-bfcf13302f93


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |

| [T1053](https://attack.mitre.org/techniques/T1053/) | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |

#### Search

```
 
| from read_ssa_enriched_events() 
| eval device=ucast(map_get(input_event, "dest_device_id"), "string", null), process_name=lower(ucast(map_get(input_event, "process_name"), "string", null)), timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)) 
| where process_name=="regsvcs.exe" OR process_name=="ftp.exe" OR process_name=="dfsvc.exe" OR process_name=="rasautou.exe" OR process_name=="schtasks.exe" OR process_name=="xwizard.exe" OR process_name=="findstr.exe" OR process_name=="esentutl.exe" OR process_name=="cscript.exe" OR process_name=="reg.exe" OR process_name=="csc.exe" OR process_name=="atbroker.exe" OR process_name=="print.exe" OR process_name=="pcwrun.exe" OR process_name=="vbc.exe" OR process_name=="rpcping.exe" OR process_name=="wsreset.exe" OR process_name=="ilasm.exe" OR process_name=="certutil.exe" OR process_name=="replace.exe" OR process_name=="mshta.exe" OR process_name=="bitsadmin.exe" OR process_name=="wscript.exe" OR process_name=="ieexec.exe" OR process_name=="cmd.exe" OR process_name=="microsoft.workflow.compiler.exe" OR process_name=="runscripthelper.exe" OR process_name=="makecab.exe" OR process_name=="forfiles.exe" OR process_name=="desktopimgdownldr.exe" OR process_name=="control.exe" OR process_name=="msbuild.exe" OR process_name=="register-cimprovider.exe" OR process_name=="tttracer.exe" OR process_name=="ie4uinit.exe" OR process_name=="sc.exe" OR process_name=="bash.exe" OR process_name=="hh.exe" OR process_name=="cmstp.exe" OR process_name=="mmc.exe" OR process_name=="jsc.exe" OR process_name=="scriptrunner.exe" OR process_name=="odbcconf.exe" OR process_name=="extexport.exe" OR process_name=="msdt.exe" OR process_name=="diskshadow.exe" OR process_name=="extrac32.exe" OR process_name=="eventvwr.exe" OR process_name=="mavinject.exe" OR process_name=="regasm.exe" OR process_name=="gpscript.exe" OR process_name=="rundll32.exe" OR process_name=="regsvr32.exe" OR process_name=="regedit.exe" OR process_name=="msiexec.exe" OR process_name=="gfxdownloadwrapper.exe" OR process_name=="presentationhost.exe" OR process_name=="regini.exe" OR process_name=="wmic.exe" OR process_name=="runonce.exe" OR process_name=="syncappvpublishingserver.exe" OR process_name=="verclsid.exe" OR process_name=="psr.exe" OR process_name=="infdefaultinstall.exe" OR process_name=="explorer.exe" OR process_name=="expand.exe" OR process_name=="installutil.exe" OR process_name=="netsh.exe" OR process_name=="wab.exe" OR process_name=="dnscmd.exe" OR process_name=="at.exe" OR process_name=="pcalua.exe" OR process_name=="cmdkey.exe" OR process_name=="msconfig.exe" 
| stats count(process_name) as lolbas_counter by device,span(timestamp, 300s) 
| eval lolbas_counter=lolbas_counter*1.0 
| rename window_end as timestamp 
| adaptive_threshold algorithm="quantile" value="lolbas_counter" entity="device" window=2419200000L 
| where label AND quantile>0.99 
| eval start_time = window_start, end_time = timestamp, entities = mvappend(device), body=create_map(["lolbas_counter", lolbas_counter, "quantile", quantile, "device", device]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `unusual_lolbas_in_short_period_of_time_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* dest_device_id
* _time
* process_name


#### How To Implement
Collect endpoint data such as sysmon or 4688 events.

#### Known False Positives
Some administrative tasks may involve multiple use of LOLBAS applications in a short period of time. This might trigger false positives at the beginning when it hasn&#39;t collected yet enough data to construct the baseline.


#### Associated Analytic story
* [Unusual Processes](/stories/unusual_processes)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | A system process $process_name$ with commandline $cmd_line$ spawn iin short period of time in host $dest_device_id$ |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://github.com/LOLBAS-Project/LOLBAS/tree/master/yml/OSBinaries](https://github.com/LOLBAS-Project/LOLBAS/tree/master/yml/OSBinaries)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/unusual_lolbas_in_short_period_of_time.yml) \| *version*: **2**