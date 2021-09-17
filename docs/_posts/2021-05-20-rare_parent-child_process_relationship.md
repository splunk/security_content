---
title: "Rare Parent-Child Process Relationship"
excerpt: "Exploitation for Client Execution, Command and Scripting Interpreter, Scheduled Task/Job, Software Deployment Tools"
categories:
  - Endpoint
last_modified_at: 2021-05-20
toc: true
tags:
  - Anomaly
  - T1203
  - Exploitation for Client Execution
  - Execution
  - T1059
  - Command and Scripting Interpreter
  - Execution
  - T1053
  - Scheduled Task/Job
  - Execution
  - Persistence
  - Privilege Escalation
  - T1072
  - Software Deployment Tools
  - Execution
  - Lateral Movement
  - Splunk Behavioral Analytics
  - Exploitation
---

# Rare Parent-Child Process Relationship

An attacker may use LOLBAS tools spawned from vulnerable applications not typically used by system administrators. This search leverages the Splunk Streaming ML DSP plugin to find rare parent/child relationships. The list of application has been extracted from https://github.com/LOLBAS-Project/LOLBAS/tree/master/yml/OSBinaries

- **Product**: Splunk Behavioral Analytics
- **Datamodel**:
- **ATT&CK**: [T1203](https://attack.mitre.org/techniques/T1203/), [T1059](https://attack.mitre.org/techniques/T1059/), [T1053](https://attack.mitre.org/techniques/T1053/), [T1072](https://attack.mitre.org/techniques/T1072/)
- **Last Updated**: 2021-05-20
- **Author**: Peter Gael, Splunk; Ignacio Bermudez Corrales, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1203 | Exploitation for Client Execution | Execution |
| T1059 | Command and Scripting Interpreter | Execution |
| T1053 | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |
| T1072 | Software Deployment Tools | Execution, Lateral Movement |


#### Search

```

| from read_ssa_enriched_events() 
| eval timestamp=parse_long(ucast(map_get(input_event, &#34;_time&#34;), &#34;string&#34;, null)) 
| eval parent_process=lower(ucast(map_get(input_event, &#34;parent_process_name&#34;), &#34;string&#34;, null)), parent_process_name=mvindex(split(parent_process, &#34;\\&#34;), -1), process_name=lower(ucast(map_get(input_event, &#34;process_name&#34;), &#34;string&#34;, null)), cmd_line=ucast(map_get(input_event, &#34;process&#34;), &#34;string&#34;, null), dest_user_id=ucast(map_get(input_event, &#34;dest_user_id&#34;), &#34;string&#34;, null), dest_device_id=ucast(map_get(input_event, &#34;dest_device_id&#34;), &#34;string&#34;, null), event_id=ucast(map_get(input_event, &#34;event_id&#34;), &#34;string&#34;, null) 
| where parent_process_name!=null 
| select parent_process_name, process_name, cmd_line, timestamp, dest_device_id, dest_user_id 
| conditional_anomaly conditional=&#34;parent_process_name&#34; target=&#34;process_name&#34; 
| where (process_name=&#34;powershell.exe&#34; OR process_name=&#34;regsvcs.exe&#34; OR process_name=&#34;ftp.exe&#34; OR process_name=&#34;dfsvc.exe&#34; OR process_name=&#34;rasautou.exe&#34; OR process_name=&#34;schtasks.exe&#34; OR process_name=&#34;xwizard.exe&#34; OR process_name=&#34;findstr.exe&#34; OR process_name=&#34;esentutl.exe&#34; OR process_name=&#34;cscript.exe&#34; OR process_name=&#34;reg.exe&#34; OR process_name=&#34;csc.exe&#34; OR process_name=&#34;atbroker.exe&#34; OR process_name=&#34;print.exe&#34; OR process_name=&#34;pcwrun.exe&#34; OR process_name=&#34;vbc.exe&#34; OR process_name=&#34;rpcping.exe&#34; OR process_name=&#34;wsreset.exe&#34; OR process_name=&#34;ilasm.exe&#34; OR process_name=&#34;certutil.exe&#34; OR process_name=&#34;replace.exe&#34; OR process_name=&#34;mshta.exe&#34; OR process_name=&#34;bitsadmin.exe&#34; OR process_name=&#34;wscript.exe&#34; OR process_name=&#34;ieexec.exe&#34; OR process_name=&#34;cmd.exe&#34; OR process_name=&#34;microsoft.workflow.compiler.exe&#34; OR process_name=&#34;runscripthelper.exe&#34; OR process_name=&#34;makecab.exe&#34; OR process_name=&#34;forfiles.exe&#34; OR process_name=&#34;desktopimgdownldr.exe&#34; OR process_name=&#34;control.exe&#34; OR process_name=&#34;msbuild.exe&#34; OR process_name=&#34;register-cimprovider.exe&#34; OR process_name=&#34;tttracer.exe&#34; OR process_name=&#34;ie4uinit.exe&#34; OR process_name=&#34;sc.exe&#34; OR process_name=&#34;bash.exe&#34; OR process_name=&#34;hh.exe&#34; OR process_name=&#34;cmstp.exe&#34; OR process_name=&#34;mmc.exe&#34; OR process_name=&#34;jsc.exe&#34; OR process_name=&#34;scriptrunner.exe&#34; OR process_name=&#34;odbcconf.exe&#34; OR process_name=&#34;extexport.exe&#34; OR process_name=&#34;msdt.exe&#34; OR process_name=&#34;diskshadow.exe&#34; OR process_name=&#34;extrac32.exe&#34; OR process_name=&#34;eventvwr.exe&#34; OR process_name=&#34;mavinject.exe&#34; OR process_name=&#34;regasm.exe&#34; OR process_name=&#34;gpscript.exe&#34; OR process_name=&#34;rundll32.exe&#34; OR process_name=&#34;regsvr32.exe&#34; OR process_name=&#34;regedit.exe&#34; OR process_name=&#34;msiexec.exe&#34; OR process_name=&#34;gfxdownloadwrapper.exe&#34; OR process_name=&#34;presentationhost.exe&#34; OR process_name=&#34;regini.exe&#34; OR process_name=&#34;wmic.exe&#34; OR process_name=&#34;runonce.exe&#34; OR process_name=&#34;syncappvpublishingserver.exe&#34; OR process_name=&#34;verclsid.exe&#34; OR process_name=&#34;psr.exe&#34; OR process_name=&#34;infdefaultinstall.exe&#34; OR process_name=&#34;explorer.exe&#34; OR process_name=&#34;expand.exe&#34; OR process_name=&#34;installutil.exe&#34; OR process_name=&#34;netsh.exe&#34; OR process_name=&#34;wab.exe&#34; OR process_name=&#34;dnscmd.exe&#34; OR process_name=&#34;at.exe&#34; OR process_name=&#34;pcalua.exe&#34; OR process_name=&#34;cmdkey.exe&#34; OR process_name=&#34;msconfig.exe&#34;) 
| eval input = (-1)*log(output) 
| adaptive_threshold algorithm=&#34;gaussian&#34; threshold=0.001 window=604800000L 
| where label AND input &gt; mean 
| eval start_time = timestamp, end_time = timestamp, entities = mvappend(dest_device_id, dest_user_id), body = create_map([&#34;process_name&#34;, process_name, &#34;parent_process_name&#34;, parent_process_name, &#34;input&#34;, input, &#34;mean&#34;, mean, &#34;variance&#34;, variance, &#34;output&#34;, output, &#34;cmd_line&#34;, cmd_line]) 
| into write_ssa_detected_events();
```

#### Associated Analytic Story

* [Unusual Processes](_stories/unusual_processes)


#### How To Implement
Collect endpoint data such as sysmon or 4688 events.

#### Required field

* process

* process_name

* parent_process_name

* _time

* dest_device_id

* dest_user_id


#### Kill Chain Phase

* Exploitation


#### Known False Positives
Some custom tools used by admins could be used rarely to launch remotely applications. This might trigger false positives at the beginning when it hasn&#39;t collected yet enough data to construct the baseline.





#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



_version_: 1

```
#############
# Automatically generated by doc_gen.py in https://github.com/splunk/security_content''
# On Date: 2021-09-17 11:18:22.156814 UTC''
# Author: Splunk Security Research''
# Contact: research@splunk.com''
#############
```