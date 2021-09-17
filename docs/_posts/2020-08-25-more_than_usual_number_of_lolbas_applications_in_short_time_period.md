---
title: "More than usual number of LOLBAS applications in short time period"
excerpt: "Command and Scripting Interpreter, Scheduled Task/Job"
categories:
  - Endpoint
last_modified_at: 2020-08-25
toc: true
tags:
  - Anomaly
  - T1059
  - Command and Scripting Interpreter
  - Execution
  - T1053
  - Scheduled Task/Job
  - Execution
  - Persistence
  - Privilege Escalation
  - Splunk Behavioral Analytics
  - Exploitation
---

# More than usual number of LOLBAS applications in short time period

Attacker activity may compromise executing several LOLBAS applications in conjunction to accomplish their objectives. We are looking for more than usual LOLBAS applications over a window of time, by building profiles per machine.

- **Product**: Splunk Behavioral Analytics
- **Datamodel**:
- **ATT&CK**: [T1059](https://attack.mitre.org/techniques/T1059/), [T1053](https://attack.mitre.org/techniques/T1053/)
- **Last Updated**: 2020-08-25
- **Author**: Ignacio Bermudez Corrales, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| T1059 | Command and Scripting Interpreter | Execution |
| T1053 | Scheduled Task/Job | Execution, Persistence, Privilege Escalation |


#### Search

```
 
| from read_ssa_enriched_events() 
| eval device=ucast(map_get(input_event, &#34;dest_device_id&#34;), &#34;string&#34;, null), process_name=lower(ucast(map_get(input_event, &#34;process_name&#34;), &#34;string&#34;, null)), timestamp=parse_long(ucast(map_get(input_event, &#34;_time&#34;), &#34;string&#34;, null)) 
| where process_name==&#34;regsvcs.exe&#34; OR process_name==&#34;ftp.exe&#34; OR process_name==&#34;dfsvc.exe&#34; OR process_name==&#34;rasautou.exe&#34; OR process_name==&#34;schtasks.exe&#34; OR process_name==&#34;xwizard.exe&#34; OR process_name==&#34;findstr.exe&#34; OR process_name==&#34;esentutl.exe&#34; OR process_name==&#34;cscript.exe&#34; OR process_name==&#34;reg.exe&#34; OR process_name==&#34;csc.exe&#34; OR process_name==&#34;atbroker.exe&#34; OR process_name==&#34;print.exe&#34; OR process_name==&#34;pcwrun.exe&#34; OR process_name==&#34;vbc.exe&#34; OR process_name==&#34;rpcping.exe&#34; OR process_name==&#34;wsreset.exe&#34; OR process_name==&#34;ilasm.exe&#34; OR process_name==&#34;certutil.exe&#34; OR process_name==&#34;replace.exe&#34; OR process_name==&#34;mshta.exe&#34; OR process_name==&#34;bitsadmin.exe&#34; OR process_name==&#34;wscript.exe&#34; OR process_name==&#34;ieexec.exe&#34; OR process_name==&#34;cmd.exe&#34; OR process_name==&#34;microsoft.workflow.compiler.exe&#34; OR process_name==&#34;runscripthelper.exe&#34; OR process_name==&#34;makecab.exe&#34; OR process_name==&#34;forfiles.exe&#34; OR process_name==&#34;desktopimgdownldr.exe&#34; OR process_name==&#34;control.exe&#34; OR process_name==&#34;msbuild.exe&#34; OR process_name==&#34;register-cimprovider.exe&#34; OR process_name==&#34;tttracer.exe&#34; OR process_name==&#34;ie4uinit.exe&#34; OR process_name==&#34;sc.exe&#34; OR process_name==&#34;bash.exe&#34; OR process_name==&#34;hh.exe&#34; OR process_name==&#34;cmstp.exe&#34; OR process_name==&#34;mmc.exe&#34; OR process_name==&#34;jsc.exe&#34; OR process_name==&#34;scriptrunner.exe&#34; OR process_name==&#34;odbcconf.exe&#34; OR process_name==&#34;extexport.exe&#34; OR process_name==&#34;msdt.exe&#34; OR process_name==&#34;diskshadow.exe&#34; OR process_name==&#34;extrac32.exe&#34; OR process_name==&#34;eventvwr.exe&#34; OR process_name==&#34;mavinject.exe&#34; OR process_name==&#34;regasm.exe&#34; OR process_name==&#34;gpscript.exe&#34; OR process_name==&#34;rundll32.exe&#34; OR process_name==&#34;regsvr32.exe&#34; OR process_name==&#34;regedit.exe&#34; OR process_name==&#34;msiexec.exe&#34; OR process_name==&#34;gfxdownloadwrapper.exe&#34; OR process_name==&#34;presentationhost.exe&#34; OR process_name==&#34;regini.exe&#34; OR process_name==&#34;wmic.exe&#34; OR process_name==&#34;runonce.exe&#34; OR process_name==&#34;syncappvpublishingserver.exe&#34; OR process_name==&#34;verclsid.exe&#34; OR process_name==&#34;psr.exe&#34; OR process_name==&#34;infdefaultinstall.exe&#34; OR process_name==&#34;explorer.exe&#34; OR process_name==&#34;expand.exe&#34; OR process_name==&#34;installutil.exe&#34; OR process_name==&#34;netsh.exe&#34; OR process_name==&#34;wab.exe&#34; OR process_name==&#34;dnscmd.exe&#34; OR process_name==&#34;at.exe&#34; OR process_name==&#34;pcalua.exe&#34; OR process_name==&#34;cmdkey.exe&#34; OR process_name==&#34;msconfig.exe&#34; 
| stats count(process_name) as lolbas_counter by device,span(timestamp, 300s) 
| eval lolbas_counter=lolbas_counter*1.0 
| rename window_end as timestamp 
| adaptive_threshold algorithm=&#34;quantile&#34; value=&#34;lolbas_counter&#34; entity=&#34;device&#34; window=2419200000L 
| where label AND quantile&gt;0.99 
| eval start_time = window_start, end_time = timestamp, entities = mvappend(device), body=create_map([&#34;lolbas_counter&#34;, lolbas_counter]) 
| into write_null();
```

#### Associated Analytic Story

* [Unusual Processes](_stories/unusual_processes)


#### How To Implement
Collect endpoint data such as sysmon or 4688 events.

#### Required field

* dest_device_id

* _time

* process_name


#### Kill Chain Phase

* Exploitation


#### Known False Positives
Some administrative tasks may involve multiple use of LOLBAS applications in a short period of time. This might trigger false positives at the beginning when it hasn&#39;t collected yet enough data to construct the baseline.




#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 25.0 | 50 | 50 |



#### Reference


* [https://github.com/LOLBAS-Project/LOLBAS/tree/master/yml/OSBinaries](https://github.com/LOLBAS-Project/LOLBAS/tree/master/yml/OSBinaries)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



_version_: 2

```
#############
# Automatically generated by doc_gen.py in https://github.com/splunk/security_content''
# On Date: 2021-09-17 11:18:22.111208 UTC''
# Author: Splunk Security Research''
# Contact: research@splunk.com''
#############
```