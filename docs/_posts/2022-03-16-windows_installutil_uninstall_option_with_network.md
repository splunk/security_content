---
title: "Windows InstallUtil Uninstall Option with Network"
excerpt: "InstallUtil
, System Binary Proxy Execution
"
categories:
  - Endpoint
last_modified_at: 2022-03-16
toc: true
toc_label: ""
tags:
  - InstallUtil
  - System Binary Proxy Execution
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the Windows InstallUtil.exe binary making a remote network connection. This technique may be used to download and execute code while bypassing application control using the `/u` (uninstall) switch. \
InstallUtil uses the functions install and uninstall within the System.Configuration.Install namespace to process .net assembly. Install function requires admin privileges, however, uninstall function can be run as an unprivileged user.\
When `InstallUtil.exe` is used in a malicous manner, the path to an executable on the filesystem is typically specified. Take note of the parent process. In a suspicious instance, this will be spawned from a non-standard process like `Cmd.exe`, `PowerShell.exe` or `Explorer.exe`. \
If used by a developer, typically this will be found with multiple command-line switches/arguments and spawn from Visual Studio. \
During triage review resulting network connections, file modifications, and parallel processes. Capture any artifacts and review further.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-03-16
- **Author**: Michael Haag, Splunk
- **ID**: 1a52c836-43ef-11ec-a36c-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1218.004](https://attack.mitre.org/techniques/T1218/004/) | InstallUtil | Defense Evasion |

| [T1218](https://attack.mitre.org/techniques/T1218/) | System Binary Proxy Execution | Defense Evasion |

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

| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes where `process_installutil` Processes.process IN ("*/u*", "*uninstall*") by _time span=1h  Processes.process_id Processes.process_name Processes.dest Processes.process_path Processes.process Processes.parent_process_name 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| join  process_id [
| tstats `security_content_summariesonly` count FROM datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port != 0 by All_Traffic.process_id All_Traffic.dest All_Traffic.dest_port 
| `drop_dm_object_name(All_Traffic)` 
| rename dest as C2 ] 
| table _time dest parent_process_name process_name process_path process process_id dest_port C2 
| `windows_installutil_uninstall_option_with_network_filter`
```

#### Macros
The SPL above uses the following Macros:
* [process_installutil](https://github.com/splunk/security_content/blob/develop/macros/process_installutil.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **windows_installutil_uninstall_option_with_network_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
* Ports.process_guid
* Ports.dest
* Ports.dest_port


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` and `Ports` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
Limited false positives should be present as InstallUtil is not typically used to download remote files. Filter as needed based on Developers requirements.

#### Associated Analytic story
* [Signed Binary Proxy Execution InstallUtil](/stories/signed_binary_proxy_execution_installutil)
* [Living Off The Land](/stories/living_off_the_land)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ performing an uninstall. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://evi1cg.me/archives/AppLocker_Bypass_Techniques.html#menu_index_12](https://evi1cg.me/archives/AppLocker_Bypass_Techniques.html#menu_index_12)
* [https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/md/Installutil.exe.md](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/md/Installutil.exe.md)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.004/T1218.004.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.004/T1218.004.md)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.004/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.004/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_installutil_uninstall_option_with_network.yml) \| *version*: **2**