---
title: "Windows Binary Proxy Execution Mavinject DLL Injection"
excerpt: "Mavinject
, System Binary Proxy Execution
"
categories:
  - Endpoint
last_modified_at: 2022-07-07
toc: true
toc_label: ""
tags:
  - Mavinject
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

Adversaries may abuse mavinject.exe to inject malicious DLLs into running processes (i.e. Dynamic-link Library Injection), allowing for arbitrary code execution (ex. C:\Windows\system32\mavinject.exe PID /INJECTRUNNING PATH_DLL). In addition to Dynamic-link Library Injection, Mavinject.exe can also be abused to perform import descriptor injection via its /HMODULE command-line parameter (ex. mavinject.exe PID /HMODULE=BASE_ADDRESS PATH_DLL ORDINAL_NUMBER). This command would inject an import table entry consisting of the specified DLL into the module at the given base address. During triage, review file modifcations and parallel processes.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-07-07
- **Author**: Michael Haag, Splunk
- **ID**: ccf4b61b-1b26-4f2e-a089-f2009c569c57


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1218.013](https://attack.mitre.org/techniques/T1218/013/) | Mavinject | Defense Evasion |

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

* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 5
* CIS 16



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search 

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=mavinject.exe Processes.process IN ("*injectrunning*", "*hmodule=0x*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_binary_proxy_execution_mavinject_dll_injection_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

> :information_source:
> **windows_binary_proxy_execution_mavinject_dll_injection_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
False positives may be present, filter on DLL name or parent process.

#### Associated Analytic story
* [Living Off The Land](/stories/living_off_the_land)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ attempting load a DLL. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://attack.mitre.org/techniques/T1218/013/](https://attack.mitre.org/techniques/T1218/013/)
* [https://posts.specterops.io/mavinject-exe-functionality-deconstructed-c29ab2cf5c0e](https://posts.specterops.io/mavinject-exe-functionality-deconstructed-c29ab2cf5c0e)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md#atomic-test-1---mavinject---inject-dll-into-running-process](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md#atomic-test-1---mavinject---inject-dll-into-running-process)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.013/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.013/atomic_red_team/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_binary_proxy_execution_mavinject_dll_injection.yml) \| *version*: **1**