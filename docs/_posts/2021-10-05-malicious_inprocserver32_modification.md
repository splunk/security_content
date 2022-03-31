---
title: "Malicious InProcServer32 Modification"
excerpt: "Regsvr32
, Modify Registry
"
categories:
  - Endpoint
last_modified_at: 2021-10-05
toc: true
toc_label: ""
tags:
  - Regsvr32
  - Modify Registry
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies a process modifying the registry with a known malicious CLSID under InProcServer32. Most COM classes are registered with the operating system and are identified by a GUID that represents the Class Identifier (CLSID) within the registry (usually under HKLM\\Software\\Classes\\CLSID or HKCU\\Software\\Classes\\CLSID).  Behind the implementation of a COM class is the server (some binary) that is referenced within registry keys under the CLSID.  The LocalServer32 key represents a path to an executable (exe) implementation, and the InprocServer32 key represents a path to a dynamic link library (DLL) implementation (Bohops). During triage, review parallel processes for suspicious activity. Pivot on the process GUID to see the full timeline of events. Analyze the value and look for file modifications. Being this is looking for inprocserver32, a DLL found in the value will most likely be loaded by a parallel process.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-10-05
- **Author**: Michael Haag, Splunk
- **ID**: 127c8d08-25ff-11ec-9223-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1218.010](https://attack.mitre.org/techniques/T1218/010/) | Regsvr32 | Defense Evasion |

| [T1112](https://attack.mitre.org/techniques/T1112/) | Modify Registry | Defense Evasion |

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

| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes by _time Processes.process_id Processes.process_name Processes.dest Processes.process_guid Processes.user 
| `drop_dm_object_name(Processes)` 
| join process_guid [
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Registry where Registry.registry_path= "*\\CLSID\\{89565275-A714-4a43-912E-978B935EDCCC}\\InProcServer32\\(Default)" by Registry.registry_path Registry.registry_key_name Registry.registry_value_name Registry.dest Registry.process_guid Registry.user 
| `drop_dm_object_name(Registry)` 
| fields _time dest registry_path registry_key_name registry_value_name process_name process_path process process_guid user] 
| stats count min(_time) as firstTime max(_time) as lastTime by dest, process_name registry_path registry_key_name registry_value_name user 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `malicious_inprocserver32_modification_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **malicious_inprocserver32_modification_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* dest
* process_name
* registry_path
* registry_key_name
* registry_value_name
* user


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Registry` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
False positives should be limited, filter as needed. In our test case, Remcos used regsvr32.exe to modify the registry. It may be required, dependent upon the EDR tool producing registry events, to remove (Default) from the command-line.

#### Associated Analytic story
* [Suspicious Regsvr32 Activity](/stories/suspicious_regsvr32_activity)
* [Remcos](/stories/remcos)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | The $process_name$ was identified on endpoint $dest$ modifying the registry with a known malicious clsid under InProcServer32. |


#### Reference

* [https://bohops.com/2018/06/28/abusing-com-registry-structure-clsid-localserver32-inprocserver32/](https://bohops.com/2018/06/28/abusing-com-registry-structure-clsid-localserver32-inprocserver32/)
* [https://tria.ge/210929-ap75vsddan](https://tria.ge/210929-ap75vsddan)
* [https://www.virustotal.com/gui/file/cb77b93150cb0f7fe65ce8a7e2a5781e727419451355a7736db84109fa215a89](https://www.virustotal.com/gui/file/cb77b93150cb0f7fe65ce8a7e2a5781e727419451355a7736db84109fa215a89)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/remcos/remcos/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/remcos/remcos/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/malicious_inprocserver32_modification.yml) \| *version*: **1**