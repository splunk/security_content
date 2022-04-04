---
title: "Regsvr32 Silent and Install Param Dll Loading"
excerpt: "Signed Binary Proxy Execution
, Regsvr32
"
categories:
  - Endpoint
last_modified_at: 2021-10-04
toc: true
toc_label: ""
tags:
  - Signed Binary Proxy Execution
  - Regsvr32
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic is to detect a loading of dll using regsvr32 application with silent parameter and dllinstall execution. This technique was seen in several RAT malware similar to remcos, njrat and adversaries to load their malicious DLL on the compromised machine. This TTP may executed by normal 3rd party application so it is better to pivot by the parent process, parent command-line and command-line of the file that execute this regsvr32.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-10-04
- **Author**: Teoderick Contreras, Splunk
- **ID**: f421c250-24e7-11ec-bc43-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1218](https://attack.mitre.org/techniques/T1218/) | Signed Binary Proxy Execution | Defense Evasion |

| [T1218.010](https://attack.mitre.org/techniques/T1218/010/) | Regsvr32 | Defense Evasion |

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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_regsvr32` AND Processes.process="*/i*" by Processes.dest Processes.parent_process Processes.process Processes.parent_process_name Processes.process_name Processes.original_file_name Processes.user 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| where match(process,"(?i)[\-
|\/][Ss]{1}") 
| `regsvr32_silent_and_install_param_dll_loading_filter`
```

#### Macros
The SPL above uses the following Macros:
* [process_regsvr32](https://github.com/splunk/security_content/blob/develop/macros/process_regsvr32.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **regsvr32_silent_and_install_param_dll_loading_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
Other third part application may used this parameter but not so common in base windows environment.

#### Associated Analytic story
* [Data Destruction](/stories/data_destruction)
* [Suspicious Regsvr32 Activity](/stories/suspicious_regsvr32_activity)
* [Remcos](/stories/remcos)
* [Hermetic Wiper](/stories/hermetic_wiper)
* [Living Off The Land](/stories/living_off_the_land)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 36.0 | 60 | 60 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ attempting to load a DLL using the silent and dllinstall parameter. |


#### Reference

* [https://app.any.run/tasks/dc93ee63-050c-4ff8-b07e-8277af9ab939/#](https://app.any.run/tasks/dc93ee63-050c-4ff8-b07e-8277af9ab939/#)
* [https://attack.mitre.org/techniques/T1218/010/](https://attack.mitre.org/techniques/T1218/010/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.005/vbs_wscript/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.005/vbs_wscript/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/regsvr32_silent_and_install_param_dll_loading.yml) \| *version*: **1**