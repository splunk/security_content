---
title: "Windows Application Layer Protocol RMS Radmin Tool Namedpipe"
excerpt: "Application Layer Protocol
"
categories:
  - Endpoint
last_modified_at: 2022-06-24
toc: true
toc_label: ""
tags:
  - Application Layer Protocol
  - Command And Control
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the use of default or publicly known named pipes used by RMX remote admin tool. A named pipe is a named, one-way or duplex pipe for communication between the pipe server and one or more pipe clients. RMX Tool uses named pipes in many way as part of its communication for its server and client component. This tool was abuse by several adversaries and malware like Azorult to collect data to the targeted host. This TTP is a good indicator that this tool was install in production premise and need to check if the user has a valid reason why it need to install this legitimate application.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-06-24
- **Author**: Teoderick Contreras, Splunk
- **ID**: b62a6040-49f4-47c8-b3f6-fc1adb952a33


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1071](https://attack.mitre.org/techniques/T1071/) | Application Layer Protocol | Command And Control |

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
`sysmon` EventCode IN (17, 18) EventType IN ( "CreatePipe", "ConnectPipe") PipeName IN ("\\RManFUSServerNotify32", "\\RManFUSCallbackNotify32", "\\RMSPrint*") 
| stats  min(_time) as firstTime max(_time) as lastTime count by Image EventType ProcessId PipeName Computer UserID 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_application_layer_protocol_rms_radmin_tool_namedpipe_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [sysmon](https://github.com/splunk/security_content/blob/develop/macros/sysmon.yml)

> :information_source:
> **windows_application_layer_protocol_rms_radmin_tool_namedpipe_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Image
* EventType
* ProcessId
* PipeName
* Computer
* UserID


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
False positives may be present. Filter based on pipe name or process.

#### Associated Analytic story
* [Azorult](/stories/azorult)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 81.0 | 90 | 90 | possible RMS admin tool named pipe was created in $dest$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://app.any.run/tasks/a6f2ffe2-e6e2-4396-ae2e-04ea0143f2d8/](https://app.any.run/tasks/a6f2ffe2-e6e2-4396-ae2e-04ea0143f2d8/)
* [https://attack.mitre.org/techniques/T1071/](https://attack.mitre.org/techniques/T1071/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/azorult/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/azorult/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_application_layer_protocol_rms_radmin_tool_namedpipe.yml) \| *version*: **1**