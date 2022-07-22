---
title: "Powershell Using memory As Backing Store"
excerpt: "PowerShell
, Command and Scripting Interpreter
"
categories:
  - Endpoint
last_modified_at: 2022-03-22
toc: true
toc_label: ""
tags:
  - PowerShell
  - Command and Scripting Interpreter
  - Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies suspicious PowerShell script execution via EventCode 4104 that is using memory stream as new object backstore. The malicious PowerShell script will contain stream flate data and will be decompressed in memory to run or drop the actual payload. During triage, review parallel processes within the same timeframe. Review the full script block to identify other related artifacts.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-03-22
- **Author**: Teoderick Contreras, Splunk
- **ID**: c396a0c4-c9f2-11eb-b4f5-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Execution |

| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |

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
`powershell` EventCode=4104 ScriptBlockText = *New-Object* ScriptBlockText = *IO.MemoryStream* 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode ScriptBlockText Computer user_id 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `powershell_using_memory_as_backing_store_filter`
```

#### Macros
The SPL above uses the following Macros:
* [powershell](https://github.com/splunk/security_content/blob/develop/macros/powershell.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **powershell_using_memory_as_backing_store_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* EventCode
* ScriptBlockText
* Computer
* UserID


#### How To Implement
To successfully implement this analytic, you will need to enable PowerShell Script Block Logging on some or all endpoints. Additional setup here https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell.

#### Known False Positives
powershell may used this function to store out object into memory.

#### Associated Analytic story
* [Hermetic Wiper](/stories/hermetic_wiper)
* [Malicious PowerShell](/stories/malicious_powershell)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 40.0 | 50 | 80 | A suspicious powershell script contains memorystream command in $ScriptBlockText$ as new object backstore with EventCode $EventCode$ in host $Computer$ |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://web.archive.org/web/20201112031711/https://www.carbonblack.com/blog/decoding-malicious-powershell-streams/](https://web.archive.org/web/20201112031711/https://www.carbonblack.com/blog/decoding-malicious-powershell-streams/)
* [https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell.](https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell.)
* [https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63](https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63)
* [https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/59c1814829f18782e24f1fe2/1505853768977/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2017+v2.1.pdf](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/59c1814829f18782e24f1fe2/1505853768977/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2017+v2.1.pdf)
* [https://www.crowdstrike.com/blog/investigating-powershell-command-and-script-logging/](https://www.crowdstrike.com/blog/investigating-powershell-command-and-script-logging/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/honeypots/pwsh/windows-powershell-xml.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/honeypots/pwsh/windows-powershell-xml.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/powershell_using_memory_as_backing_store.yml) \| *version*: **2**