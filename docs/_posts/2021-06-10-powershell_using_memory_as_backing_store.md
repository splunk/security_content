---
title: "Powershell Using memory As Backing Store"
excerpt: "Deobfuscate/Decode Files or Information"
categories:
  - Endpoint
last_modified_at: 2021-06-10
toc: true
tags:
  - TTP
  - T1140
  - Deobfuscate/Decode Files or Information
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Exploitation
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies suspicious PowerShell script execution via EventCode 4104 that is using memory stream as new object backstore. The malicious PowerShell script will contain stream flate data and will be decompressed in memory to run or drop the actual payload. During triage, review parallel processes within the same timeframe. Review the full script block to identify other related artifacts.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-06-10
- **Author**: Teoderick Contreras, Splunk
- **ID**: c396a0c4-c9f2-11eb-b4f5-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1140](https://attack.mitre.org/techniques/T1140/) | Deobfuscate/Decode Files or Information | Defense Evasion |



#### Search

```
`powershell` EventCode=4104 Message = "*New-Object IO.MemoryStream*" 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Message ComputerName User 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `powershell_using_memory_as_backing_store_filter`
```

#### Associated Analytic Story
* [Malicious PowerShell](/stories/malicious_powershell)


#### How To Implement
To successfully implement this analytic, you will need to enable PowerShell Script Block Logging on some or all endpoints. Additional setup here https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell.

#### Required field
* _time
* EventCode
* Message
* ComputerName
* User


#### Kill Chain Phase
* Exploitation


#### Known False Positives
powershell may used this function to store out object into memory.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 40.0 | 50 | 80 | A suspicious powershell script contains memorystream command in $Message$ as new object backstore with EventCode $EventCode$ in host $ComputerName$ |



#### Reference

* [https://www.carbonblack.com/blog/decoding-malicious-powershell-streams/](https://www.carbonblack.com/blog/decoding-malicious-powershell-streams/)
* [https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell.](https://docs.splunk.com/Documentation/UBA/5.0.4.1/GetDataIn/AddPowerShell#Configure_module_logging_for_PowerShell.)
* [https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63](https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63)
* [https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/59c1814829f18782e24f1fe2/1505853768977/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2017+v2.1.pdf](https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/59c1814829f18782e24f1fe2/1505853768977/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2017+v2.1.pdf)
* [https://www.crowdstrike.com/blog/investigating-powershell-command-and-script-logging/](https://www.crowdstrike.com/blog/investigating-powershell-command-and-script-logging/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/honeypots/pwsh/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/honeypots/pwsh/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/powershell_using_memory_as_backing_store.yml) \| *version*: **1**