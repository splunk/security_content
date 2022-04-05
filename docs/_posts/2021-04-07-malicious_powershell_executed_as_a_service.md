---
title: "Malicious Powershell Executed As A Service"
excerpt: "System Services
, Service Execution
"
categories:
  - Endpoint
last_modified_at: 2021-04-07
toc: true
toc_label: ""
tags:
  - System Services
  - Service Execution
  - Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This detection is to identify the abuse the Windows SC.exe to execute malicious commands or payloads via PowerShell.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-04-07
- **Author**: Ryan Becwar
- **ID**: 8e204dfd-cae0-4ea8-a61d-e972a1ff2ff8


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1569](https://attack.mitre.org/techniques/T1569/) | System Services | Execution |

| [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | Service Execution | Execution |

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
 `wineventlog_system` EventCode=7045 
| eval l_Service_File_Name=lower(Service_File_Name) 
| regex l_Service_File_Name="powershell[.\s]
|powershell_ise[.\s]
|pwsh[.\s]
|psexec[.\s]" 
| regex l_Service_File_Name="-nop[rofile\s]+
|-w[indowstyle]*\s+hid[den]*
|-noe[xit\s]+
|-enc[odedcommand\s]+" 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Service_File_Name Service_Name Service_Start_Type Service_Type Service_Account user 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `malicious_powershell_executed_as_a_service_filter`
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_system](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_system.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **malicious_powershell_executed_as_a_service_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* EventCode
* Service_File_Name
* Service_Type
* _time
* Service_Name
* Service_Start_Type
* Service_Account
* user


#### How To Implement
To successfully implement this search, you need to be ingesting Windows System logs with the Service name, Service File Name Service Start type, and Service Type from your endpoints.

#### Known False Positives
Creating a hidden powershell service is rare and could key off of those instances.

#### Associated Analytic story
* [Malicious Powershell](/stories/malicious_powershell)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 90 | 80 | Identifies the abuse the Windows SC.exe to execute malicious powerShell as a service $Service_File_Name$ by $user$ on $dest$ |


#### Reference

* [https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/dosfuscation-report.pdf](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/dosfuscation-report.pdf)
* [http://az4n6.blogspot.com/2017/](http://az4n6.blogspot.com/2017/)
* [https://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier](https://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1569.002/atomic_red_team/windows-system.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1569.002/atomic_red_team/windows-system.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/malicious_powershell_executed_as_a_service.yml) \| *version*: **1**