---
title: "Windows Identify Protocol Handlers"
excerpt: "Command and Scripting Interpreter
"
categories:
  - Endpoint
last_modified_at: 2022-07-11
toc: true
toc_label: ""
tags:
  - Command and Scripting Interpreter
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following hunting analytic will identify any protocol handlers utilized on the command-line. A protocol handler is an application that knows how to handle particular types of links: for example, a mail client is a protocol handler for "mailto:" links. When the user clicks a "mailto:" link, the browser opens the application selected as the handler for the "mailto:" protocol (or offers them a choice of handlers, depending on their settings). To identify protocol handlers we can use NirSoft https://www.nirsoft.net/utils/url_protocol_view.html URLProtocolView or query the registry using PowerShell: get-Item Registry::HKEY_CLASSES_ROOT\* | Select-Object "Property","PSChildName" | Where-Object -Property Property -Match "^URL*" #|Export-Csv -path c:\temp\url_all.csv. Note my query is limited to URL in the property to limit the scope of this query to similar handlers as ms-msdt.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-07-11
- **Author**: Michael Haag, Splunk
- **ID**: bd5c311e-a6ea-48ae-a289-19a3398e3648


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes  by Processes.dest Processes.user Processes.process_name Processes.process 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `drop_dm_object_name(Processes)` 
| lookup windows_protocol_handlers handler AS process OUTPUT handler ishandler 
| where ishandler="TRUE" 
| `windows_identify_protocol_handlers_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **windows_identify_protocol_handlers_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Lookups
The SPL above uses the following Lookups:

* [windows_protocol_handlers](https://github.com/splunk/security_content/blob/develop/lookups/windows_protocol_handlers.yml) with [data](https://github.com/splunk/security_content/tree/develop/lookups/windows_protocol_handlers.csv)

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
False positives will be found. https and http is a URL Protocol handler that will trigger this analytic. Tune based on process or command-line.

#### Associated Analytic story
* [Living Off The Land](/stories/living_off_the_land)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 6.0 | 30 | 20 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ utilizing a protocol handler. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://www.oreilly.com/library/view/learning-java/1565927184/apas02.html](https://www.oreilly.com/library/view/learning-java/1565927184/apas02.html)
* [https://blogs.windows.com/msedgedev/2022/01/20/getting-started-url-protocol-handlers-microsoft-edge/](https://blogs.windows.com/msedgedev/2022/01/20/getting-started-url-protocol-handlers-microsoft-edge/)
* [https://github.com/Mr-Un1k0d3r/PoisonHandler](https://github.com/Mr-Un1k0d3r/PoisonHandler)
* [https://www.mdsec.co.uk/2021/03/phishing-users-to-take-a-test/](https://www.mdsec.co.uk/2021/03/phishing-users-to-take-a-test/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md#atomic-test-5---protocolhandlerexe-downloaded-a-suspicious-file](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md#atomic-test-5---protocolhandlerexe-downloaded-a-suspicious-file)
* [https://techcommunity.microsoft.com/t5/windows-it-pro-blog/disabling-the-msix-ms-appinstaller-protocol-handler/ba-p/3119479](https://techcommunity.microsoft.com/t5/windows-it-pro-blog/disabling-the-msix-ms-appinstaller-protocol-handler/ba-p/3119479)
* [https://www.huntress.com/blog/microsoft-office-remote-code-execution-follina-msdt-bug](https://www.huntress.com/blog/microsoft-office-remote-code-execution-follina-msdt-bug)
* [https://parsiya.net/blog/2021-03-17-attack-surface-analysis-part-2-custom-protocol-handlers/](https://parsiya.net/blog/2021-03-17-attack-surface-analysis-part-2-custom-protocol-handlers/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/protocol_handlers/protocolhandlers.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/protocol_handlers/protocolhandlers.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_identify_protocol_handlers.yml) \| *version*: **1**