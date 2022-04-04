---
title: "CMD Carry Out String Command Parameter"
excerpt: "Windows Command Shell
, Command and Scripting Interpreter
"
categories:
  - Endpoint
last_modified_at: 2022-01-18
toc: true
toc_label: ""
tags:
  - Windows Command Shell
  - Command and Scripting Interpreter
  - Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2021-44228
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies command-line arguments where `cmd.exe /c` is used to execute a program. `cmd /c` is used to run commands in MS-DOS and terminate after command or process completion. This technique is commonly seen in adversaries and malware to execute batch command using different shell like PowerShell or different process other than `cmd.exe`. This is a good hunting query for suspicious command-line made by a script or relative process execute it.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-01-18
- **Author**: Teoderick Contreras, Bhavin Patel, Splunk
- **ID**: 54a6ed00-3256-11ec-b031-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Windows Command Shell | Execution |

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
| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) | Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects. | 9.3 |



</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_cmd` AND Processes.process="* /c *" by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.original_file_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `cmd_carry_out_string_command_parameter_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [process_cmd](https://github.com/splunk/security_content/blob/develop/macros/process_cmd.yml)

Note that **cmd_carry_out_string_command_parameter_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.parent_process_name
* Processes.parent_process
* Processes.process_name
* Processes.process_id
* Processes.process
* Processes.dest
* Processes.user
* Processes.process_id
* Processes.parent_process_id


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
False positives may be high based on legitimate scripted code in any environment. Filter as needed.

#### Associated Analytic story
* [Data Destruction](/stories/data_destruction)
* [IcedID](/stories/icedid)
* [Log4Shell CVE-2021-44228](/stories/log4shell_cve-2021-44228)
* [WhisperGate](/stories/whispergate)
* [Hermetic Wiper](/stories/hermetic_wiper)
* [Living Off The Land](/stories/living_off_the_land)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 30.0 | 60 | 50 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ attempting spawn a new process. |


#### Reference

* [https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/](https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/)
* [https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/](https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/cmd_carry_str_param/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/cmd_carry_str_param/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/cmd_carry_out_string_command_parameter.yml) \| *version*: **3**