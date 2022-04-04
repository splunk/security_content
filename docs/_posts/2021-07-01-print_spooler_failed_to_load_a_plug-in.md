---
title: "Print Spooler Failed to Load a Plug-in"
excerpt: "Print Processors
, Boot or Logon Autostart Execution
"
categories:
  - Endpoint
last_modified_at: 2021-07-01
toc: true
toc_label: ""
tags:
  - Print Processors
  - Boot or Logon Autostart Execution
  - Persistence
  - Privilege Escalation
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2021-34527
  - CVE-2021-1675
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies driver load errors utilizing the Windows PrintService Admin logs. This was identified during our testing of CVE-2021-34527 previously (CVE-2021-1675) or PrintNightmare. \
Within the proof of concept code, the following error will occur - "The print spooler failed to load a plug-in module C:\Windows\system32\spool\DRIVERS\x64\3\meterpreter.dll, error code 0x45A. See the event user data for context information." \
The analytic is based on file path and failure to load the plug-in. \
During triage, isolate the endpoint and review for source of exploitation. Capture any additional file modification events.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-07-01
- **Author**: Mauricio Velazco, Michael Haag, Splunk
- **ID**: 1adc9548-da7c-11eb-8f13-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1547.012](https://attack.mitre.org/techniques/T1547/012/) | Print Processors | Persistence, Privilege Escalation |

| [T1547](https://attack.mitre.org/techniques/T1547/) | Boot or Logon Autostart Execution | Persistence, Privilege Escalation |

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
| [CVE-2021-34527](https://nvd.nist.gov/vuln/detail/CVE-2021-34527) | Windows Print Spooler Remote Code Execution Vulnerability | 9.0 |
| [CVE-2021-1675](https://nvd.nist.gov/vuln/detail/CVE-2021-1675) | Windows Print Spooler Elevation of Privilege Vulnerability | 9.3 |



</div>
</details>

#### Search

```
`printservice` ((ErrorCode="0x45A" (EventCode="808" OR EventCode="4909")) OR ("The print spooler failed to load a plug-in module" OR "\\drivers\\x64\\")) 
| stats count min(_time) as firstTime max(_time) as lastTime by OpCode EventCode ComputerName Message 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `print_spooler_failed_to_load_a_plug_in_filter`
```

#### Macros
The SPL above uses the following Macros:
* [printservice](https://github.com/splunk/security_content/blob/develop/macros/printservice.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **print_spooler_failed_to_load_a_plug-in_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* OpCode
* EventCode
* ComputerName
* Message


#### How To Implement
You will need to ensure PrintService Admin and Operational logs are being logged to Splunk from critical or all systems.

#### Known False Positives
False positives are unknown and filtering may be required.

#### Associated Analytic story
* [PrintNightmare CVE-2021-34527](/stories/printnightmare_cve-2021-34527)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 80 | 90 | Suspicious printer spooler errors have occured on endpoint $ComputerName$ with EventCode $EventCode$. |


#### Reference

* [https://blog.truesec.com/2021/06/30/fix-for-printnightmare-cve-2021-1675-exploit-to-keep-your-print-servers-running-while-a-patch-is-not-available/](https://blog.truesec.com/2021/06/30/fix-for-printnightmare-cve-2021-1675-exploit-to-keep-your-print-servers-running-while-a-patch-is-not-available/)
* [https://blog.truesec.com/2021/06/30/exploitable-critical-rce-vulnerability-allows-regular-users-to-fully-compromise-active-directory-printnightmare-cve-2021-1675/](https://blog.truesec.com/2021/06/30/exploitable-critical-rce-vulnerability-allows-regular-users-to-fully-compromise-active-directory-printnightmare-cve-2021-1675/)
* [https://www.reddit.com/r/msp/comments/ob6y02/critical_vulnerability_printnightmare_exposes](https://www.reddit.com/r/msp/comments/ob6y02/critical_vulnerability_printnightmare_exposes)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/print_spooler_failed_to_load_a_plug-in.yml) \| *version*: **1**