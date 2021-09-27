---
title: "Print Spooler Adding A Printer Driver"
excerpt: "Print Processors"
categories:
  - Endpoint
last_modified_at: 2021-07-01
toc: true
tags:
  - TTP
  - T1547.012
  - Print Processors
  - Persistence
  - Privilege Escalation
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies new printer drivers being load by utilizing the Windows PrintService operational logs, EventCode 316. This was identified during our testing of CVE-2021-34527 previously (CVE-2021-1675) or PrintNightmare. \
Within the proof of concept code, the following event will occur - &#34;Printer driver 1234 for Windows x64 Version-3 was added or updated. Files:- UNIDRV.DLL, kernelbase.dll, evil.dll. No user action is required.&#34; \
During triage, isolate the endpoint and review for source of exploitation. Capture any additional file modification events and review the source of where the exploitation began.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-07-01
- **Author**: Mauricio Velazco, Michael Haag, Teoderick Contreras, Splunk
- **ID**: 313681a2-da8e-11eb-adad-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1547.012](https://attack.mitre.org/techniques/T1547/012/) | Print Processors | Persistence, Privilege Escalation |


#### Search

```
`printservice` EventCode=316 category = "Adding a printer driver" Message = "*kernelbase.dll,*" Message = "*UNIDRV.DLL,*" Message = "*.DLL.*" 
| stats  count min(_time) as firstTime max(_time) as lastTime by OpCode EventCode ComputerName Message 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `print_spooler_adding_a_printer_driver_filter`
```

#### Associated Analytic Story
* [PrintNightmare CVE-2021-34527](/stories/printnightmare_cve-2021-34527)


#### How To Implement
You will need to ensure PrintService Admin and Operational logs are being logged to Splunk from critical or all systems.

#### Required field
* _time
* OpCode
* EventCode
* ComputerName
* Message


#### Kill Chain Phase
* Exploitation


#### Known False Positives
Unknown. This may require filtering.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 80 | 90 | Suspicious print driver was loaded on endpoint $ComputerName$. |



#### Reference

* [https://twitter.com/MalwareJake/status/1410421445608476679?s=20](https://twitter.com/MalwareJake/status/1410421445608476679?s=20)
* [https://blog.truesec.com/2021/06/30/fix-for-printnightmare-cve-2021-1675-exploit-to-keep-your-print-servers-running-while-a-patch-is-not-available/](https://blog.truesec.com/2021/06/30/fix-for-printnightmare-cve-2021-1675-exploit-to-keep-your-print-servers-running-while-a-patch-is-not-available/)
* [https://blog.truesec.com/2021/06/30/exploitable-critical-rce-vulnerability-allows-regular-users-to-fully-compromise-active-directory-printnightmare-cve-2021-1675/](https://blog.truesec.com/2021/06/30/exploitable-critical-rce-vulnerability-allows-regular-users-to-fully-compromise-active-directory-printnightmare-cve-2021-1675/)
* [https://www.reddit.com/r/msp/comments/ob6y02/critical_vulnerability_printnightmare_exposes](https://www.reddit.com/r/msp/comments/ob6y02/critical_vulnerability_printnightmare_exposes)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.012/printnightmare/windows-printservice_operational.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.012/printnightmare/windows-printservice_operational.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/print_spooler_adding_a_printer_driver.yml) \| *version*: **1**