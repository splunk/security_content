---
title: "Nishang PowershellTCPOneLine"
excerpt: "PowerShell"
categories:
  - Endpoint
last_modified_at: 2021-03-03
toc: true
tags:
  - TTP
  - T1059.001
  - PowerShell
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



#### Description

This query detects the Nishang Invoke-PowerShellTCPOneLine utility that spawns a call back to a remote command and control server. This is a powershell oneliner. In addition, this will capture on the command-line additional utilities used by Nishang. Triage the endpoint and identify any parallel processes that look suspicious. Review the reputation of the remote IP or domain contacted by the powershell process.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-03-03
- **Author**: Michael Haag, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Execution |


#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=powershell.exe OR Processes.process_name=pwsh.exe OR Processes.process_name=PowerShell_ISE.exe (Processes.process=*Net.Sockets.TCPClient* AND Processes.process=*System.Text.ASCIIEncoding*) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `nishang_powershelltcponeline_filter`
```

#### Associated Analytic Story
* [HAFNIUM Group](_stories/hafnium_group)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

#### Required field
* _time
* Processes.process_name
* Processes.process
* Processes.dest
* Processes.user
* Processes.parent_process
* Processes.process_name
* Processes.process_id
* Processes.parent_process_id


#### Kill Chain Phase
* Exploitation


#### Known False Positives
Limited false positives may be present. Filter as needed based on initial analysis.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 42.0 | 70 | 60 |



#### Reference

* [https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1)
* [https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/](https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/)
* [https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/](https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/)
* [https://blog.rapid7.com/2021/03/03/rapid7s-insightidr-enables-detection-and-response-to-microsoft-exchange-0-day/](https://blog.rapid7.com/2021/03/03/rapid7s-insightidr-enables-detection-and-response-to-microsoft-exchange-0-day/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/atomic_red_team/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/atomic_red_team/windows-sysmon.log)


_version_: 1