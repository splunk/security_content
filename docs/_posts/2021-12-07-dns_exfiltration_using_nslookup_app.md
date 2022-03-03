---
title: "DNS Exfiltration Using Nslookup App"
excerpt: "Exfiltration Over Alternative Protocol"
categories:
  - Endpoint
last_modified_at: 2021-12-07
toc: true
toc_label: ""
tags:
  - Exfiltration Over Alternative Protocol
  - Exfiltration
  - Splunk Behavioral Analytics
  - Endpoint_Processes
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This search is to detect potential DNS exfiltration using nslookup application. This technique are seen in couple of malware and APT group to exfiltrated collected data in a infected machine or infected network. This detection is looking for unique use of nslookup where it tries to use specific record type, TXT, A, AAAA, that are commonly used by attacker and also the retry parameter which is designed to query C2 DNS multiple tries.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Behavioral Analytics
- **Datamodel**: [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2021-12-07
- **Author**: Michael Haag, Splunk
- **ID**: 2452e632-9e0d-11eb-34ba-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol | Exfiltration |

#### Search

```

| from read_ssa_enriched_events() 
| where "Endpoint_Processes" IN(_datamodels) 
| eval timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), cmd_line=ucast(map_get(input_event, "process"), "string", null), process_name=ucast(map_get(input_event, "process_name"), "string", null), process_path=ucast(map_get(input_event, "process_path"), "string", null), parent_process_name=ucast(map_get(input_event, "parent_process_name"), "string", null), event_id=ucast(map_get(input_event, "event_id"), "string", null) 
| where cmd_line IS NOT NULL AND process_name IS NOT NULL AND process_name="nslookup.exe" AND (like (cmd_line, "%-querytype=%") OR like (cmd_line, "%-qt=%") OR like (cmd_line, "%-q=%") OR like (cmd_line, "%-type=%") OR like (cmd_line, "%-retry=%")) 
| eval start_time=timestamp, end_time=timestamp, entities=mvappend(ucast(map_get(input_event, "dest_user_id"), "string", null), ucast(map_get(input_event, "dest_device_id"), "string", null)) 
| eval body=create_map(["event_id", event_id, "cmd_line", cmd_line, "process_name", process_name, "parent_process_name", parent_process_name, "process_path", process_path]) 
| into write_ssa_detected_events();
```

#### Macros
The SPL above uses the following Macros:

Note that `dns_exfiltration_using_nslookup_app_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* dest_device_id
* process_name
* parent_process_name
* process_path
* dest_user_id
* process
* cmd_line


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint_Processess` datamodel.

#### Known False Positives
It is possible for some legitimate administrative utilities to use similar cmd_line parameters. Filter as needed.

#### Associated Analytic story
* [Suspicious DNS Traffic](/stories/suspicious_dns_traffic)
* [Dynamic DNS](/stories/dynamic_dns)
* [Command and Control](/stories/command_and_control)
* [Data Exfiltration](/stories/data_exfiltration)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 90 | 80 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest_device_id$ by user $dest_user_id$ performing activity related to DNS exfiltration. |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://www.fireeye.com/blog/threat-research/2017/03/fin7_spear_phishing.html](https://www.fireeye.com/blog/threat-research/2017/03/fin7_spear_phishing.html)
* [https://www.varonis.com/blog/dns-tunneling/](https://www.varonis.com/blog/dns-tunneling/)
* [https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/](https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1048.003/nslookup_exfil/windows-security.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1048.003/nslookup_exfil/windows-security.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/dns_exfiltration_using_nslookup_app.yml) \| *version*: **1**