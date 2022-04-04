---
title: "DNS Exfiltration Using Nslookup App"
excerpt: "Exfiltration Over Alternative Protocol
"
categories:
  - Endpoint
last_modified_at: 2021-04-15
toc: true
toc_label: ""
tags:
  - Exfiltration Over Alternative Protocol
  - Exfiltration
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

this search is to detect potential DNS exfiltration using nslookup application. This technique are seen in couple of malware and APT group to exfiltrated collected data in a infected machine or infected network. This detection is looking for unique use of nslookup where it tries to use specific record type, TXT, A, AAAA, that are commonly used by attacker and also the retry parameter which is designed to query C2 DNS multiple tries.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-04-15
- **Author**: Teoderick Contreras, Splunk
- **ID**: 2452e632-9e0d-11eb-bacd-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol | Exfiltration |

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

| tstats `security_content_summariesonly` values(Processes.process) as process values(Processes.process_id) as process_id values(Processes.parent_process) as parent_process count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name = "nslookup.exe" Processes.process = "*-querytype=*" OR Processes.process="*-qt=*" OR Processes.process="*-q=*" OR Processes.process="-type=*" OR Processes.process="*-retry=*" by Processes.dest Processes.user Processes.process_name  
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `dns_exfiltration_using_nslookup_app_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **dns_exfiltration_using_nslookup_app_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA. Tune and filter known instances of nslookup.exe may be used.

#### Known False Positives
admin nslookup usage

#### Associated Analytic story
* [Suspicious DNS Traffic](/stories/suspicious_dns_traffic)
* [Dynamic DNS](/stories/dynamic_dns)
* [Data Exfiltration](/stories/data_exfiltration)
* [Command and Control](/stories/command_and_control)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 72.0 | 90 | 80 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ performing activity related to DNS exfiltration. |


#### Reference

* [https://www.fireeye.com/blog/threat-research/2017/03/fin7_spear_phishing.html](https://www.fireeye.com/blog/threat-research/2017/03/fin7_spear_phishing.html)
* [https://www.varonis.com/blog/dns-tunneling/](https://www.varonis.com/blog/dns-tunneling/)
* [https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/](https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1048.003/nslookup_exfil/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1048.003/nslookup_exfil/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/dns_exfiltration_using_nslookup_app.yml) \| *version*: **1**