---
title: "Download Files Using Telegram"
excerpt: "Ingress Tool Transfer"
categories:
  - Endpoint
last_modified_at: 2021-05-06
toc: true
tags:
  - TTP
  - T1105
  - Ingress Tool Transfer
  - Command And Control
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic will identify a suspicious download by the Telegram application on a Windows system. This behavior was identified on a honeypot where the adversary gained access, installed Telegram and followed through with downloading different network scanners (port, bruteforcer, masscan) to the system and later used to mapped the whole network and further move laterally.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-06
- **Author**: Teoderick Contreras, Splunk
- **ID**: 58194e28-ae5e-11eb-8912-acde48001122


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | Command And Control |



#### Search

```
`sysmon` EventCode= 15 process_name = "telegram.exe" TargetFilename = "*:Zone.Identifier" 
|stats count min(_time) as firstTime max(_time) as lastTime by Computer EventCode Image process_id TargetFilename Hash 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `download_files_using_telegram_filter`
```

#### Associated Analytic Story
* [XMRig](/stories/xmrig)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name and TargetFilename from your endpoints or Events that monitor filestream events which is happened when process download something. (EventCode 15) If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* Computer
* EventCode
* Image
* process_id
* TargetFilename
* Hash


#### Kill Chain Phase
* Exploitation


#### Known False Positives
normal download of file in telegram app. (if it was a common app in network)



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | Suspicious files were downloaded with the Telegram application on $dest$ by $user$. |



#### Reference

* [https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/](https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/minergate/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/minergate/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/download_files_using_telegram.yml) \| *version*: **1**