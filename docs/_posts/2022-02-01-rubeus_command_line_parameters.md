---
title: "Rubeus Command Line Parameters"
excerpt: "Use Alternate Authentication Material
, Pass the Ticket
, Steal or Forge Kerberos Tickets
, Kerberoasting
, AS-REP Roasting
"
categories:
  - Endpoint
last_modified_at: 2022-02-01
toc: true
toc_label: ""
tags:
  - Use Alternate Authentication Material
  - Pass the Ticket
  - Steal or Forge Kerberos Tickets
  - Kerberoasting
  - AS-REP Roasting
  - Defense Evasion
  - Lateral Movement
  - Defense Evasion
  - Lateral Movement
  - Credential Access
  - Credential Access
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is heavily adapted from Benjamin Delpys Kekeo project and Vincent LE TOUXs MakeMeEnterpriseAdmin project. This analytic looks for the use of Rubeus command line arguments utilized in common Kerberos attacks like exporting and importing tickets, forging silver and golden tickets, requesting a TGT or TGS, kerberoasting, password spraying, etc. Red teams and adversaries alike use Rubeus for Kerberos attacks within Active Directory networks. Defenders should be aware that adversaries may customize the source code of Rubeus and modify the command line parameters. This would effectively bypass this analytic.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)

- **Last Updated**: 2022-02-01
- **Author**: Mauricio Velazco, Splunk
- **ID**: cca37478-8377-11ec-b59a-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1550](https://attack.mitre.org/techniques/T1550/) | Use Alternate Authentication Material | Defense Evasion, Lateral Movement |

| [T1550.003](https://attack.mitre.org/techniques/T1550/003/) | Pass the Ticket | Defense Evasion, Lateral Movement |

| [T1558](https://attack.mitre.org/techniques/T1558/) | Steal or Forge Kerberos Tickets | Credential Access |

| [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | Kerberoasting | Credential Access |

| [T1558.004](https://attack.mitre.org/techniques/T1558/004/) | AS-REP Roasting | Credential Access |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process = "*ptt /ticket*" OR Processes.process = "* monitor*" OR Processes.process ="* asktgt* /user:*" OR Processes.process ="* asktgs* /service:*" OR Processes.process ="* golden* /user:*" OR Processes.process ="* silver* /service:*" OR Processes.process ="* kerberoast*" OR Processes.process ="* asreproast*" OR Processes.process = "* renew* /ticket:*" OR Processes.process = "* brute* /password:*" OR Processes.process = "* brute* /passwords:*" OR Processes.process ="* harvest*") by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.parent_process_name 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `rubeus_command_line_parameters_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `rubeus_command_line_parameters_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_id
* Processes.parent_process_name


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
Although unlikely, legitimate applications may use the same command line parameters as Rubeus. Filter as needed.

#### Associated Analytic story
* [Active Directory Kerberos Attacks](/stories/active_directory_kerberos_attacks)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 36.0 | 60 | 60 | Rubeus command line parameters were used on $dest$ |




#### Reference

* [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
* [http://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/](http://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/)
* [https://attack.mitre.org/techniques/T1550/003/](https://attack.mitre.org/techniques/T1550/003/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1550.003/rubeus/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1550.003/rubeus/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/rubeus_command_line_parameters.yml) \| *version*: **1**