---
title: "Detect Exchange Web Shell"
excerpt: "Server Software Component
, Web Shell
, Exploit Public-Facing Application
"
categories:
  - Endpoint
last_modified_at: 2021-10-05
toc: true
toc_label: ""
tags:
  - Server Software Component
  - Web Shell
  - Exploit Public-Facing Application
  - Persistence
  - Persistence
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following query identifies suspicious .aspx created in 3 paths identified by Microsoft as known drop locations for Exchange exploitation related to HAFNIUM group and recently disclosed vulnerablity named ProxyShell. Paths include: `\HttpProxy\owa\auth\`, `\inetpub\wwwroot\aspnet_client\`, and `\HttpProxy\OAB\`. Upon triage, the suspicious .aspx file will likely look obvious on the surface. inspect the contents for script code inside. Identify additional log sources, IIS included, to review source and other potential exploitation. It is often the case that a particular threat is only applicable to a specific subset of systems in your environment. Typically analytics to detect those threats are written without the benefit of being able to only target those systems as well. Writing analytics against all systems when those behaviors are limited to identifiable subsets of those systems is suboptimal. Consider the case ProxyShell vulnerability on Microsoft Exchange Servers. With asset information, a hunter can limit their analytics to systems that have been identified as Exchange servers. A hunter may start with the theory that the exchange server is communicating with new systems that it has not previously. If this theory is run against all publicly facing systems, the amount of noise it will generate will likely render this theory untenable. However, using the asset information to limit this analytic to just the Exchange servers will reduce the noise allowing the hunter to focus only on the systems where this behavioral change is relevant.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-10-05
- **Author**: Michael Haag, Shannon Davis, David Dorsey, Splunk
- **ID**: 8c14eeee-2af1-4a4b-bda8-228da0f4862a


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1505](https://attack.mitre.org/techniques/T1505/) | Server Software Component | Persistence |

| [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Web Shell | Persistence |

| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Initial Access |

#### Search

```

| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes where Processes.process_name=System  by _time span=1h Processes.process_id Processes.process_name Processes.dest 
| `drop_dm_object_name(Processes)` 
| join process_guid, _time [
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("*\\HttpProxy\\owa\\auth\\*", "*\\inetpub\\wwwroot\\aspnet_client\\*", "*\\HttpProxy\\OAB\\*") Filesystem.file_name="*.aspx" by _time span=1h Filesystem.dest Filesystem.file_create_time Filesystem.file_name Filesystem.file_path 
| `drop_dm_object_name(Filesystem)` 
| fields _time dest file_create_time file_name file_path process_name process_path process] 
| dedup file_create_time 
| table dest file_create_time, file_name, file_path, process_name 
| `detect_exchange_web_shell_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `detect_exchange_web_shell_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Filesystem.file_path
* Filesystem.process_id
* Filesystem.file_name
* Filesystem.file_hash
* Filesystem.user


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node and `Filesystem` node.

#### Known False Positives
The query is structured in a way that `action` (read, create) is not defined. Review the results of this query, filter, and tune as necessary. It may be necessary to generate this query specific to your endpoint product.

#### Associated Analytic story
* [HAFNIUM Group](/stories/hafnium_group)
* [ProxyShell](/stories/proxyshell)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 81.0 | 90 | 90 | A file - $file_name$ was written to disk that is related to IIS exploitation previously performed by HAFNIUM. Review further file modifications on endpoint $dest$ by user $user$. |




#### Reference

* [https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/MSTICIoCs-ExchangeServerVulnerabilitiesDisclosedMarch2021.csv](https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Sample%20Data/Feeds/MSTICIoCs-ExchangeServerVulnerabilitiesDisclosedMarch2021.csv)
* [https://www.zerodayinitiative.com/blog/2021/8/17/from-pwn2own-2021-a-new-attack-surface-on-microsoft-exchange-proxyshell](https://www.zerodayinitiative.com/blog/2021/8/17/from-pwn2own-2021-a-new-attack-surface-on-microsoft-exchange-proxyshell)
* [https://www.youtube.com/watch?v=FC6iHw258RI](https://www.youtube.com/watch?v=FC6iHw258RI)
* [https://www.huntress.com/blog/rapid-response-microsoft-exchange-servers-still-vulnerable-to-proxyshell-exploit#what-should-you-do](https://www.huntress.com/blog/rapid-response-microsoft-exchange-servers-still-vulnerable-to-proxyshell-exploit#what-should-you-do)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.003/windows-sysmon_proxylogon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.003/windows-sysmon_proxylogon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/detect_exchange_web_shell.yml) \| *version*: **3**