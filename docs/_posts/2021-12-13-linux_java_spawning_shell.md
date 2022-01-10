---
title: "Linux Java Spawning Shell"
excerpt: "Exploit Public-Facing Application"
categories:
  - Endpoint
last_modified_at: 2021-12-13
toc: true
toc_label: ""
tags:
  - Exploit Public-Facing Application
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2021-44228
  - Endpoint
---

### ⚠️ WARNING THIS IS A EXPERIMENTAL DETECTION
We have not been able to test, simulate, or build datasets for this detection. Use at your own risk. This analytic is **NOT** supported.


[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the process name of Java, Apache, or Tomcat spawning a Linux shell. This is potentially indicative of exploitation of the Java application and may be related to current event CVE-2021-44228 (Log4Shell). The shells included in the macro are &#34;sh&#34;, &#34;ksh&#34;, &#34;zsh&#34;, &#34;bash&#34;, &#34;dash&#34;, &#34;rbash&#34;, &#34;fish&#34;, &#34;csh&#39;, &#34;tcsh&#39;, &#34;ion&#34;, &#34;eshell&#34;. Upon triage, review parallel processes and command-line arguments to determine legitimacy.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-12-13
- **Author**: Michael Haag, Splunk
- **ID**: 7b09db8a-5c20-11ec-9945-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Initial Access |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name=java OR Processes.parent_process_name=apache OR Processes.parent_process_name=tomcat `linux_shells` by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `linux_java_spawning_shell_filter`
```

#### Associated Analytic Story
* [Log4Shell CVE-2021-44228](/stories/log4shell_cve-2021-44228)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon for Linux, you will need to ensure mapping is occurring correctly. Ensure EDR product is mapping OS Linux to the datamodel properly. Add any additional java process names for your environment to the analytic as needed.

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


#### Kill Chain Phase
* Exploitation


#### Known False Positives
Filtering may be required on internal developer build systems or classify assets as web facing and restrict the analytic based on that.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 40.0 | 80 | 50 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ spawning a Linux shell, potentially indicative of exploitation. |



#### CVE

| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) | Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0, this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects. | 9.3 |



#### Reference

* [https://blog.netlab.360.com/ten-families-of-malicious-samples-are-spreading-using-the-log4j2-vulnerability-now/](https://blog.netlab.360.com/ten-families-of-malicious-samples-are-spreading-using-the-log4j2-vulnerability-now/)
* [https://gist.github.com/olafhartong/916ebc673ba066537740164f7e7e1d72](https://gist.github.com/olafhartong/916ebc673ba066537740164f7e7e1d72)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)




[*source*](https://github.com/splunk/security_content/tree/develop/detections/experimental/endpoint/linux_java_spawning_shell.yml) \| *version*: **1**