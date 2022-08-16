---
title: "Java Writing JSP File"
excerpt: "Exploit Public-Facing Application
"
categories:
  - Endpoint
last_modified_at: 2022-06-03
toc: true
toc_label: ""
tags:
  - Exploit Public-Facing Application
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2022-22965
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the process java writing a .jsp to disk. This is potentially indicative of a web shell being written to disk. Modify and tune the analytic based on data ingested. For instance, it may be worth running a broad query for jsp file writes first before performing a join.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-06-03
- **Author**: Michael Haag, Splunk
- **ID**: eb65619c-4f8d-4383-a975-d352765d344b


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Initial Access |

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

* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 5
* CIS 16



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">
| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2022-22965](https://nvd.nist.gov/vuln/detail/CVE-2022-22965) | A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it. | 7.5 |



</div>
</details>

#### Search 

```

| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes where Processes.process_name IN ("java","java.exe", "javaw.exe") by _time Processes.process_id Processes.process_name Processes.dest Processes.process_guid Processes.user 
| `drop_dm_object_name(Processes)` 
| join process_guid [
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Filesystem where Filesystem.file_name="*.jsp*" by _time Filesystem.dest Filesystem.file_create_time Filesystem.file_name Filesystem.file_path Filesystem.process_guid Filesystem.user 
| `drop_dm_object_name(Filesystem)` 
| fields _time process_guid file_path file_name file_create_time user dest process_name] 
| stats count min(_time) as firstTime max(_time) as lastTime by dest process_name process_guid file_name file_path file_create_time user 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `java_writing_jsp_file_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **java_writing_jsp_file_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
* Filesystem.dest
* Filesystem.file_create_time
* Filesystem.file_name
* Filesystem.file_path
* Filesystem.process_guid
* Filesystem.user


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` and `Filesystem` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
False positives are possible and filtering may be required. Restrict by assets or filter known jsp files that are common for the environment.

#### Associated Analytic story
* [Spring4Shell CVE-2022-22965](/stories/spring4shell_cve-2022-22965)
* [Atlassian Confluence Server and Data Center CVE-2022-26134](/stories/atlassian_confluence_server_and_data_center_cve-2022-26134)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 42.0 | 60 | 70 | An instance of $process_name$ was identified on endpoint $dest$ writing a jsp file to disk, potentially indicative of exploitation. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://www.microsoft.com/security/blog/2022/04/04/springshell-rce-vulnerability-guidance-for-protecting-against-and-detecting-cve-2022-22965/](https://www.microsoft.com/security/blog/2022/04/04/springshell-rce-vulnerability-guidance-for-protecting-against-and-detecting-cve-2022-22965/)
* [https://github.com/TheGejr/SpringShell](https://github.com/TheGejr/SpringShell)
* [https://www.tenable.com/blog/spring4shell-faq-spring-framework-remote-code-execution-vulnerability](https://www.tenable.com/blog/spring4shell-faq-spring-framework-remote-code-execution-vulnerability)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/spring4shell/java_write_jsp-linux-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/spring4shell/java_write_jsp-linux-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/java_writing_jsp_file.yml) \| *version*: **2**