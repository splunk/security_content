---
title: "Windows File Extension and Association Abuse"
last_modified_at: 2018-01-26
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

#### Description

Detect and investigate suspected abuse of file extensions and Windows file associations. Some of the malicious behaviors involved may include inserting spaces before file extensions or prepending the file extension with a different one, among other techniques.

- **ID**: 30552a76-ac78-48e4-b3c0-de4e34e9563d
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2018-01-26
- **Author**: Rico Valdez, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Execution of File with Multiple Extensions](/endpoint/execution_of_file_with_multiple_extensions/) | None | TTP |

#### Reference

* [https://blog.malwarebytes.com/cybercrime/2013/12/file-extensions-2/](https://blog.malwarebytes.com/cybercrime/2013/12/file-extensions-2/)
* [https://attack.mitre.org/wiki/Technique/T1042](https://attack.mitre.org/wiki/Technique/T1042)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_file_extension_and_association_abuse.yml) \| *version*: **1**