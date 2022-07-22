---
title: "Windows File Extension and Association Abuse"
last_modified_at: 2018-01-26
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Detect and investigate suspected abuse of file extensions and Windows file associations. Some of the malicious behaviors involved may include inserting spaces before file extensions or prepending the file extension with a different one, among other techniques.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2018-01-26
- **Author**: Rico Valdez, Splunk
- **ID**: 30552a76-ac78-48e4-b3c0-de4e34e9563d

#### Narrative

Attackers use a variety of techniques to entice users to run malicious code or to persist on an endpoint. One way to accomplish these goals is to leverage file extensions and the mechanism Windows uses to associate files with specific applications. \
 Since its earliest days, Windows has used extensions to identify file types. Users have become familiar with these extensions and their application associations. For example, if users see that a file ends in `.doc` or `.docx`, they will assume that it is a Microsoft Word document and expect that double-clicking will open it using `winword.exe`. The user will typically also presume that the `.docx` file is safe. \
 Attackers take advantage of this expectation by obfuscating the true file extension. They can accomplish this in a couple of ways. One technique involves inserting multiple spaces in the file name before the extension to hide the extension from the GUI, obscuring the true nature of the file. Another approach involves prepending the real extension with a different one. This is especially effective when Windows is configured to "hide extensions for known file types." In this case, the real extension is not displayed, but the prepended one is, leading end users to believe the file is a different type than it actually is.\
Changing the association between a file extension and an application can allow an attacker to execute arbitrary code. The technique typically involves changing the association for an often-launched file type to associate instead with a malicious program the attacker has dropped on the endpoint. When the end user launches a file that has been manipulated in this way, it will execute the attacker's malware. It will also execute the application the end user expected to run, cleverly obscuring the fact that something suspicious has occurred.\
Run the searches in this story to detect and investigate suspicious behavior that may indicate abuse or manipulation of Windows file extensions and/or associations.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Execution of File With Spaces Before Extension](/deprecated/execution_of_file_with_spaces_before_extension/) | [Rename System Utilities](/tags/#rename-system-utilities)| TTP |
| [Suspicious Changes to File Associations](/deprecated/suspicious_changes_to_file_associations/) | [Change Default File Association](/tags/#change-default-file-association)| TTP |
| [Execution of File with Multiple Extensions](/endpoint/execution_of_file_with_multiple_extensions/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities)| TTP |

#### Reference

* [https://blog.malwarebytes.com/cybercrime/2013/12/file-extensions-2/](https://blog.malwarebytes.com/cybercrime/2013/12/file-extensions-2/)
* [https://attack.mitre.org/wiki/Technique/T1042](https://attack.mitre.org/wiki/Technique/T1042)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_file_extension_and_association_abuse.yml) \| *version*: **1**