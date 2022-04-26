---
title: "Signed Binary Proxy Execution InstallUtil"
last_modified_at: 2021-11-12
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Adversaries may use InstallUtil to proxy execution of code through a trusted Windows utility.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-11-12
- **Author**: Michael Haag, Splunk
- **ID**: 9482a314-43dc-11ec-a3c9-acde48001122

#### Narrative

InstallUtil is a command-line utility that allows for installation and uninstallation of resources by executing specific installer components specified in .NET binaries. InstallUtil is digitally signed by Microsoft and located in the .NET directories on a Windows system: C:\Windows\Microsoft.NET\Framework\v\InstallUtil.exe and C:\Windows\Microsoft.NET\Framework64\v\InstallUtil.exe. \
There are multiple ways to instantiate InstallUtil and they are all outlined within Atomic Red Team - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.004/T1218.004.md. Two specific ways may be used and that includes invoking via  installer assembly class constructor through .NET and via InstallUtil.exe. \
Typically, adversaries will utilize the most commonly found way to invoke via InstallUtil Uninstall method. \
Note that parallel processes, and parent process, play a role in how InstallUtil is being used. In particular, a developer using InstallUtil will spawn from VisualStudio. Adversaries, will spawn from non-standard processes like Explorer.exe, cmd.exe or PowerShell.exe. It's important to review the command-line to identify the DLL being loaded. \
Parallel processes may also include csc.exe being used to compile a local `.cs` file. This file will be the input to the output. Developers usually do not build direct on the command shell, therefore this should raise suspicion.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Windows DotNet Binary in Non Standard Path](/endpoint/windows_dotnet_binary_in_non_standard_path/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [InstallUtil](/tags/#installutil)| TTP |
| [Windows InstallUtil Credential Theft](/endpoint/windows_installutil_credential_theft/) | [InstallUtil](/tags/#installutil), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution)| TTP |
| [Windows InstallUtil in Non Standard Path](/endpoint/windows_installutil_in_non_standard_path/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution), [InstallUtil](/tags/#installutil)| TTP |
| [Windows InstallUtil Remote Network Connection](/endpoint/windows_installutil_remote_network_connection/) | [InstallUtil](/tags/#installutil), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution)| TTP |
| [Windows InstallUtil Uninstall Option](/endpoint/windows_installutil_uninstall_option/) | [InstallUtil](/tags/#installutil), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution)| TTP |
| [Windows InstallUtil Uninstall Option with Network](/endpoint/windows_installutil_uninstall_option_with_network/) | [InstallUtil](/tags/#installutil), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution)| TTP |
| [Windows InstallUtil URL in Command Line](/endpoint/windows_installutil_url_in_command_line/) | [InstallUtil](/tags/#installutil), [Signed Binary Proxy Execution](/tags/#signed-binary-proxy-execution)| TTP |

#### Reference

* [https://attack.mitre.org/techniques/T1218/004/](https://attack.mitre.org/techniques/T1218/004/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.004/T1218.004.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.004/T1218.004.md)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/signed_binary_proxy_execution_installutil.yml) \| *version*: **1**