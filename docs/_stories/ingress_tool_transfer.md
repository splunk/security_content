---
title: "Ingress Tool Transfer"
last_modified_at: 2021-03-24
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Adversaries may transfer tools or other files from an external system into a compromised environment. Files may be copied from an external adversary controlled system through the command and control channel to bring tools into the victim network or through alternate protocols with another tool such as FTP.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-03-24
- **Author**: Michael Haag, Splunk
- **ID**: b3782036-8cbd-11eb-9d8e-acde48001122

#### Narrative

Ingress tool transfer is a Technique under tactic Command and Control. Behaviors will include the use of living off the land binaries to download implants or binaries over alternate communication ports. It is imperative to baseline applications on endpoints to understand what generates network activity, to where, and what is its native behavior. These utilities, when abused, will write files to disk in world writeable paths.\ During triage, review the reputation of the remote public destination IP or domain. Capture any files written to disk and perform analysis. Review other parrallel processes for additional behaviors.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Any Powershell DownloadFile](/endpoint/any_powershell_downloadfile/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell)| TTP |
| [Any Powershell DownloadString](/endpoint/any_powershell_downloadstring/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell)| TTP |
| [BITSAdmin Download File](/endpoint/bitsadmin_download_file/) | [BITS Jobs](/tags/#bits-jobs), [Ingress Tool Transfer](/tags/#ingress-tool-transfer)| TTP |
| [CertUtil Download With URLCache and Split Arguments](/endpoint/certutil_download_with_urlcache_and_split_arguments/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer)| TTP |
| [CertUtil Download With VerifyCtl and Split Arguments](/endpoint/certutil_download_with_verifyctl_and_split_arguments/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer)| TTP |
| [Curl Download and Bash Execution](/endpoint/curl_download_and_bash_execution/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer)| TTP |
| [Wget Download and Bash Execution](/endpoint/wget_download_and_bash_execution/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer)| TTP |
| [Windows Curl Download to Suspicious Path](/endpoint/windows_curl_download_to_suspicious_path/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer)| TTP |
| [Windows Curl Upload to Remote Destination](/endpoint/windows_curl_upload_to_remote_destination/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer)| TTP |
| [Suspicious Curl Network Connection](/endpoint/suspicious_curl_network_connection/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer)| TTP |

#### Reference

* [https://attack.mitre.org/techniques/T1105/](https://attack.mitre.org/techniques/T1105/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/ingress_tool_transfer.yml) \| *version*: **1**