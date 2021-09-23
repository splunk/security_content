---
title: "Ingress Tool Transfer"
last_modified_at: 2021-03-24
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Adversaries may transfer tools or other files from an external system into a compromised environment. Files may be copied from an external adversary controlled system through the command and control channel to bring tools into the victim network or through alternate protocols with another tool such as FTP.

- **ID**: b3782036-8cbd-11eb-9d8e-acde48001122
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-03-24
- **Author**: Michael Haag, Splunk

#### Narrative

Ingress tool transfer is a Technique under tactic Command and Control. Behaviors will include the use of living off the land binaries to download implants or binaries over alternate communication ports. It is imperative to baseline applications on endpoints to understand what generates network activity, to where, and what is its native behavior. These utilities, when abused, will write files to disk in world writeable paths.\ During triage, review the reputation of the remote public destination IP or domain. Capture any files written to disk and perform analysis. Review other parrallel processes for additional behaviors.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Any Powershell DownloadFile](/endpoint/any_powershell_downloadfile/) | [PowerShell](/tags/#powershell), [BITS Jobs](/tags/#bits-jobs), [Ingress Tool Transfer](/tags/#ingress-tool-transfer), [OS Credential Dumping](/tags/#os-credential-dumping), [Remote Services](/tags/#remote-services), [Screen Capture](/tags/#screen-capture), [Audio Capture](/tags/#audio-capture), [Remote Service Session Hijacking](/tags/#remote-service-session-hijacking), [Scheduled Task/Job](/tags/#scheduled-task/job), [Access Token Manipulation](/tags/#access-token-manipulation), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism), [Process Injection](/tags/#process-injection), [Native API](/tags/#native-api), [System Services](/tags/#system-services), [Obfuscated Files or Information](/tags/#obfuscated-files-or-information), [Indicator Removal from Tools](/tags/#indicator-removal-from-tools), [Component Object Model Hijacking](/tags/#component-object-model-hijacking), [Deobfuscate/Decode Files or Information](/tags/#deobfuscate/decode-files-or-information), [Gather Victim Host Information](/tags/#gather-victim-host-information), [Impair Defenses](/tags/#impair-defenses) | TTP |
| [Any Powershell DownloadString](/endpoint/any_powershell_downloadstring/) | [PowerShell](/tags/#powershell), [Web Shell](/tags/#web-shell), [Local Account](/tags/#local-account), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Service Execution](/tags/#service-execution), [LSASS Memory](/tags/#lsass-memory), [Remote Email Collection](/tags/#remote-email-collection), [NTDS](/tags/#ntds), [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | TTP |
| [BITSAdmin Download File](/endpoint/bitsadmin_download_file/) | [BITS Jobs](/tags/#bits-jobs), [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | TTP |
| [CertUtil Download With URLCache and Split Arguments](/endpoint/certutil_download_with_urlcache_and_split_arguments/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | TTP |
| [CertUtil Download With VerifyCtl and Split Arguments](/endpoint/certutil_download_with_verifyctl_and_split_arguments/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | TTP |
| [Suspicious Curl Network Connection](/endpoint/suspicious_curl_network_connection/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer), [Launch Agent](/tags/#launch-agent), [Data Staged](/tags/#data-staged) | TTP |

#### Reference

* [https://attack.mitre.org/techniques/T1105/](https://attack.mitre.org/techniques/T1105/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/ingress_tool_transfer.yml) \| *version*: **1**