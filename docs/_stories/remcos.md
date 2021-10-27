---
title: "Remcos"
last_modified_at: 2021-09-23
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the Remcos RAT trojan, including looking for file writes associated with its payload, screencapture, registry modification, UAC bypassed, persistence and data collection..

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-23
- **Author**: Teoderick Contreras, Splunk
- **ID**: 2bd4aa08-b9a5-40cf-bfe5-7d43f13d496c

#### Narrative

Remcos or Remote Control and Surveillance, marketed as a legitimate software for remotely managing Windows systems is now widely used in multiple malicious campaigns both APT and commodity malware by threat actors.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Disabling Remote User Account Control](/endpoint/disabling_remote_user_account_control/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | TTP |
| [Executables Or Script Creation In Suspicious Path](/endpoint/executables_or_script_creation_in_suspicious_path/) | [Masquerading](/tags/#masquerading) | TTP |
| [Malicious InProcServer32 Modification](/endpoint/malicious_inprocserver32_modification/) | [Regsvr32](/tags/#regsvr32), [Modify Registry](/tags/#modify-registry) | TTP |
| [Process Deleting Its Process File Path](/endpoint/process_deleting_its_process_file_path/) | [Indicator Removal on Host](/tags/#indicator-removal-on-host) | TTP |
| [Process Writing DynamicWrapperX](/endpoint/process_writing_dynamicwrapperx/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Component Object Model](/tags/#component-object-model) | Hunting |
| [Registry Keys Used For Persistence](/endpoint/registry_keys_used_for_persistence/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | TTP |
| [Remcos RAT File Creation in Remcos Folder](/endpoint/remcos_rat_file_creation_in_remcos_folder/) | [Screen Capture](/tags/#screen-capture) | TTP |
| [Remcos client registry install entry](/endpoint/remcos_client_registry_install_entry/) | [Modify Registry](/tags/#modify-registry) | TTP |
| [Suspicious Image Creation In Appdata Folder](/endpoint/suspicious_image_creation_in_appdata_folder/) | [Screen Capture](/tags/#screen-capture) | TTP |
| [Suspicious Process File Path](/endpoint/suspicious_process_file_path/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | TTP |
| [Suspicious WAV file in Appdata Folder](/endpoint/suspicious_wav_file_in_appdata_folder/) | [Screen Capture](/tags/#screen-capture) | TTP |
| [Vbscript Execution Using Wscript App](/endpoint/vbscript_execution_using_wscript_app/) | [Visual Basic](/tags/#visual-basic), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | TTP |
| [Winhlp32 Spawning a Process](/endpoint/winhlp32_spawning_a_process/) | [Process Injection](/tags/#process-injection) | TTP |
| [Wscript Or Cscript Suspicious Child Process](/endpoint/wscript_or_cscript_suspicious_child_process/) | [Process Injection](/tags/#process-injection), [Create or Modify System Process](/tags/#create-or-modify-system-process), [Parent PID Spoofing](/tags/#parent-pid-spoofing), [Access Token Manipulation](/tags/#access-token-manipulation) | TTP |

#### Reference

* [https://success.trendmicro.com/solution/1123281-remcos-malware-information](https://success.trendmicro.com/solution/1123281-remcos-malware-information)
* [https://attack.mitre.org/software/S0332/](https://attack.mitre.org/software/S0332/)
* [https://malpedia.caad.fkie.fraunhofer.de/details/win.remcos#:~:text=Remcos%20(acronym%20of%20Remote%20Control,used%20to%20remotely%20control%20computers.&text=Remcos%20can%20be%20used%20for,been%20used%20in%20hacking%20campaigns.](https://malpedia.caad.fkie.fraunhofer.de/details/win.remcos#:~:text=Remcos%20(acronym%20of%20Remote%20Control,used%20to%20remotely%20control%20computers.&text=Remcos%20can%20be%20used%20for,been%20used%20in%20hacking%20campaigns.)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/remcos.yml) \| *version*: **1**