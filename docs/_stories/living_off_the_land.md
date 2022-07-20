---
title: "Living Off The Land"
last_modified_at: 2022-03-16
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Risk
  - Actions on Objectives
  - Exploitation
  - Installation
  - Reconnaissance
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage analytics that allow you to identify the presence of an adversary leveraging native applications within your environment.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Risk](https://docs.splunk.com/Documentation/CIM/latest/User/Risk)
- **Last Updated**: 2022-03-16
- **Author**: Lou Stella, Splunk
- **ID**: 6f7982e2-900b-11ec-a54a-acde48001122

#### Narrative

Living Off The Land refers to an adversary methodology of using native applications already installed on the target operating system to achieve their objective. Native utilities provide the adversary with reduced chances of detection by antivirus software or EDR tools. This allows the adversary to blend in with native process behavior.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [BITS Job Persistence](/endpoint/bits_job_persistence/) | [BITS Jobs](/tags/#bits-jobs)| TTP |
| [BITSAdmin Download File](/endpoint/bitsadmin_download_file/) | [BITS Jobs](/tags/#bits-jobs), [Ingress Tool Transfer](/tags/#ingress-tool-transfer)| TTP |
| [CertUtil Download With URLCache and Split Arguments](/endpoint/certutil_download_with_urlcache_and_split_arguments/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer)| TTP |
| [CertUtil Download With VerifyCtl and Split Arguments](/endpoint/certutil_download_with_verifyctl_and_split_arguments/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer)| TTP |
| [Certutil exe certificate extraction](/endpoint/certutil_exe_certificate_extraction/) | None| TTP |
| [CertUtil With Decode Argument](/endpoint/certutil_with_decode_argument/) | [Deobfuscate/Decode Files or Information](/tags/#deobfuscate/decode-files-or-information)| TTP |
| [CMD Carry Out String Command Parameter](/endpoint/cmd_carry_out_string_command_parameter/) | [Windows Command Shell](/tags/#windows-command-shell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter)| Hunting |
| [Control Loading from World Writable Directory](/endpoint/control_loading_from_world_writable_directory/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Control Panel](/tags/#control-panel)| TTP |
| [Creation of Shadow Copy with wmic and powershell](/endpoint/creation_of_shadow_copy_with_wmic_and_powershell/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping)| TTP |
| [Detect HTML Help Renamed](/endpoint/detect_html_help_renamed/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Compiled HTML File](/tags/#compiled-html-file)| Hunting |
| [Detect HTML Help Spawn Child Process](/endpoint/detect_html_help_spawn_child_process/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Compiled HTML File](/tags/#compiled-html-file)| TTP |
| [Detect HTML Help URL in Command Line](/endpoint/detect_html_help_url_in_command_line/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Compiled HTML File](/tags/#compiled-html-file)| TTP |
| [Detect HTML Help Using InfoTech Storage Handlers](/endpoint/detect_html_help_using_infotech_storage_handlers/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Compiled HTML File](/tags/#compiled-html-file)| TTP |
| [Detect mshta inline hta execution](/endpoint/detect_mshta_inline_hta_execution/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Mshta](/tags/#mshta)| TTP |
| [Detect mshta renamed](/endpoint/detect_mshta_renamed/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Mshta](/tags/#mshta)| Hunting |
| [Detect MSHTA Url in Command Line](/endpoint/detect_mshta_url_in_command_line/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Mshta](/tags/#mshta)| TTP |
| [Detect Regasm Spawning a Process](/endpoint/detect_regasm_spawning_a_process/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Regsvcs/Regasm](/tags/#regsvcs/regasm)| TTP |
| [Detect Regasm with Network Connection](/endpoint/detect_regasm_with_network_connection/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Regsvcs/Regasm](/tags/#regsvcs/regasm)| TTP |
| [Detect Regasm with no Command Line Arguments](/endpoint/detect_regasm_with_no_command_line_arguments/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Regsvcs/Regasm](/tags/#regsvcs/regasm)| TTP |
| [Detect Regsvcs Spawning a Process](/endpoint/detect_regsvcs_spawning_a_process/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Regsvcs/Regasm](/tags/#regsvcs/regasm)| TTP |
| [Detect Regsvcs with Network Connection](/endpoint/detect_regsvcs_with_network_connection/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Regsvcs/Regasm](/tags/#regsvcs/regasm)| TTP |
| [Detect Regsvcs with No Command Line Arguments](/endpoint/detect_regsvcs_with_no_command_line_arguments/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Regsvcs/Regasm](/tags/#regsvcs/regasm)| TTP |
| [Detect Regsvr32 Application Control Bypass](/endpoint/detect_regsvr32_application_control_bypass/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Regsvr32](/tags/#regsvr32)| TTP |
| [Detect Rundll32 Application Control Bypass - advpack](/endpoint/detect_rundll32_application_control_bypass_-_advpack/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32)| TTP |
| [Detect Rundll32 Application Control Bypass - setupapi](/endpoint/detect_rundll32_application_control_bypass_-_setupapi/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32)| TTP |
| [Detect Rundll32 Application Control Bypass - syssetup](/endpoint/detect_rundll32_application_control_bypass_-_syssetup/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32)| TTP |
| [Detect Rundll32 Inline HTA Execution](/endpoint/detect_rundll32_inline_hta_execution/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Mshta](/tags/#mshta)| TTP |
| [Disable Schedule Task](/endpoint/disable_schedule_task/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses)| TTP |
| [Dump LSASS via comsvcs DLL](/endpoint/dump_lsass_via_comsvcs_dll/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping)| TTP |
| [Esentutl SAM Copy](/endpoint/esentutl_sam_copy/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping)| Hunting |
| [Eventvwr UAC Bypass](/endpoint/eventvwr_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism)| TTP |
| [Living Off The Land](/endpoint/living_off_the_land/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer), [Exploit Public-Facing Application](/tags/#exploit-public-facing-application), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter)| Correlation |
| [MacOS LOLbin](/endpoint/macos_lolbin/) | [Unix Shell](/tags/#unix-shell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter)| TTP |
| [MacOS plutil](/endpoint/macos_plutil/) | [Plist File Modification](/tags/#plist-file-modification)| TTP |
| [Mmc LOLBAS Execution Process Spawn](/endpoint/mmc_lolbas_execution_process_spawn/) | [Remote Services](/tags/#remote-services), [Distributed Component Object Model](/tags/#distributed-component-object-model), [MMC](/tags/#mmc)| TTP |
| [Mshta spawning Rundll32 OR Regsvr32 Process](/endpoint/mshta_spawning_rundll32_or_regsvr32_process/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Mshta](/tags/#mshta)| TTP |
| [Ntdsutil Export NTDS](/endpoint/ntdsutil_export_ntds/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping)| TTP |
| [Reg exe Manipulating Windows Services Registry Keys](/endpoint/reg_exe_manipulating_windows_services_registry_keys/) | [Services Registry Permissions Weakness](/tags/#services-registry-permissions-weakness), [Hijack Execution Flow](/tags/#hijack-execution-flow)| TTP |
| [Regsvr32 Silent and Install Param Dll Loading](/endpoint/regsvr32_silent_and_install_param_dll_loading/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Regsvr32](/tags/#regsvr32)| Anomaly |
| [Regsvr32 with Known Silent Switch Cmdline](/endpoint/regsvr32_with_known_silent_switch_cmdline/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Regsvr32](/tags/#regsvr32)| Anomaly |
| [Remote WMI Command Attempt](/endpoint/remote_wmi_command_attempt/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation)| TTP |
| [Rundll32 Control RunDLL Hunt](/endpoint/rundll32_control_rundll_hunt/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32)| Hunting |
| [Rundll32 Control RunDLL World Writable Directory](/endpoint/rundll32_control_rundll_world_writable_directory/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32)| TTP |
| [Rundll32 Create Remote Thread To A Process](/endpoint/rundll32_create_remote_thread_to_a_process/) | [Process Injection](/tags/#process-injection)| TTP |
| [Rundll32 CreateRemoteThread In Browser](/endpoint/rundll32_createremotethread_in_browser/) | [Process Injection](/tags/#process-injection)| TTP |
| [Rundll32 DNSQuery](/endpoint/rundll32_dnsquery/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32)| TTP |
| [Rundll32 Process Creating Exe Dll Files](/endpoint/rundll32_process_creating_exe_dll_files/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32)| TTP |
| [Rundll32 Shimcache Flush](/endpoint/rundll32_shimcache_flush/) | [Modify Registry](/tags/#modify-registry)| TTP |
| [RunDLL Loading DLL By Ordinal](/endpoint/rundll_loading_dll_by_ordinal/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32)| TTP |
| [Schedule Task with HTTP Command Arguments](/endpoint/schedule_task_with_http_command_arguments/) | [Scheduled Task/Job](/tags/#scheduled-task/job)| TTP |
| [Schedule Task with Rundll32 Command Trigger](/endpoint/schedule_task_with_rundll32_command_trigger/) | [Scheduled Task/Job](/tags/#scheduled-task/job)| TTP |
| [Scheduled Task Creation on Remote Endpoint using At](/endpoint/scheduled_task_creation_on_remote_endpoint_using_at/) | [Scheduled Task/Job](/tags/#scheduled-task/job), [At](/tags/#at)| TTP |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/scheduled_task_deleted_or_created_via_cmd/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job)| TTP |
| [Scheduled Task Initiation on Remote Endpoint](/endpoint/scheduled_task_initiation_on_remote_endpoint/) | [Scheduled Task/Job](/tags/#scheduled-task/job), [Scheduled Task](/tags/#scheduled-task)| TTP |
| [Schtasks scheduling job on remote system](/endpoint/schtasks_scheduling_job_on_remote_system/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job)| TTP |
| [Services LOLBAS Execution Process Spawn](/endpoint/services_lolbas_execution_process_spawn/) | [Create or Modify System Process](/tags/#create-or-modify-system-process), [Windows Service](/tags/#windows-service)| TTP |
| [Suspicious IcedID Rundll32 Cmdline](/endpoint/suspicious_icedid_rundll32_cmdline/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32)| TTP |
| [Suspicious microsoft workflow compiler rename](/endpoint/suspicious_microsoft_workflow_compiler_rename/) | [Masquerading](/tags/#masquerading), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Rename System Utilities](/tags/#rename-system-utilities)| Hunting |
| [Suspicious microsoft workflow compiler usage](/endpoint/suspicious_microsoft_workflow_compiler_usage/) | [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution)| TTP |
| [Suspicious msbuild path](/endpoint/suspicious_msbuild_path/) | [Masquerading](/tags/#masquerading), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Rename System Utilities](/tags/#rename-system-utilities), [MSBuild](/tags/#msbuild)| TTP |
| [Suspicious MSBuild Rename](/endpoint/suspicious_msbuild_rename/) | [Masquerading](/tags/#masquerading), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Rename System Utilities](/tags/#rename-system-utilities), [MSBuild](/tags/#msbuild)| Hunting |
| [Suspicious MSBuild Spawn](/endpoint/suspicious_msbuild_spawn/) | [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [MSBuild](/tags/#msbuild)| TTP |
| [Suspicious mshta child process](/endpoint/suspicious_mshta_child_process/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Mshta](/tags/#mshta)| TTP |
| [Suspicious mshta spawn](/endpoint/suspicious_mshta_spawn/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Mshta](/tags/#mshta)| TTP |
| [Suspicious Regsvr32 Register Suspicious Path](/endpoint/suspicious_regsvr32_register_suspicious_path/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Regsvr32](/tags/#regsvr32)| TTP |
| [Suspicious Rundll32 dllregisterserver](/endpoint/suspicious_rundll32_dllregisterserver/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32)| TTP |
| [Suspicious Scheduled Task from Public Directory](/endpoint/suspicious_scheduled_task_from_public_directory/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job)| Anomaly |
| [Svchost LOLBAS Execution Process Spawn](/endpoint/svchost_lolbas_execution_process_spawn/) | [Scheduled Task/Job](/tags/#scheduled-task/job), [Scheduled Task](/tags/#scheduled-task)| TTP |
| [Windows Binary Proxy Execution Mavinject DLL Injection](/endpoint/windows_binary_proxy_execution_mavinject_dll_injection/) | [Mavinject](/tags/#mavinject), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution)| TTP |
| [Windows Diskshadow Proxy Execution](/endpoint/windows_diskshadow_proxy_execution/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution)| TTP |
| [Windows Identify Protocol Handlers](/endpoint/windows_identify_protocol_handlers/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter)| Hunting |
| [Windows Indirect Command Execution Via forfiles](/endpoint/windows_indirect_command_execution_via_forfiles/) | [Indirect Command Execution](/tags/#indirect-command-execution)| TTP |
| [Windows Indirect Command Execution Via pcalua](/endpoint/windows_indirect_command_execution_via_pcalua/) | [Indirect Command Execution](/tags/#indirect-command-execution)| TTP |
| [Windows InstallUtil in Non Standard Path](/endpoint/windows_installutil_in_non_standard_path/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [InstallUtil](/tags/#installutil)| TTP |
| [Windows InstallUtil Remote Network Connection](/endpoint/windows_installutil_remote_network_connection/) | [InstallUtil](/tags/#installutil), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution)| TTP |
| [Windows InstallUtil Uninstall Option](/endpoint/windows_installutil_uninstall_option/) | [InstallUtil](/tags/#installutil), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution)| TTP |
| [Windows InstallUtil Uninstall Option with Network](/endpoint/windows_installutil_uninstall_option_with_network/) | [InstallUtil](/tags/#installutil), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution)| TTP |
| [Windows InstallUtil URL in Command Line](/endpoint/windows_installutil_url_in_command_line/) | [InstallUtil](/tags/#installutil), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution)| TTP |
| [Windows MOF Event Triggered Execution via WMI](/endpoint/windows_mof_event_triggered_execution_via_wmi/) | [Windows Management Instrumentation Event Subscription](/tags/#windows-management-instrumentation-event-subscription)| TTP |
| [Windows Odbcconf Hunting](/endpoint/windows_odbcconf_hunting/) | [Odbcconf](/tags/#odbcconf)| Hunting |
| [Windows Odbcconf Load DLL](/endpoint/windows_odbcconf_load_dll/) | [Odbcconf](/tags/#odbcconf)| TTP |
| [Windows Odbcconf Load Response File](/endpoint/windows_odbcconf_load_response_file/) | [Odbcconf](/tags/#odbcconf)| TTP |
| [WSReset UAC Bypass](/endpoint/wsreset_uac_bypass/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism)| TTP |

#### Reference

* [https://lolbas-project.github.io/](https://lolbas-project.github.io/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/living_off_the_land.yml) \| *version*: **2**