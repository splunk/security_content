---
title: "Linux Living Off The Land"
last_modified_at: 2022-07-27
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
  - Delivery
  - Exploitation
  - Installation
  - Reconnaissance
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Linux Living Off The Land consists of binaries that may be used to bypass local security restrictions within misconfigured systems.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-07-27
- **Author**: Michael Haag, Splunk
- **ID**: e405a2d7-dc8e-4227-8e9d-f60267b8c0cd

#### Narrative

Similar to Windows LOLBAS project, the GTFOBins project focuses solely on Unix binaries that may be abused in multiple categories including Reverse Shell, File Upload, File Download and much more. These binaries are native to the operating system and the functionality is typically native. The behaviors are typically not malicious by default or vulnerable, but these are built in functionality of the applications. When reviewing any notables or hunting through mountains of events of interest, it's important to identify the binary, review command-line arguments, path of file, and capture any network and file modifications. Linux analysis may be a bit cumbersome due to volume and how process behavior is seen in EDR products. Piecing it together will require some effort.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Curl Download and Bash Execution](/endpoint/curl_download_and_bash_execution/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer)| TTP |
| [Linux Add Files In Known Crontab Directories](/endpoint/linux_add_files_in_known_crontab_directories/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job)| Anomaly |
| [Linux Adding Crontab Using List Parameter](/endpoint/linux_adding_crontab_using_list_parameter/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job)| Hunting |
| [Linux At Allow Config File Creation](/endpoint/linux_at_allow_config_file_creation/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job)| Anomaly |
| [Linux At Application Execution](/endpoint/linux_at_application_execution/) | [At](/tags/#at), [Scheduled Task/Job](/tags/#scheduled-task/job)| Anomaly |
| [Linux AWK Privilege Escalation](/endpoint/linux_awk_privilege_escalation/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism)| Anomaly |
| [Linux Change File Owner To Root](/endpoint/linux_change_file_owner_to_root/) | [Linux and Mac File and Directory Permissions Modification](/tags/#linux-and-mac-file-and-directory-permissions-modification), [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification)| Anomaly |
| [Linux Clipboard Data Copy](/endpoint/linux_clipboard_data_copy/) | [Clipboard Data](/tags/#clipboard-data)| Anomaly |
| [Linux Common Process For Elevation Control](/endpoint/linux_common_process_for_elevation_control/) | [Setuid and Setgid](/tags/#setuid-and-setgid), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism)| Hunting |
| [Linux Curl Upload File](/endpoint/linux_curl_upload_file/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer)| TTP |
| [Linux Decode Base64 to Shell](/endpoint/linux_decode_base64_to_shell/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information), [Unix Shell](/tags/#unix-shell)| TTP |
| [Linux Docker Privilege Escalation](/endpoint/linux_docker_privilege_escalation/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism)| Anomaly |
| [Linux Edit Cron Table Parameter](/endpoint/linux_edit_cron_table_parameter/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job)| Hunting |
| [Linux Ingress Tool Transfer Hunting](/endpoint/linux_ingress_tool_transfer_hunting/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer)| Hunting |
| [Linux Ingress Tool Transfer with Curl](/endpoint/linux_ingress_tool_transfer_with_curl/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer)| Anomaly |
| [Linux Node Privilege Escalation](/endpoint/linux_node_privilege_escalation/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism)| Anomaly |
| [Linux Obfuscated Files or Information Base64 Decode](/endpoint/linux_obfuscated_files_or_information_base64_decode/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information)| Anomaly |
| [Linux pkexec Privilege Escalation](/endpoint/linux_pkexec_privilege_escalation/) | [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation)| TTP |
| [Linux Possible Access Or Modification Of sshd Config File](/endpoint/linux_possible_access_or_modification_of_sshd_config_file/) | [SSH Authorized Keys](/tags/#ssh-authorized-keys), [Account Manipulation](/tags/#account-manipulation)| Anomaly |
| [Linux Possible Append Cronjob Entry on Existing Cronjob File](/endpoint/linux_possible_append_cronjob_entry_on_existing_cronjob_file/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job)| Hunting |
| [Linux Possible Cronjob Modification With Editor](/endpoint/linux_possible_cronjob_modification_with_editor/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job)| Hunting |
| [Linux Possible Ssh Key File Creation](/endpoint/linux_possible_ssh_key_file_creation/) | [SSH Authorized Keys](/tags/#ssh-authorized-keys), [Account Manipulation](/tags/#account-manipulation)| Anomaly |
| [Linux Proxy Socks Curl](/endpoint/linux_proxy_socks_curl/) | [Proxy](/tags/#proxy), [Non-Application Layer Protocol](/tags/#non-application-layer-protocol)| TTP |
| [Linux Service File Created In Systemd Directory](/endpoint/linux_service_file_created_in_systemd_directory/) | [Systemd Timers](/tags/#systemd-timers), [Scheduled Task/Job](/tags/#scheduled-task/job)| Anomaly |
| [Linux Service Restarted](/endpoint/linux_service_restarted/) | [Systemd Timers](/tags/#systemd-timers), [Scheduled Task/Job](/tags/#scheduled-task/job)| Anomaly |
| [Linux Service Started Or Enabled](/endpoint/linux_service_started_or_enabled/) | [Systemd Timers](/tags/#systemd-timers), [Scheduled Task/Job](/tags/#scheduled-task/job)| Anomaly |
| [Linux Setuid Using Chmod Utility](/endpoint/linux_setuid_using_chmod_utility/) | [Setuid and Setgid](/tags/#setuid-and-setgid), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism)| Anomaly |
| [Linux SSH Authorized Keys Modification](/endpoint/linux_ssh_authorized_keys_modification/) | [SSH Authorized Keys](/tags/#ssh-authorized-keys)| Anomaly |
| [Linux SSH Remote Services Script Execute](/endpoint/linux_ssh_remote_services_script_execute/) | [SSH](/tags/#ssh)| TTP |
| [Suspicious Curl Network Connection](/endpoint/suspicious_curl_network_connection/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer)| TTP |

#### Reference

* [https://gtfobins.github.io/](https://gtfobins.github.io/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/linux_living_off_the_land.yml) \| *version*: **1**