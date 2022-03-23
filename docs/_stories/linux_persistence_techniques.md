---
title: "Linux Persistence Techniques"
last_modified_at: 2021-12-17
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

Monitor for activities and techniques associated with maintaining persistence on a Linux system--a sign that an adversary may have compromised your environment.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-12-17
- **Author**: Teoderick Contreras, Splunk
- **ID**: e40d13e5-d38b-457e-af2a-e8e6a2f2b516

#### Narrative

Maintaining persistence is one of the first steps taken by attackers after the initial compromise. Attackers leverage various custom and built-in tools to ensure survivability and persistent access within a compromised enterprise. This Analytic Story provides searches to help you identify various behaviors used by attackers to maintain persistent access to a Linux environment.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Linux Add Files In Known Crontab Directories](/endpoint/linux_add_files_in_known_crontab_directories/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job)| Anomaly |
| [Linux Add User Account](/endpoint/linux_add_user_account/) | [Local Account](/tags/#local-account), [Create Account](/tags/#create-account)| Hunting |
| [Linux At Allow Config File Creation](/endpoint/linux_at_allow_config_file_creation/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job)| Anomaly |
| [Linux At Application Execution](/endpoint/linux_at_application_execution/) | [At (Linux)](/tags/#at-(linux)), [Scheduled Task/Job](/tags/#scheduled-task/job)| Anomaly |
| [Linux Change File Owner To Root](/endpoint/linux_change_file_owner_to_root/) | [Linux and Mac File and Directory Permissions Modification](/tags/#linux-and-mac-file-and-directory-permissions-modification), [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification)| Anomaly |
| [Linux Common Process For Elevation Control](/endpoint/linux_common_process_for_elevation_control/) | [Setuid and Setgid](/tags/#setuid-and-setgid), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism)| Hunting |
| [Linux Doas Conf File Creation](/endpoint/linux_doas_conf_file_creation/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism)| Anomaly |
| [Linux Doas Tool Execution](/endpoint/linux_doas_tool_execution/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism)| Anomaly |
| [Linux Edit Cron Table Parameter](/endpoint/linux_edit_cron_table_parameter/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job)| Hunting |
| [Linux File Created In Kernel Driver Directory](/endpoint/linux_file_created_in_kernel_driver_directory/) | [Kernel Modules and Extensions](/tags/#kernel-modules-and-extensions), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution)| Anomaly |
| [Linux File Creation In Init Boot Directory](/endpoint/linux_file_creation_in_init_boot_directory/) | [RC Scripts](/tags/#rc-scripts), [Boot or Logon Initialization Scripts](/tags/#boot-or-logon-initialization-scripts)| Anomaly |
| [Linux File Creation In Profile Directory](/endpoint/linux_file_creation_in_profile_directory/) | [Unix Shell Configuration Modification](/tags/#unix-shell-configuration-modification), [Event Triggered Execution](/tags/#event-triggered-execution)| Anomaly |
| [Linux Insert Kernel Module Using Insmod Utility](/endpoint/linux_insert_kernel_module_using_insmod_utility/) | [Kernel Modules and Extensions](/tags/#kernel-modules-and-extensions), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution)| Anomaly |
| [Linux Install Kernel Module Using Modprobe Utility](/endpoint/linux_install_kernel_module_using_modprobe_utility/) | [Kernel Modules and Extensions](/tags/#kernel-modules-and-extensions), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution)| Anomaly |
| [Linux NOPASSWD Entry In Sudoers File](/endpoint/linux_nopasswd_entry_in_sudoers_file/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism)| Anomaly |
| [Linux Possible Access Or Modification Of sshd Config File](/endpoint/linux_possible_access_or_modification_of_sshd_config_file/) | [SSH Authorized Keys](/tags/#ssh-authorized-keys), [Account Manipulation](/tags/#account-manipulation)| Anomaly |
| [Linux Possible Access To Credential Files](/endpoint/linux_possible_access_to_credential_files/) | [/etc/passwd and /etc/shadow](/tags/#/etc/passwd-and-/etc/shadow), [OS Credential Dumping](/tags/#os-credential-dumping)| Anomaly |
| [Linux Possible Access To Sudoers File](/endpoint/linux_possible_access_to_sudoers_file/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism)| Anomaly |
| [Linux Possible Append Command To At Allow Config File](/endpoint/linux_possible_append_command_to_at_allow_config_file/) | [At (Linux)](/tags/#at-(linux)), [Scheduled Task/Job](/tags/#scheduled-task/job)| Anomaly |
| [Linux Possible Append Command To Profile Config File](/endpoint/linux_possible_append_command_to_profile_config_file/) | [Unix Shell Configuration Modification](/tags/#unix-shell-configuration-modification), [Event Triggered Execution](/tags/#event-triggered-execution)| Anomaly |
| [Linux Possible Append Cronjob Entry on Existing Cronjob File](/endpoint/linux_possible_append_cronjob_entry_on_existing_cronjob_file/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job)| Hunting |
| [Linux Possible Cronjob Modification With Editor](/endpoint/linux_possible_cronjob_modification_with_editor/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job)| Hunting |
| [Linux Possible Ssh Key File Creation](/endpoint/linux_possible_ssh_key_file_creation/) | [SSH Authorized Keys](/tags/#ssh-authorized-keys), [Account Manipulation](/tags/#account-manipulation)| Anomaly |
| [Linux Preload Hijack Library Calls](/endpoint/linux_preload_hijack_library_calls/) | [Dynamic Linker Hijacking](/tags/#dynamic-linker-hijacking), [Hijack Execution Flow](/tags/#hijack-execution-flow)| TTP |
| [Linux Service File Created In Systemd Directory](/endpoint/linux_service_file_created_in_systemd_directory/) | [Systemd Timers](/tags/#systemd-timers), [Scheduled Task/Job](/tags/#scheduled-task/job)| Anomaly |
| [Linux Service Restarted](/endpoint/linux_service_restarted/) | [Systemd Timers](/tags/#systemd-timers), [Scheduled Task/Job](/tags/#scheduled-task/job)| Anomaly |
| [Linux Service Started Or Enabled](/endpoint/linux_service_started_or_enabled/) | [Systemd Timers](/tags/#systemd-timers), [Scheduled Task/Job](/tags/#scheduled-task/job)| Anomaly |
| [Linux Setuid Using Chmod Utility](/endpoint/linux_setuid_using_chmod_utility/) | [Setuid and Setgid](/tags/#setuid-and-setgid), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism)| Anomaly |
| [Linux Setuid Using Setcap Utility](/endpoint/linux_setuid_using_setcap_utility/) | [Setuid and Setgid](/tags/#setuid-and-setgid), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism)| Anomaly |
| [Linux Sudo OR Su Execution](/endpoint/linux_sudo_or_su_execution/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism)| Hunting |
| [Linux Sudoers Tmp File Creation](/endpoint/linux_sudoers_tmp_file_creation/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism)| Anomaly |
| [Linux Visudo Utility Execution](/endpoint/linux_visudo_utility_execution/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism)| Anomaly |

#### Reference

* [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)
* [https://kifarunix.com/scheduling-tasks-using-at-command-in-linux/](https://kifarunix.com/scheduling-tasks-using-at-command-in-linux/)
* [https://gtfobins.github.io/gtfobins/at/](https://gtfobins.github.io/gtfobins/at/)
* [https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf](https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/linux_persistence_techniques.yml) \| *version*: **1**