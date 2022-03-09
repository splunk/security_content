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
| [Linux Add Files In Known Crontab Directories](/endpoint/linux_add_files_in_known_crontab_directories/) | None| Anomaly |
| [Linux Add User Account](/endpoint/linux_add_user_account/) | None| Hunting |
| [Linux At Allow Config File Creation](/endpoint/linux_at_allow_config_file_creation/) | None| Anomaly |
| [Linux At Application Execution](/endpoint/linux_at_application_execution/) | None| Anomaly |
| [Linux Change File Owner To Root](/endpoint/linux_change_file_owner_to_root/) | None| Anomaly |
| [Linux Common Process For Elevation Control](/endpoint/linux_common_process_for_elevation_control/) | None| Hunting |
| [Linux Doas Conf File Creation](/endpoint/linux_doas_conf_file_creation/) | None| Anomaly |
| [Linux Doas Tool Execution](/endpoint/linux_doas_tool_execution/) | None| Anomaly |
| [Linux Edit Cron Table Parameter](/endpoint/linux_edit_cron_table_parameter/) | None| Hunting |
| [Linux File Created In Kernel Driver Directory](/endpoint/linux_file_created_in_kernel_driver_directory/) | None| Anomaly |
| [Linux File Creation In Init Boot Directory](/endpoint/linux_file_creation_in_init_boot_directory/) | None| Anomaly |
| [Linux File Creation In Profile Directory](/endpoint/linux_file_creation_in_profile_directory/) | None| Anomaly |
| [Linux Insert Kernel Module Using Insmod Utility](/endpoint/linux_insert_kernel_module_using_insmod_utility/) | None| Anomaly |
| [Linux Install Kernel Module Using Modprobe Utility](/endpoint/linux_install_kernel_module_using_modprobe_utility/) | None| Anomaly |
| [Linux NOPASSWD Entry In Sudoers File](/endpoint/linux_nopasswd_entry_in_sudoers_file/) | None| Anomaly |
| [Linux Possible Access Or Modification Of sshd Config File](/endpoint/linux_possible_access_or_modification_of_sshd_config_file/) | None| Anomaly |
| [Linux Possible Access To Credential Files](/endpoint/linux_possible_access_to_credential_files/) | None| Anomaly |
| [Linux Possible Access To Sudoers File](/endpoint/linux_possible_access_to_sudoers_file/) | None| Anomaly |
| [Linux Possible Append Command To At Allow Config File](/endpoint/linux_possible_append_command_to_at_allow_config_file/) | None| Anomaly |
| [Linux Possible Append Command To Profile Config File](/endpoint/linux_possible_append_command_to_profile_config_file/) | None| Anomaly |
| [Linux Possible Append Cronjob Entry on Existing Cronjob File](/endpoint/linux_possible_append_cronjob_entry_on_existing_cronjob_file/) | None| Hunting |
| [Linux Possible Cronjob Modification With Editor](/endpoint/linux_possible_cronjob_modification_with_editor/) | None| Hunting |
| [Linux Possible Ssh Key File Creation](/endpoint/linux_possible_ssh_key_file_creation/) | None| Anomaly |
| [Linux Preload Hijack Library Calls](/endpoint/linux_preload_hijack_library_calls/) | None| TTP |
| [Linux Service File Created In Systemd Directory](/endpoint/linux_service_file_created_in_systemd_directory/) | None| Anomaly |
| [Linux Service Restarted](/endpoint/linux_service_restarted/) | None| Anomaly |
| [Linux Service Started Or Enabled](/endpoint/linux_service_started_or_enabled/) | None| Anomaly |
| [Linux Setuid Using Chmod Utility](/endpoint/linux_setuid_using_chmod_utility/) | None| Anomaly |
| [Linux Setuid Using Setcap Utility](/endpoint/linux_setuid_using_setcap_utility/) | None| Anomaly |
| [Linux Sudo OR Su Execution](/endpoint/linux_sudo_or_su_execution/) | None| Hunting |
| [Linux Sudoers Tmp File Creation](/endpoint/linux_sudoers_tmp_file_creation/) | None| Anomaly |
| [Linux Visudo Utility Execution](/endpoint/linux_visudo_utility_execution/) | None| Anomaly |

#### Reference

* [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)
* [https://kifarunix.com/scheduling-tasks-using-at-command-in-linux/](https://kifarunix.com/scheduling-tasks-using-at-command-in-linux/)
* [https://gtfobins.github.io/gtfobins/at/](https://gtfobins.github.io/gtfobins/at/)
* [https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf](https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/linux_persistence_techniques.yml) \| *version*: **1**