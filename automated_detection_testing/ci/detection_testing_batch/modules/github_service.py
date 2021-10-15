
import git
import os
import logging
import glob
import subprocess
import yaml

# Logger
logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOGGER = logging.getLogger(__name__)

SECURITY_CONTENT_URL = "https://github.com/splunk/security_content"


class GithubService:

    def __init__(self, security_content_branch, PR_number = None):
        self.security_content_branch = security_content_branch
        self.security_content_repo_obj = self.clone_project(SECURITY_CONTENT_URL, f"security_content", f"develop")
        if PR_number:
            subprocess.call(["git", "-C", "security_content/", "fetch", "origin", "refs/pull/%d/head:%s"%(PR_number, security_content_branch)])

        self.security_content_repo_obj.git.checkout(security_content_branch)

    def clone_project(self, url, project, branch):
        LOGGER.info(f"Clone Security Content Project")
        repo_obj = git.Repo.clone_from(url, project, branch=branch)
        return repo_obj

    def get_changed_test_files(self):
        branch1 = self.security_content_branch
        branch2 = 'develop'
        g = git.Git('security_content')
        changed_test_files = []
        changed_detection_files = []
        if branch1 != 'develop':
            differ = g.diff('--name-status', branch2 + '...' + branch1)
            changed_files = differ.splitlines()

            for file_path in changed_files:
                # added or changed test files
                if file_path.startswith('A') or file_path.startswith('M'):
                    if 'tests' in file_path:
                        if not os.path.basename(file_path).startswith('ssa') and os.path.basename(file_path).endswith('.test.yml'):
                            if file_path not in changed_test_files:
                                changed_test_files.append(file_path)

                    # changed detections
                    if 'detections' in file_path:
                        if not os.path.basename(file_path).startswith('ssa') and os.path.basename(file_path).endswith('.yml'):
                            changed_detection_files.append(file_path)
                            #file_path_base = os.path.splitext(file_path)[0].replace('detections', 'tests') + '.test'
                            #file_path_new = file_path_base + '.yml'
                            #if file_path_new not in changed_test_files:
                            #    changed_test_files.append(file_path_new)

        #all files have the format A\tFILENAME or M\tFILENAME.  Get rid of those leading characters
        changed_test_files = [name.split('\t')[1] for name in changed_test_files if len(name.split('\t')) == 2]
        changed_detection_files = [name.split('\t')[1] for name in changed_detection_files if len(name.split('\t')) == 2]
        
        changed_detection_files = [
        "detections/endpoint/active_setup_registry_autostart.yml",
        "detections/endpoint/change_default_file_association.yml",
        "detections/endpoint/delete_shadowcopy_with_powershell.yml",
        "detections/endpoint/detect_processes_used_for_system_network_configuration_discovery.yml",
        "detections/endpoint/enable_rdp_in_other_port_number.yml",
        "detections/endpoint/enable_wdigest_uselogoncredential_registry.yml",
        "detections/endpoint/etw_registry_disabled.yml",
        "detections/endpoint/eventvwr_uac_bypass.yml",
        "detections/endpoint/get_notable_history.yml",
        "detections/endpoint/get_parent_process_info.yml",
        "detections/endpoint/get_process_info.yml",
        "detections/endpoint/hide_user_account_from_sign_in_screen.yml",
        "detections/endpoint/logon_script_event_trigger_execution.yml",
        "detections/endpoint/mailsniper_invoke_functions.yml",
        "detections/endpoint/malicious_inprocserver32_modification.yml",
        "detections/endpoint/modification_of_wallpaper.yml",
        "detections/endpoint/monitor_registry_keys_for_print_monitors.yml",
        "detections/endpoint/net_profiler_uac_bypass.yml",
        "detections/endpoint/powershell_disable_security_monitoring.yml",
        "detections/endpoint/powershell_enable_smb1protocol_feature.yml",
        "detections/endpoint/process_writing_dynamicwrapperx.yml",
        "detections/endpoint/registry_keys_used_for_persistence.yml",
        "detections/endpoint/registry_keys_used_for_privilege_escalation.yml",
        "detections/endpoint/remcos_client_registry_install_entry.yml",
        "detections/endpoint/revil_registry_entry.yml",
        "detections/endpoint/screensaver_event_trigger_execution.yml",
        "detections/endpoint/sdclt_uac_bypass.yml",
        "detections/endpoint/secretdumps_offline_ntds_dumping_tool.yml",
        "detections/endpoint/silentcleanup_uac_bypass.yml",
        "detections/endpoint/slui_runas_elevated.yml", 
        "detections/endpoint/disable_amsi_through_registry.yml",
        "detections/endpoint/disable_etw_through_registry.yml",
        "detections/endpoint/disable_registry_tool.yml",
        "detections/endpoint/disable_security_logs_using_minint_registry.yml",
        "detections/endpoint/disable_show_hidden_files.yml",
        "detections/endpoint/disable_uac_remote_restriction.yml",
        "detections/endpoint/disable_windows_app_hotkeys.yml",
        "detections/endpoint/disable_windows_behavior_monitoring.yml",
        "detections/endpoint/disable_windows_smartscreen_protection.yml",
        "detections/endpoint/disabling_cmd_application.yml",
        "detections/endpoint/disabling_controlpanel.yml",
        "detections/endpoint/disabling_folderoptions_windows_feature.yml",
        "detections/endpoint/disabling_norun_windows_app.yml",
        "detections/endpoint/disabling_remote_user_account_control.yml",
        "detections/endpoint/disabling_systemrestore_in_registry.yml",
        "detections/endpoint/disabling_task_manager.yml"]

        detections_to_test,_,_ = self.filter_test_types(changed_detection_files)
        for f in detections_to_test:
            file_path_base = os.path.splitext(f)[0].replace('detections', 'tests') + '.test'
            file_path_new = file_path_base + '.yml'
            if file_path_new not in changed_test_files:
                changed_test_files.append(file_path_new)

        
        
       
        
        #print("Total things to test (test files and detection files changed): [%d]"%(len(changed_test_files)))
        #for l in changed_test_files:
        #    print(l)
        #print(len(changed_test_files))
        #import time
        #time.sleep(5)
        return changed_test_files

    def filter_test_types(self, test_files, test_types = ["Anomaly", "Hunting", "TTP"]):
        files_to_test = []
        files_not_to_test = []
        error_files = []
        for filename in test_files:
            try:
                with open(os.path.join("security_content", filename), "r") as fileData:
                    yaml_dict = list(yaml.safe_load_all(fileData))[0]
                    if 'type' not in yaml_dict.keys():
                        print("Failed to find 'type' in the yaml for: [%s]"%(filename))
                        error_files.append(filename)
                    if yaml_dict['type'] in test_types:
                        files_to_test.append(filename)
                    else:
                        files_not_to_test.append(filename)
            except Exception as e:
                print("Error on trying to scan [%s]: [%s]"%(filename, str(e)))
                error_files.append(filename)
        print("***Detection Information***\n"\
              "\tTotal Files       : %d"
              "\tFiles to test     : %d"
              "\tFiles not to test : %d"
              "\tError files       : %d"%(len(test_files), len(files_to_test), len(files_not_to_test), len(error_files)))
        import time
        time.sleep(5)
        return files_to_test, files_not_to_test, error_files    



                




