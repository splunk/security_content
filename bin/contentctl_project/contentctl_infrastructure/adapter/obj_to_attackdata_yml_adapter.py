import os
import re
from pathlib import Path
from bin.contentctl_project.contentctl_infrastructure.adapter.yml_writer import YmlWriter
from bin.contentctl_project.contentctl_core.application.adapter.adapter import Adapter
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType
import shutil

class ObjToAttackDataYmlAdapter(Adapter):

    def __init__(self):
        self.ATTACK_DATASET_LINK = "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets"
        self.sourcetype_dict = {
        'windows-sysmon.log':'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational', 
        'windows-security.log': 'WinEventLog:Security',
        'windows-system.log': 'WinEventLog:system',
        'windows-powershell-xml.log' :'XmlWinEventLog:Microsoft-Windows-PowerShell/Operational',
        'stream_http_events.log' :'stream:http',
        'aws_cloudtrail_events.json' :'aws:cloudtrail',
        'o365_events.json' :'o365:management:activity',
        'o365_exchange_events.json' :'o365:management:activity',
        'kubernetes_events.json' :'kubernetes',
        'security_hub_finding.json' :'aws:securityhub:finding',
        'gsuite_gmail_bigquery.json' :'gsuite:gmail:bigquery',
        'gsuite_drive_json.json':'gsuite:drive:json',
        'github.json' : 'aws:firehose:json',
        'kubernetes_nginx.json' :'kube:container:controller',
        'circleci.json' :'circleci',
        'sysmon_linux.log' :'Syslog:Linux-Sysmon/Operational',
        'xml-windows-security.log': 'XmlWinEventLog:Security',
        'xml-windows-system.log': 'XmlWinEventLog:System', 
        'xml-windows-application.log': 'XmlWinEventLog:Application',                              
        'xml-windows-directory-service.log': 'XmlWinEventLog:Directory Service'
        }
        return

    def banner(self):
        print("""
        inspired from contentctl.py ...
        running attack dataset utility helper. 
        warming up "Millenium Falcon"...  
                      c==o
                    _/____\_
            _.,--'" ||^ || "`z._
            /_/^ ___\||  || _/o\ "`-._
            _/  ]. L_| || .||  \_/_  . _`--._
        /_~7  _ . " ||. || /] \ ]. (_)  . "`--.
        |__7~.(_)_ []|+--+|/____T_____________L|
        |__|  _^(_) /^   __\____e_   _|
        |__| (_){_) J ]K{__ L___0_   _]
        |__| . _(_) \v     /__________|________
        l__l_ (_). []|+-+-<\^   L  . _   - ---L|
        \__\    __. ||^l  \Y] /_]  (_) .  _,--'
            \~_]  L_| || .\ .\\/~.    _,--'"
            \_\ . __/||  |\  \`-+-<'"
                "`---._|J__L|X o~~|[\\      
        -Row      \____/ \___|[//      
                   `--'   `--+-'
        """)

    def expand_path(self, in_path: str) -> str:
        if "~" in in_path:
            return str(in_path).replace("~", str(Path.home()))
        else:
            return in_path


    def extract_base_path(self, in_path: str) -> str:
        return os.path.basename(os.path.normpath(self.expand_path(in_path)))


    def gen_attack_data_descp(self, in_path: str) -> str:
        descp = "Generated datasets for {} in attack range.".format(self.extract_base_path(self.expand_path(in_path)).replace("_"," "))
        return descp


    def writeObjects(self, objects: list, output_path: str, type: SecurityContentType = None) -> None:

        ## check if src_path exist
        expanded_src_path = self.expand_path(objects['src_path'])
        expanded_dst_path = self.expand_path(objects['dst_path'])
        try:
            st = os.stat(expanded_src_path)
        except os.error:
            print("[x] ERROR: File {0} is not exist".format(objects['src_path']))
            exit()

        ## check if dest_path exist
        if not os.path.isdir(expanded_dst_path):
            os.makedirs(expanded_dst_path, exist_ok=True)
            
        objects['description'] = self.gen_attack_data_descp(objects['dst_path'])
        
        objects['dataset'] = [self.ATTACK_DATASET_LINK + objects['dst_path'].split("datasets")[1] + os.sep + self.extract_base_path(objects['src_path'])]
        
        objects['sourcetypes'] = [self.sourcetype_dict[objects['sourcetypes'][0]]]
        
        attack_data_yml_file = expanded_dst_path + os.sep + self.extract_base_path(objects['dst_path']).replace(" ", "_") + ".yml"
        
        ## copy the dataset to the destination folder
        shutil.copy(expanded_src_path, expanded_dst_path)

        objects.pop('src_path')
        
        objects.pop('dst_path')
        
        YmlWriter.writeYmlFile(attack_data_yml_file, objects)

        ## read attackdata file
        with open(attack_data_yml_file, 'r') as f:
            self.banner()
            print("[+] ----------- generated attack data yml file ------------\n")
            print(f.read())



