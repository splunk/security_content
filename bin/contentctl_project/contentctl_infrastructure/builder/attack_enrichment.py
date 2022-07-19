
import csv
import os
from posixpath import split
from typing import Optional
import sys
from attackcti import attack_client

import logging
logging.getLogger('taxii2client').setLevel(logging.CRITICAL)


class AttackEnrichment():

    @classmethod
    def get_attack_lookup(self, input_path: str, store_csv = None, force_cached_or_offline: bool = False, skip_enrichment:bool = False) -> dict:
        print("Getting MITRE Attack Enrichment Data. This may take some time...")
        attack_lookup = dict()
        file_path = os.path.join(input_path, "lookups", "mitre_enrichment.csv")

        if skip_enrichment is True:
            print("Skipping enrichment")
            return attack_lookup
        try:

            if force_cached_or_offline is True:
                raise(Exception("WARNING - Using cached MITRE Attack Enrichment.  Attack Enrichment may be out of date. Only use this setting for offline environments and development purposes."))
            print(f"\r{'Client'.rjust(23)}: [{0:3.0f}%]...", end="", flush=True)
            lift = attack_client()
            print(f"\r{'Client'.rjust(23)}: [{100:3.0f}%]...Done!", end="\n", flush=True)
            
            print(f"\r{'Enterprise'.rjust(23)}: [{0.0:3.0f}%]...", end="", flush=True)
            all_enterprise = lift.get_enterprise(stix_format=False)
            print(f"\r{'Enterprise'.rjust(23)}: [{100:3.0f}%]...Done!", end="\n", flush=True)
            
            print(f"\r{'Relationships'.rjust(23)}: [{0.0:3.0f}%]...", end="", flush=True)
            enterprise_relationships = lift.get_enterprise_relationships()
            print(f"\r{'Relationships'.rjust(23)}: [{100:3.0f}%]...Done!", end="\n", flush=True)
            
            print(f"\r{'Groups'.rjust(23)}: [{0:3.0f}%]...", end="", flush=True)
            enterprise_groups = lift.get_enterprise_groups()
            print(f"\r{'Groups'.rjust(23)}: [{100:3.0f}%]...Done!", end="\n", flush=True)
            
            for index, technique in enumerate(all_enterprise['techniques']):
                progress_percent = ((index+1)/len(all_enterprise['techniques'])) * 100
                if (sys.stdout.isatty() and sys.stdin.isatty() and sys.stderr.isatty()):
                    print(f"\r\t{'MITRE Technique Progress'.rjust(23)}: [{progress_percent:3.0f}%]...", end="", flush=True)
                apt_groups = []
                for relationship in enterprise_relationships:
                    if (relationship['target_ref'] == technique['id']) and relationship['source_ref'].startswith('intrusion-set'):
                        for group in enterprise_groups:
                            if relationship['source_ref'] == group['id']:
                                apt_groups.append(group['name'])

                tactics = []
                if ('tactic' in technique):
                    for tactic in technique['tactic']:
                        tactics.append(tactic.replace('-',' ').title())

                if not ('revoked' in technique):
                    attack_lookup[technique['technique_id']] = {'technique': technique['technique'], 'tactics': tactics, 'groups': apt_groups}

            if store_csv:
                f = open(file_path, 'w')
                writer = csv.writer(f)
                writer.writerow(['mitre_id', 'technique', 'tactics' ,'groups'])
                for key in attack_lookup.keys():
                    if len(attack_lookup[key]['groups']) == 0:
                        groups = 'no'
                    else:
                        groups = '|'.join(attack_lookup[key]['groups'])
                    
                    writer.writerow([
                        key,
                        attack_lookup[key]['technique'],
                        '|'.join(attack_lookup[key]['tactics']),
                        groups
                    ])
                
                f.close()

        except Exception as err:
            print('Warning: ' + str(err))
            print('Use local copy lookups/mitre_enrichment.csv')
            dict_from_csv = {}
            with open(file_path, mode='r') as inp:
                reader = csv.reader(inp)
                attack_lookup = {rows[0]:{'technique': rows[1], 'tactics': rows[2].split('|'), 'groups': rows[3].split('|')} for rows in reader}
            attack_lookup.pop('mitre_id')

        print("Done!")
        return attack_lookup