
import csv
import os
from posixpath import split
from typing import Optional

from attackcti import attack_client

import logging
logging.getLogger('taxii2client').setLevel(logging.CRITICAL)


class AttackEnrichment():

    @classmethod
    def get_attack_lookup(self, store_csv = None) -> dict:
        attack_lookup = dict()
        file_path = os.path.join(os.path.dirname(__file__), '../../../../lookups/mitre_enrichment.csv')

        try:
            lift = attack_client()
            all_enterprise = lift.get_enterprise(stix_format=False)
            enterprise_relationships = lift.get_enterprise_relationships()
            enterprise_groups = lift.get_enterprise_groups()

            for technique in all_enterprise['techniques']:
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

        return attack_lookup