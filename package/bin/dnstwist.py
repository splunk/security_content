#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#
#
# Licensed under the Apache License, Version 2.0 (the "License"): you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
#
# Code modified from DNSTwist (https://github.com/elceef/dnstwist)
# Thanks elceef!
#
# Changes made:
# Just kept the DomainFuzz class and passing the domain to the fuzzer.  Then added
# the Splunk specific code around it
#

from __future__ import absolute_import, division, print_function, unicode_literals

import sys
import re
import csv
import time
import os

from splunklib.searchcommands import dispatch, GeneratingCommand, \
    Configuration, Option, Boolean
from splunk.clilib.bundle_paths import make_splunkhome_path


class DomainFuzz(object):

    def __init__(self, domain):
        self.domain, self.tld = self.__domain_tld(domain)
        self.domains = []
        self.qwerty = {
            '1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3',
            '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7',
            '9': '0oi8', '0': 'po9', 'q': '12wa', 'w': '3esaq2',
            'e': '4rdsw3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6',
            'u': '8ijhy7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
            'a': 'qwsz', 's': 'edxzaw', 'd': 'rfcxse', 'f': 'tgvcdr',
            'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'ikmnhu', 'k': 'olmji',
            'l': 'kop', 'z': 'asx', 'x': 'zsdc', 'c': 'xdfv',
            'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
        }
        self.qwertz = {
            '1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3',
            '5': '6tr4', '6': '7zt5', '7': '8uz6', '8': '9iu7',
            '9': '0oi8', '0': 'po9', 'q': '12wa', 'w': '3esaq2',
            'e': '4rdsw3', 'r': '5tfde4', 't': '6zgfr5',
            'z': '7uhgt6', 'u': '8ijhz7', 'i': '9okju8',
            'o': '0plki9', 'p': 'lo0', 'a': 'qwsy', 's': 'edxyaw',
            'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'zhbvft',
            'h': 'ujnbgz', 'j': 'ikmnhu', 'k': 'olmji', 'l': 'kop',
            'y': 'asx', 'x': 'ysdc', 'c': 'xdfv', 'v': 'cfgb',
            'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
        }
        self.azerty = {
            '1': '2a', '2': '3za1', '3': '4ez2', '4': '5re3',
            '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7',
            '9': '0oi8', '0': 'po9', 'a': '2zq1', 'z': '3esqa2',
            'e': '4rdsz3', 'r': '5tfde4', 't': '6ygfr5',
            'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8',
            'o': '0plki9', 'p': 'lo0m', 'q': 'zswa', 's': 'edxwqz',
            'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft',
            'h': 'ujnbgy', 'j': 'iknhu', 'k': 'olji', 'l': 'kopm',
            'm': 'lp', 'w': 'sxq', 'x': 'zsdc', 'c': 'xdfv',
            'v': 'cfgb', 'b': 'vghn', 'n': 'bhj'
        }
        self.keyboards = [self.qwerty, self.qwertz, self.azerty]

    def __domain_tld(self, domain):
        domain = domain.rsplit('.', 2)

        if len(domain) == 2:
            return domain[0], domain[1]

        return domain[0] + '.' + domain[1], domain[2]

    def __validate_domain(self, domain):
        if len(domain) == len(domain.encode('idna')) and domain != domain.encode('idna'):
            return False
        allowed = re.compile(b'(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\\.)+[a-zA-Z]{2,63}\\.?$)', re.IGNORECASE)
        return allowed.match(domain.encode('idna'))

    def __filter_domains(self):
        seen = set()
        filtered = []

        for d in self.domains:
            # if not self.__validate_domain(d['domain-name']):
            #   p_err("debug: invalid domain %s\n" % d['domain-name'])
            try:
                if self.__validate_domain(d['domain-name']) and d['domain-name'] not in seen:
                    seen.add(d['domain-name'])
                    filtered.append(d)
            except ValueError:
                continue

        self.domains = filtered

    def __bitsquatting(self):
        result = []
        masks = [1, 2, 4, 8, 16, 32, 64, 128]
        for i in range(0, len(self.domain)):
            c = self.domain[i]
            for j in range(0, len(masks)):
                b = chr(ord(c) ^ masks[j])
                o = ord(b)
                if (o >= 48 and o <= 57) or (o >= 97 and o <= 122) or o == 45:
                    result.append(self.domain[:i] + b + self.domain[i+1:])

        return result

    def __homoglyph(self):
        glyphs = {
            'a': [u'à', u'á', u'â', u'ã', u'ä', u'å', u'ɑ', u'а', u'ạ', u'ǎ', u'ă', u'ȧ', u'ӓ'],
            'b': ['d', 'lb', 'ib', u'ʙ', u'Ь', u'b̔', u'ɓ', u'Б'],
            'c': [u'ϲ', u'с', u'ƈ', u'ċ', u'ć', u'ç'],
            'd': ['b', 'cl', 'dl', 'di', u'ԁ', u'ժ', u'ɗ', u'đ'],
            'e': [u'é', u'ê', u'ë', u'ē', u'ĕ', u'ě', u'ė', u'е', u'ẹ', u'ę', u'є', u'ϵ', u'ҽ'],
            'f': [u'Ϝ', u'ƒ', u'Ғ'],
            'g': ['q', u'ɢ', u'ɡ', u'Ԍ', u'Ԍ', u'ġ', u'ğ', u'ց', u'ǵ', u'ģ'],
            'h': ['lh', 'ih', u'һ', u'հ', u'Ꮒ', u'н'],
            'i': ['1', 'l', u'Ꭵ', u'í', u'ï', u'ı', u'ɩ', u'ι', u'ꙇ', u'ǐ', u'ĭ'],
            'j': [u'ј', u'ʝ', u'ϳ', u'ɉ'],
            'k': ['lk', 'ik', 'lc', u'κ', u'ⲕ', u'κ'],
            'l': ['1', 'i', u'ɫ', u'ł'],
            'm': ['n', 'nn', 'rn', 'rr', u'ṃ', u'ᴍ', u'м', u'ɱ'],
            'n': ['m', 'r', u'ń'],
            'o': ['0', u'Ο', u'ο', u'О', u'о', u'Օ', u'ȯ', u'ọ', u'ỏ', u'ơ', u'ó', u'ö', u'ӧ'],
            'p': [u'ρ', u'р', u'ƿ', u'Ϸ', u'Þ'],
            'q': ['g', u'զ', u'ԛ', u'գ', u'ʠ'],
            'r': [u'ʀ', u'Г', u'ᴦ', u'ɼ', u'ɽ'],
            's': [u'Ⴝ', u'Ꮪ', u'ʂ', u'ś', u'ѕ'],
            't': [u'τ', u'т', u'ţ'],
            'u': [u'μ', u'υ', u'Ս', u'ս', u'ц', u'ᴜ', u'ǔ', u'ŭ'],
            'v': [u'ѵ', u'ν', u'v̇'],
            'w': ['vv', u'ѡ', u'ա', u'ԝ'],
            'x': [u'х', u'ҳ', u'ẋ'],
            'y': [u'ʏ', u'γ', u'у', u'Ү', u'ý'],
            'z': [u'ʐ', u'ż', u'ź', u'ʐ', u'ᴢ']
        }

        result = []

        for ws in range(0, len(self.domain)):
            for i in range(0, (len(self.domain)-ws)+1):
                win = self.domain[i:i+ws]

                j = 0
                while j < ws:
                    c = win[j]
                    if c in glyphs:
                        win_copy = win
                        for g in glyphs[c]:
                            win = win.replace(c, g)
                            result.append(self.domain[:i] + win + self.domain[i+ws:])
                            win = win_copy
                    j += 1

        return list(set(result))

    def __hyphenation(self):
        result = []

        for i in range(1, len(self.domain)):
            result.append(self.domain[:i] + '-' + self.domain[i:])

        return result

    def __insertion(self):
        result = []

        for i in range(1, len(self.domain)-1):
            for keys in self.keyboards:
                if self.domain[i] in keys:
                    for c in keys[self.domain[i]]:
                        result.append(self.domain[:i] + c + self.domain[i] + self.domain[i+1:])
                        result.append(self.domain[:i] + self.domain[i] + c + self.domain[i+1:])

        return list(set(result))

    def __omission(self):
        result = []

        for i in range(0, len(self.domain)):
            result.append(self.domain[:i] + self.domain[i+1:])

        n = re.sub(r'(.)\1+', r'\1', self.domain)

        if n not in result and n != self.domain:
            result.append(n)

        return list(set(result))

    def __repetition(self):
        result = []

        for i in range(0, len(self.domain)):
            if self.domain[i].isalpha():
                result.append(self.domain[:i] + self.domain[i] + self.domain[i] + self.domain[i+1:])

        return list(set(result))

    def __replacement(self):
        result = []

        for i in range(0, len(self.domain)):
            for keys in self.keyboards:
                if self.domain[i] in keys:
                    for c in keys[self.domain[i]]:
                        result.append(self.domain[:i] + c + self.domain[i+1:])

        return list(set(result))

    def __subdomain(self):
        result = []

        for i in range(1, len(self.domain)):
            if self.domain[i] not in ['-', '.'] and self.domain[i-1] not in ['-', '.']:
                result.append(self.domain[:i] + '.' + self.domain[i:])

        return result

    def __transposition(self):
        result = []

        for i in range(0, len(self.domain)-1):
            if self.domain[i+1] != self.domain[i]:
                result.append(self.domain[:i] + self.domain[i+1] + self.domain[i] + self.domain[i+2:])

        return result

    def __vowel_swap(self):
        vowels = 'aeiou'
        result = []

        for i in range(0, len(self.domain)):
            for vowel in vowels:
                if self.domain[i] in vowels:
                    result.append(self.domain[:i] + vowel + self.domain[i+1:])

        return list(set(result))

    def __addition(self):
        result = []

        for i in range(97, 123):
            result.append(self.domain + chr(i))

        return result

    def generate(self):
        self.domains.append({'fuzzer': 'Original*', 'domain-name': self.domain + '.' + self.tld})

        for domain in self.__addition():
            self.domains.append({'fuzzer': 'Addition', 'domain-name': domain + '.' + self.tld})
        for domain in self.__bitsquatting():
            self.domains.append({'fuzzer': 'Bitsquatting', 'domain-name': domain + '.' + self.tld})
        for domain in self.__homoglyph():
            self.domains.append({'fuzzer': 'Homoglyph', 'domain-name': domain + '.' + self.tld})
        for domain in self.__hyphenation():
            self.domains.append({'fuzzer': 'Hyphenation', 'domain-name': domain + '.' + self.tld})
        for domain in self.__insertion():
            self.domains.append({'fuzzer': 'Insertion', 'domain-name': domain + '.' + self.tld})
        for domain in self.__omission():
            self.domains.append({'fuzzer': 'Omission', 'domain-name': domain + '.' + self.tld})
        for domain in self.__repetition():
            self.domains.append({'fuzzer': 'Repetition', 'domain-name': domain + '.' + self.tld})
        for domain in self.__replacement():
            self.domains.append({'fuzzer': 'Replacement', 'domain-name': domain + '.' + self.tld})
        for domain in self.__subdomain():
            self.domains.append({'fuzzer': 'Subdomain', 'domain-name': domain + '.' + self.tld})
        for domain in self.__transposition():
            self.domains.append({'fuzzer': 'Transposition', 'domain-name': domain + '.' + self.tld})
        for domain in self.__vowel_swap():
            self.domains.append({'fuzzer': 'Vowel-swap', 'domain-name': domain + '.' + self.tld})

        if not self.domain.startswith('www.'):
            self.domains.append({'fuzzer': 'Various', 'domain-name': 'ww' + self.domain + '.' + self.tld})
            self.domains.append({'fuzzer': 'Various', 'domain-name': 'www' + self.domain + '.' + self.tld})
            self.domains.append({'fuzzer': 'Various', 'domain-name': 'www-' + self.domain + '.' + self.tld})
        if '.' in self.tld:
            self.domains.append({'fuzzer': 'Various', 'domain-name': self.domain + '.' + self.tld.split('.')[-1]})
            self.domains.append({'fuzzer': 'Various', 'domain-name': self.domain + self.tld})
        if '.' not in self.tld:
            self.domains.append({'fuzzer': 'Various', 'domain-name': self.domain + self.tld + '.' + self.tld})
        if self.tld != 'com' and '.' not in self.tld:
            self.domains.append({'fuzzer': 'Various', 'domain-name': self.domain + '-' + self.tld + '.com'})

        self.__filter_domains()


@Configuration(distributed=True)
class DnsTwistCommand(GeneratingCommand):

    domainlist_file_name = Option(doc='''
        **Syntax:** **domainlist=***<path>*
        **Description:** CSV file from which repeated random samples will be drawn
        ''', name='domainlist', require=False)

    populate_from_cim = Option(doc='''
        **Syntax: populate_cim=<bool>
        **Description:** When `true`, populates Splunk_SA_CIM lookups cim_corporate_email_domains.csv
        and cim_corporate_web_domains.csv with dnstwisted domains. Defaults to `false`.
        ''', name='populate_from_cim', default=False, validate=Boolean())

    domain = Option(doc='''
        **Syntax:** **domain=***<domain name>*
        **Description:** Domain to DNS generated twisted entries for.
        ''', name='domain', require=False, default='')

    def generate(self):
        event_count = 0
        csv_file_names = []

        if self.populate_from_cim:
            csv_file_names.append(make_splunkhome_path([
                'etc',
                'apps',
                'Splunk_SA_CIM',
                'lookups',
                'cim_corporate_email_domains.csv']))
            csv_file_names.append(make_splunkhome_path([
                'etc',
                'apps',
                'Splunk_SA_CIM',
                'lookups',
                'cim_corporate_web_domains.csv']))

        # Make sure we just get the base file name from file. In case there was some directory traversal going on.
        if self.domainlist_file_name:
            sanitized_file_name = os.path.basename(self.domainlist_file_name)
            lookup_path = make_splunkhome_path(['etc', 'apps', 'DA-ESS-ContentUpdate', 'lookups', sanitized_file_name])

            # Make sure there really isn't any directory traversal going on.
            valid_path = True
            if "../" in lookup_path:
                valid_path = False

            # Make sure the path that is created by adding the file name to the path is the same as the
            # absolute path
            if lookup_path != os.path.abspath(lookup_path):
                valid_path = False

            if valid_path:
                csv_file_names.append(lookup_path)

        domains_to_twist = []

        for csv_file_name in csv_file_names:
            if os.path.exists(csv_file_name):
                # this is nasty but works .. please forgive me
                if sys.version_info >= (3, 0):
                    csv_file = open(csv_file_name, "r", newline='')
                else:
                    csv_file = open(csv_file_name, "r")
                for input_domain in csv.DictReader(csv_file):
                    if input_domain['domain'] not in domains_to_twist:
                        domains_to_twist.append(input_domain['domain'])

        # if a single domain is passed lets just calculate that
        if self.domain != '':
            domains_to_twist = []
            domains_to_twist.append(self.domain)

        for domain_to_twist in domains_to_twist:
            domain_to_twist = domain_to_twist.lstrip('*')
            dfuzz = DomainFuzz(domain_to_twist)
            dfuzz.generate()
            domains = dfuzz.domains
            for domain in domains:
                # We don't want to keep the original domain
                if domain['domain-name'] in domain_to_twist:
                    continue
                event_count += 1
                yield {
                        '_time': time.time(),
                        'event_no': event_count,
                        '_raw': domain['domain-name'],
                        'domain': '*'+domain['domain-name']+'*',
                        'original_domain': domain_to_twist
                }

    def __init__(self):
        super(DnsTwistCommand, self).__init__()


dispatch(DnsTwistCommand, sys.argv, sys.stdin, sys.stdout, __name__)
