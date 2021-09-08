#!/usr/bin/env python
# coding=utf-8
#
# Copyright 2011-2015 Splunk, Inc.
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

import app
import os,sys
import requests

splunkhome = os.environ['SPLUNK_HOME']
sys.path.append(os.path.join(splunkhome, 'etc', 'apps', 'devsecops', 'lib'))
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, validators, Option
from splunklib.searchcommands.validators import Code

@Configuration()
class WgetCommand(StreamingCommand):
    """ Call wget from url in data.
    ##Syntax
    .. code-block::
        wget url=<field> fieldname=<field>
    ##Description
    The :code:`wget` command calls a url which is present in a field.
    ##Example
    tbd
    """
    url = Option(
        doc='''
        **Syntax:** **url=***<url>*
        **Description:** Name of the field that contains a given url''',
        require=True, validate=validators.Fieldname())

    fieldname = Option(
        doc='''
        **Syntax:** **fieldname=***<fieldname>*
        **Description:** Name of the field that will hold the return data''',
        require=True, validate=validators.Fieldname())

    def stream(self, records):
        self.logger.debug('WgetCommand: %s', self)  # logs command line
        url = self.url
        # to do check if valid url

        for record in records:
            r = requests.get(url)
            record[self.fieldname] = r.json()
            yield record

dispatch(WgetCommand, sys.argv, sys.stdin, sys.stdout, __name__)