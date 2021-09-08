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

from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, validators, Option
from splunklib.searchcommands.validators import Code

@Configuration()
class WgetCommand(StreamingCommand):
    """ Call wget from url in data.
    ##Syntax
    .. code-block::
        wget output=<field> <field-list>
    ##Description
    The :code:`wget` command calls a url which is present in a field.
    ##Example
    tbd
    """

    output = Option(
        doc='''
        **Syntax:** **output=***<output>*
        **Description:** Name of the field that will hold the return data''',
        require=True, validate=validators.Fieldname())

    def stream(self, records):
        self.logger.debug('WgetCommand: %s', self)  # logs command line
        fieldnames = self.fieldnames

        for record in records:
            for fieldname in fieldnames:
                r = requests.get(record[fieldname])
                record[self.output] = r.json()
                yield record

dispatch(WgetCommand, sys.argv, sys.stdin, sys.stdout, __name__)