# Copyright 2016 Splunk, Inc.
#
# Licensed under the Apache License, Version 2.0 (the 'License'): you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

'''
This module provides interfaces to parse and convert timestamp.
'''

import datetime
import json

from . import splunk_rest_client as rest_client
from .packages.splunklib import binding
from .utils import retry

__all__ = ['TimeParser']


class InvalidTimeFormatException(Exception):
    pass


class TimeParser(object):
    '''Datetime parser.

    Use splunkd rest to parse datetime.

    :param session_key: Splunk access token.
    :type session_key: ``string``
    :param scheme: (optional) The access scheme, default is None.
    :type scheme: ``string``
    :param host: (optional) The host name, default is None.
    :type host: ``string``
    :param port: (optional) The port number, default is None.
    :type port: ``integer``
    :param context: Other configurations for Splunk rest client.
    :type context: ``dict``

    Usage::

       >>> from solnlib import time_parser
       >>> tp = time_parser.TimeParser(session_key)
       >>> tp.to_seconds('2011-07-06T21:54:23.000-07:00')
       >>> tp.to_utc('2011-07-06T21:54:23.000-07:00')
       >>> tp.to_local('2011-07-06T21:54:23.000-07:00')
    '''

    URL = '/services/search/timeparser'

    def __init__(self, session_key,
                 scheme=None, host=None, port=None, **context):
        self._rest_client = rest_client.SplunkRestClient(
            session_key,
            '-',
            scheme=scheme,
            host=host,
            port=port,
            **context)

    @retry(exceptions=[binding.HTTPError])
    def to_seconds(self, time_str):
        '''Parse `time_str` and convert to seconds since epoch.

        :param time_str: ISO8601 format timestamp, example:
            2011-07-06T21:54:23.000-07:00.
        :type time_str: ``string``
        :returns: Seconds since epoch.
        :rtype: ``float``
        '''

        try:
            response = self._rest_client.get(
                self.URL, output_mode='json',
                time=time_str, output_time_format='%s').body.read()
        except binding.HTTPError as e:
            if e.status != 400:
                raise

            raise InvalidTimeFormatException(
                'Invalid time format: %s.' % time_str)

        seconds = json.loads(response)[time_str]
        return float(seconds)

    def to_utc(self, time_str):
        '''Parse `time_str` and convert to UTC timestamp.

        :param time_str: ISO8601 format timestamp, example:
            2011-07-06T21:54:23.000-07:00.
        :type time_str: ``string``
        :returns: UTC timestamp.
        :rtype: ``datetime.datetime``
        '''

        return datetime.datetime.utcfromtimestamp(self.to_seconds(time_str))

    @retry(exceptions=[binding.HTTPError])
    def to_local(self, time_str):
        '''Parse `time_str` and convert to local timestamp.

        :param time_str: ISO8601 format timestamp, example:
            2011-07-06T21:54:23.000-07:00.
        :type time_str: ``string``
        :returns: local timestamp in ISO8601 format.
        :rtype: ``string``
        '''

        try:
            response = self._rest_client.get(
                self.URL, output_mode='json',
                time=time_str).body.read()
        except binding.HTTPError as e:
            if e.status != 400:
                raise

            raise InvalidTimeFormatException(
                'Invalid time format: %s.' % time_str)

        return json.loads(response)[time_str]
