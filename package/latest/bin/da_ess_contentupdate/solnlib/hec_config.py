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

from . import splunk_rest_client as rest_client
from .packages.splunklib import binding
from .utils import retry

__all__ = ['HECConfig']


class HECConfig(object):
    '''HTTP Event Collector configuration.

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
    '''

    input_type = 'http'

    def __init__(self, session_key, scheme=None,
                 host=None, port=None, **context):
        self._rest_client = rest_client.SplunkRestClient(
            session_key,
            'splunk_httpinput',
            scheme=scheme,
            host=host,
            port=port,
            **context)

    @retry(exceptions=[binding.HTTPError])
    def get_settings(self):
        '''Get http data input global settings.

        :returns: Http global setting like: {
            'enableSSL': 1,
            'disabled': 0,
            'useDeploymentServer': 0,
            'port': 8088}
        :rtype: ``dict``
        '''

        return self._do_get_input(self.input_type).content

    @retry(exceptions=[binding.HTTPError])
    def update_settings(self, settings):
        '''Update http data input global settings.

        :param settings: Http global setting like: {
            'enableSSL': 1,
            'disabled': 0,
            'useDeploymentServer': 0,
            'port': 8088}
        :type settings: ``dict``
        '''

        res = self._do_get_input(self.input_type)
        res.update(**settings)

    @retry(exceptions=[binding.HTTPError])
    def create_input(self, name, stanza):
        '''Create http data input.

        :param name: Http data input name.
        :type name: ``string``
        :param stanza: Data input stanza content like: {
            'index': 'main'
            'sourcetype': 'akamai:cm:json'}
        :type stanza: ``dict``
        :returns: Dict object like: {
            'index': 'main',
            'sourcetype': 'test',
            'host': 'Kens-MacBook-Pro.local',
            'token': 'A0-5800-406B-9224-8E1DC4E720B7'}
        :rtype: ``dict``

        Usage::

           >>> from solnlib import HEConfig
           >>> hec = HECConfig(session_key)
           >>> hec.create_input('my_hec_data_input',
                                {'index': 'main', 'sourcetype': 'hec'})
        '''

        res = self._rest_client.inputs.create(name, self.input_type, **stanza)
        return res.content

    @retry(exceptions=[binding.HTTPError])
    def update_input(self, name, stanza):
        '''Update http data input.

        It will create if the data input doesn't exist.

        :param name: Http data input name.
        :type name: ``string``
        :param stanza: Data input stanza like: {
            'index': 'main'
            'sourcetype': 'akamai:cm:json'}
        :type stanza: ``dict``

        Usage::

           >>> from solnlib import HEConfig
           >>> hec = HECConfig(session_key)
           >>> hec.update_input('my_hec_data_input',
                                {'index': 'main', 'sourcetype': 'hec2'})
        '''

        res = self._do_get_input(name)
        if res is None:
            return self.create_input(name, stanza)
        res.update(**stanza)

    @retry(exceptions=[binding.HTTPError])
    def delete_input(self, name):
        '''Delete http data input.

        :param name: Http data input name
        :type name: ``string``
        '''

        try:
            self._rest_client.inputs.delete(name, self.input_type)
        except KeyError:
            pass

    @retry(exceptions=[binding.HTTPError])
    def get_input(self, name):
        '''Get http data input.

        :param name: Http event collector data input name,
        :type name: ``string``
        :returns: Http event collector data input config dict, like: {
            'disabled': '0',
            'index': 'main',
            'sourcetype': 'hec'} if successful else None.
        :rtype: ``dict``
        '''

        res = self._do_get_input(name)
        if res:
            return res.content
        else:
            return None

    def _do_get_input(self, name):
        try:
            return self._rest_client.inputs[(name, self.input_type)]
        except KeyError:
            return None

    @retry(exceptions=[binding.HTTPError])
    def get_limits(self):
        '''Get http input limits.

        :returns: Dict object like: {
            'metrics_report_interval': '60',
            'max_content_length': '2000000',
            'max_number_of_acked_requests_pending_query': '10000000',
            ...}
        :rtype: ``dict``
        '''

        return self._rest_client.confs['limits']['http_input'].content

    @retry(exceptions=[binding.HTTPError])
    def set_limits(self, limits):
        ''' Set http input limits.

        :param limits: Dict object which can contain: {
            'max_content_length': '3000000',
            'metrics_report_interval': '70',
            ...}
        :type limits: ``dict``
        '''

        res = self._rest_client.confs['limits']['http_input']
        res.submit(limits)
