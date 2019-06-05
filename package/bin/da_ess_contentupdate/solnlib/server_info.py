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
This module contains splunk server info related functionalities.
'''

import json

from . import splunk_rest_client as rest_client
from . import utils
from .packages.splunklib import binding
from .utils import retry

__all__ = ['ServerInfo']


class ServerInfoException(Exception):
    pass


class ServerInfo(object):
    '''This class is a wrapper of splunk server info.

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

    SHC_MEMBER_ENDPOINT = '/services/shcluster/member/members'
    SHC_CAPTAIN_INFO_ENDPOINT = '/services/shcluster/captain/info'

    def __init__(self, session_key,
                 scheme=None, host=None, port=None, **context):
        self._rest_client = rest_client.SplunkRestClient(session_key,
                                                         '-',
                                                         scheme=scheme,
                                                         host=host,
                                                         port=port,
                                                         **context)

    @retry(exceptions=[binding.HTTPError])
    def _server_info(self):
        return self._rest_client.info

    @property
    def server_name(self):
        '''Get server name.

        :returns: Server name.
        :rtype: ``string``
        '''

        return self._server_info()['serverName']

    @property
    def guid(self):
        '''Get guid for the server.

        :returns: GUID.
        :rtype: ``string``
        '''

        return self._server_info()['guid']

    @property
    def version(self):
        '''Get splunk server version.

        :returns: Splunk server version.
        :rtype: ``string``
        '''

        return self._server_info()['version']

    def is_captain(self):
        '''Check if this server is SHC captain. Note during a rolling start
           of SH members, the captain may be changed from machine to machine.
           To avoid the race condition, client may need do necessary sleep and
           then poll is_captain_ready() == True and then check is_captain().
           See is_captain_ready() for more details

        :returns: True if this server is SHC captain else False.
        :rtype: ``bool``
        '''

        return 'shc_captain' in self._server_info()['server_roles']

    def is_cloud_instance(self):
        '''Check if this server is a cloud instance.

        :returns: True if this server is a cloud instance else False.
        :rtype: ``bool``
        '''

        try:
            return self._server_info()['instance_type'] == 'cloud'
        except KeyError:
            return False

    def is_search_head(self):
        '''Check if this server is a search head.

        :returns: True if this server is a search head else False.
        :rtype: ``bool``
        '''

        server_info = self._server_info()
        for sh in ('search_head', 'cluster_search_head'):
            if sh in server_info['server_roles']:
                return True

        return False

    def is_shc_member(self):
        '''Check if this server is a SHC member.

        :returns: True if this server is a SHC member else False.
        :rtype: ``bool``
        '''

        server_info = self._server_info()
        for sh in ('shc_member', 'shc_captain'):
            if sh in server_info['server_roles']:
                return True

        return False

    @retry(exceptions=[binding.HTTPError])
    def get_shc_members(self):
        '''Get SHC members.

        :returns: List of SHC members [(label, peer_scheme_host_port) ...]
        :rtype: ``list``

        :raises ServerInfoException: If this server has no SHC members.
        '''

        try:
            content = self._rest_client.get(self.SHC_MEMBER_ENDPOINT,
                                            output_mode='json').body.read()
        except binding.HTTPError as e:
            if e.status != 404 and e.status != 503:
                raise

            raise ServerInfoException(
                'This server is not a SHC member and has no SHC members.')

        members = []
        for member in json.loads(content)['entry']:
            content = member['content']
            members.append((content['label'],
                            content['peer_scheme_host_port']))

        return members

    @retry(exceptions=[binding.HTTPError])
    def is_captain_ready(self):
        '''Check if captain is ready.

        Client usually first polls this function until captain is ready
        and then call is_captain to detect current captain machine

        :returns: True/False
        :rtype: ``bool``

        Usage::

            >>> serverinfo = solnlib.server_info.ServerInfo(session_key)
            >>> while 1:
            >>>    if serverinfo.is_captain_ready():
            >>>        break
            >>>    time.sleep(2)
            >>>
            >>> # If do_stuff can only be executed in SH captain
            >>> if serverinfo.is_captain():
            >>>    do_stuff()
        '''

        cap_info = self.captain_info()
        return utils.is_true(cap_info["service_ready_flag"]) and \
            utils.is_false(cap_info["maintenance_mode"])

    @retry(exceptions=[binding.HTTPError])
    def captain_info(self):
        '''Check if captain is ready.

        :returns: captain info, like {
            "elected_captain": 1463195590,
            "id": "9CA04BAD-0C24-4703-8A88-E20345833508",
            "initialized_flag": true,
            "label": "my-shc04-sh",
            "maintenance_mode": false,
            "mgmt_uri": "https://my-shc04-sh:8089",
            "min_peers_joined_flag": true,
            "peer_scheme_host_port": "https://my-shc04-sh2:8089",
            "rolling_restart_flag": false,
            "service_ready_flag": true}
        :rtype: ``dict``

        :raises ServerInfoException: If there is SHC is not enabled.
        '''

        try:
            content = self._rest_client.get(self.SHC_CAPTAIN_INFO_ENDPOINT,
                                            output_mode='json').body.read()
        except binding.HTTPError as e:
            if e.status == 503 and "not available" in e.message:
                raise ServerInfoException(e.message)
            raise

        return json.loads(content)["entry"][0]["content"]
