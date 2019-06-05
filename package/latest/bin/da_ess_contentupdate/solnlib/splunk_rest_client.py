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
This module proxy all REST call to splunklib SDK, it handles proxy, certs etc
in this centralized location. All clients should use SplunkRestProxy to do REST
call instead of calling splunklib SDK directly in business logic code.
'''

import logging
import os
import traceback
import urllib2
from cStringIO import StringIO

from .net_utils import check_css_params
from .net_utils import is_valid_hostname
from .net_utils import is_valid_port
from .net_utils import is_valid_scheme
from .packages.splunklib import binding
from .packages.splunklib import client
from .splunkenv import get_splunkd_access_info

__all__ = ['SplunkRestClient']


def _get_proxy_info(context):
    if not context.get('proxy_hostname') or not context.get('proxy_port'):
        return None

    user_pass = ''
    if context.get('proxy_username') and context.get('proxy_password'):
        username = urllib2.quote(context['proxy_username'], safe='')
        password = urllib2.quote(context['proxy_password'], safe='')
        user_pass = '{user}:{password}@'.format(
            user=username, password=password)

    proxy = 'http://{user_pass}{host}:{port}'.format(
        user_pass=user_pass, host=context['proxy_hostname'],
        port=context['proxy_port'])
    proxies = {
        'http': proxy,
        'https': proxy,
    }
    return proxies


def _request_handler(context):
    '''
    :param context: Http connection context can contain the following
        key/values: {
        'proxy_hostname': string,
        'proxy_port': int,
        'proxy_username': string,
        'proxy_password': string,
        'key_file': string,
        'cert_file': string
        'pool_connections', int,
        'pool_maxsize', int,
        }
    :type content: dict
    '''

    try:
        from .packages import requests
    except ImportError:
        # FIXME proxy ?
        return binding.handler(
            key_file=context.get('key_file'),
            cert_file=context.get('cert_file'))

    try:
        requests.packages.urllib3.disable_warnings()
    except AttributeError:
        pass

    proxies = _get_proxy_info(context)
    verify = context.get('verify', False)

    if context.get('key_file') and context.get('cert_file'):
        # cert = ('/path/client.cert', '/path/client.key')
        cert = context['key_file'], context['cert_file']
    elif context.get('cert_file'):
        cert = context['cert_file']
    else:
        cert = None

    if context.get('pool_connections', 0):
        logging.info('Use HTTP connection pooling')
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=context.get('pool_connections', 10),
            pool_maxsize=context.get('pool_maxsize', 10))
        session.mount('https://', adapter)
        req_func = session.request
    else:
        req_func = requests.request

    def request(url, message, **kwargs):
        '''
        :param url: URL
        :type url: string
        :param message: Can contain following key/values: {
            'method': 'GET' or 'DELETE', or 'PUT' or 'POST'
            'headers': [[key, value], [key, value], ...],
            'body': string
            }
        :type message: dict
        '''

        body = message.get('body')
        headers = {
            'User-Agent': 'curl',
            'Accept': '*/*',
            'Connection': 'Keep-Alive',
        }

        if body:
            headers['Content-Length'] = str(len(body))

        for key, value in message['headers']:
            headers[key] = value

        method = message.get('method', 'GET')

        try:
            resp = req_func(
                method, url, data=body, headers=headers, stream=False,
                verify=verify, proxies=proxies, cert=cert, **kwargs)
        except Exception as e:
            logging.error(
                'Failed to issue http request=%s to url=%s, error=%s',
                method, url, traceback.format_exc(e))
            raise

        return {
            'status': resp.status_code,
            'reason': resp.reason,
            'headers': dict(resp.headers),
            'body': StringIO(resp.content),
        }

    return request


class SplunkRestClient(client.Service):
    '''Splunk rest client

    If any of scheme, host and port is None, will discover local
    splunkd access info automatically.

    :param session_key: Splunk access token.
    :type session_key: ``string``
    :param app: App name of namespace.
    :type app: ``string``
    :param owner: (optional) Owner of namespace, default is `nobody`.
    :type owner: ``string``
    :param scheme: (optional) The access scheme, default is None.
    :type scheme: ``string``
    :param host: (optional) The host name, default is None.
    :type host: ``string``
    :param port: (optional) The port number, default is None.
    :type port: ``integer``
    :param context: Other configurations, it can contains `proxy_hostname`,
        `proxy_port`, `proxy_username`, `proxy_password`, then proxy will
        be accounted and setup, all REST APIs to Splunkd will be through
        the proxy. If `context` contains `key_file`, `cert_file`, then
        certification will be accounted and setup, all REST APIs to Splunkd
        will use certification. If `context` contains `pool_connections`,
        `pool_maxsize`, then HTTP Connection will be pooled
    :type context: ``dict``
    '''

    @check_css_params(scheme=is_valid_scheme, host=is_valid_hostname,
                      port=is_valid_port)
    def __init__(self, session_key, app, owner='nobody',
                 scheme=None, host=None, port=None, **context):
        # Only do splunkd URI discovery in SPLUNK env (SPLUNK_HOME is set)
        if not all([scheme, host, port]) and os.environ.get('SPLUNK_HOME'):
            scheme, host, port = get_splunkd_access_info()

        handler = _request_handler(context)
        super(SplunkRestClient, self).__init__(
            handler=handler,
            scheme=scheme,
            host=host,
            port=port,
            token=session_key,
            app=app,
            owner=owner,
            autologin=True)
