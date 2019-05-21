"""
Global Config Module
"""

from __future__ import absolute_import

from urlparse import urlparse
from solnlib.splunk_rest_client import SplunkRestClient

from .configuration import (
    Inputs,
    Configs,
    Settings,
    GlobalConfigError,
    Configuration
)
from .schema import GlobalConfigSchema


__all__ = [
    'GlobalConfigError',
    'GlobalConfigSchema',
    'GlobalConfig',
    'Inputs',
    'Configs',
    'Settings',
]


class GlobalConfig(object):

    def __init__(self, splunkd_uri, session_key, schema):
        """
        Global Config.

        :param splunkd_uri:
        :param session_key:
        :param schema:
        :type schema: GlobalConfigSchema
        """
        self._splunkd_uri = splunkd_uri
        self._session_key = session_key
        self._schema = schema

        splunkd_info = urlparse(self._splunkd_uri)
        self._client = SplunkRestClient(
            self._session_key,
            self._schema.product,
            scheme=splunkd_info.scheme,
            host=splunkd_info.hostname,
            port=splunkd_info.port,
        )
        self._configuration = Configuration(self._client, self._schema)
        self._inputs = Inputs(self._client, self._schema)
        self._configs = Configs(self._client, self._schema)
        self._settings = Settings(self._client, self._schema)

    @property
    def inputs(self):
        return self._inputs

    @property
    def configs(self):
        return self._configs

    @property
    def settings(self):
        return self._settings

    # add support for batch save of configuration payload
    def save(self, payload):
        return self._configuration.save(payload)
