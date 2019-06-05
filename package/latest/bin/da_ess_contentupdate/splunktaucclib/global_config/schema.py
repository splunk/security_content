
from __future__ import absolute_import

import traceback

from ..rest_handler.schema import RestSchema, RestSchemaError


class GlobalConfigSchema(RestSchema):

    def __init__(self, content, *args, **kwargs):
        """

        :param content: Python object for Global Config Schema
        :param args:
        :param kwargs:
        """
        super(GlobalConfigSchema, self).__init__(*args, **kwargs)
        self._content = content
        self._inputs = []
        self._configs = []
        self._settings = []

        try:
            self._parse()
        except Exception:
            raise RestSchemaError(
                'Invalid Global Config Schema: %s' % traceback.format_exc(),
            )

    @property
    def product(self):
        return self._meta['name']

    @property
    def namespace(self):
        return self._meta['restRoot']

    @property
    def admin_match(self):
        return ''

    @property
    def version(self):
        return self._meta['apiVersion']

    @property
    def inputs(self):
        return self._inputs

    @property
    def configs(self):
        return self._configs

    @property
    def settings(self):
        return self._settings

    def _parse(self):
        self._meta = self._content['meta']
        pages = self._content['pages']
        self._parse_configuration(pages.get('configuration'))
        self._parse_inputs(pages.get('inputs'))

    def _parse_configuration(self, configurations):
        if not configurations or 'tabs' not in configurations:
            return
        for configuration in configurations['tabs']:
            if 'table' in configuration:
                self._configs.append(configuration)
            else:
                self._settings.append(configuration)

    def _parse_inputs(self, inputs):
        if not inputs or 'services' not in inputs:
            return
        self._inputs = inputs['services']
