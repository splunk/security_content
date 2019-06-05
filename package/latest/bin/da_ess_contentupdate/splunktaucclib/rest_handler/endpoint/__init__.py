from __future__ import absolute_import

from ..util import get_base_app_name
from ..error import RestError


__all__ = [
    'RestModel',
    'RestEndpoint',
    'SingleModel',
    'MultipleModel',
    'DataInputModel',
]


class RestModel(object):

    def __init__(self, fields, name=None):
        """
        REST Model.
        :param name:
        :param fields:
        """
        self.name = name
        self.fields = fields


class RestEndpoint(object):
    """
    REST Endpoint.
    """

    def __init__(
            self,
            user='nobody',
            app=None,
            *args,
            **kwargs
    ):
        """

        :param user:
        :param app: if None, it will be base app name
        :param args:
        :param kwargs:
        """
        self.user = user
        self.app = app or get_base_app_name()
        self.args = args
        self.kwargs = kwargs

        # If reload is needed while GET request
        self.need_reload = False

    @property
    def internal_endpoint(self):
        """
        Endpoint of Splunk internal service.

        :return:
        """
        raise NotImplementedError()

    def model(self, name, data):
        """
        Real model for given name & data.

        :param name:
        :param data:
        :return:
        """
        raise NotImplementedError()

    def _loop_fields(self, meth, name, data, *args, **kwargs):
        model = self.model(name, data)
        return map(
            lambda f: getattr(f, meth)(data, *args, **kwargs),
            model.fields,
        )

    def validate(self, name, data, existing=None):
        self._loop_fields('validate', name, data, existing=existing)

    def encode(self, name, data):
        self._loop_fields('encode', name, data)

    def decode(self, name, data):
        self._loop_fields('decode', name, data)


class SingleModel(RestEndpoint):
    """
    REST Model with Single Mode. It will store stanzas
    with same format  into one conf file.
    """

    def __init__(
            self,
            conf_name,
            model,
            user='nobody',
            app=None,
            *args,
            **kwargs
    ):
        """

        :param conf_name: conf file name
        :param model: REST model
        :type model: RestModel
        :param args:
        :param kwargs:
        """
        super(SingleModel, self).__init__(
            user=user, app=app, *args, **kwargs)
        self.need_reload = True

        self._model = model
        self.conf_name = conf_name

    @property
    def internal_endpoint(self):
        return 'configs/conf-{}'.format(self.conf_name)

    def model(self, name, data):
        return self._model


class MultipleModel(RestEndpoint):
    """
    REST Model with Multiple Modes. It will store
     stanzas with different formats into one conf file.
    """

    def __init__(
            self,
            conf_name,
            models,
            user='nobody',
            app=None,
            *args,
            **kwargs
    ):
        """

        :param conf_name:
        :type conf_name: basestring
        :param models: list of RestModel
        :type models: list
        :param args:
        :param kwargs:
        """
        super(MultipleModel, self).__init__(
            user=user, app=app, *args, **kwargs)
        self.need_reload = True

        self.conf_name = conf_name
        self.models = {model.name: model for model in models}

    @property
    def internal_endpoint(self):
        return 'configs/conf-{}'.format(self.conf_name)

    def model(self, name, data):
        try:
            return self.models[name]
        except KeyError:
            raise RestError(404, 'name=%s' % name)


class DataInputModel(RestEndpoint):
    """
    REST Model for Data Input.
    """

    def __init__(
            self,
            input_type,
            model,
            user='nobody',
            app=None,
            *args,
            **kwargs
    ):
        super(DataInputModel, self).__init__(
            user=user, app=app, *args, **kwargs)

        self.input_type = input_type
        self._model = model

    @property
    def internal_endpoint(self):
        return 'data/inputs/{}'.format(self.input_type)

    def model(self, name, data):
        return self._model
