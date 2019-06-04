"""
Converters for Splunk configuration.
"""

from __future__ import absolute_import

import base64
import json

__all__ = [
    'Converter',
    'Normaliser',
    'ChainOf',
    'UserDefined',
    'Unifier',
    'Boolean',
    'Lower',
    'Upper',
    'Mapping',
    'Base64',
    'JSON',
]


class Converter(object):
    """
    Converting data: encode for in-coming request
        and decode for out-coming response.
    """
    def encode(self, value, request):
        """
        Encode data from client for request.

        :param value: value to encode for request
        :param request: whole request data
        :return:
        """
        raise NotImplementedError()

    def decode(self, value, response):
        """
        Decode data from storage for response.

        :param value: value to decode for response
        :param response: whole response data
        :return:
        """
        raise NotImplementedError()


class Normaliser(Converter):
    """
    Normalizing data: same converting logic for encode & decode.
    """

    def normalize(self, value, data):
        """
        Normalize a given value.

        :param value: value to normalize
        :param data: whole payload
        :returns: normalized value.
        """
        raise NotImplementedError()

    def encode(self, value, request):
        return self.normalize(value, request)

    def decode(self, value, response):
        return self.normalize(value, response)


class ChainOf(Converter):
    """
    A composite of converters that will covert data with specified
    converters on by one, and returns result from the last converter.
    """

    def __init__(self, *converters):
        """

        :param converters: a list of converters
        """
        super(ChainOf, self).__init__()
        self._converters = converters

    def encode(self, value, request):
        for converter in self._converters:
            value = converter.encode(value, request)
        return value

    def decode(self, value, response):
        import copy
        converters = copy.copy(self._converters)
        converters.reverse()
        for converter in converters:
            value = converter.decode(value, response)
        return value


class UserDefined(Converter):
    """
    User-defined normaliser.

    The user-defined normaliser function should be in form:
    ``def fun(value, *args, **kwargs): ...``

    Usage::
    >>> def my_encoder(value, request, args):
    >>>     if request == args:
    >>>         return value
    >>>     else:
    >>>         return value
    >>> my_converter = UserDefined(my_encoder, 'test_val')
    >>> my_converter.encode('value', {'key': 'value'}, 'value1')

    """

    def __init__(self, encoder, decoder=None, *args, **kwargs):
        """

        :param encoder: user-defined function for encoding
        :param decoder: user-defined function for decoding.
            If None, it is the same to encoder.
        :param args:
        :param kwargs:
        """
        super(UserDefined, self).__init__()
        self._encoder = encoder
        self._decoder = decoder or self._encoder
        self._args = args
        self._kwargs = kwargs

    def encode(self, value, request):
        return self._encoder(
            value,
            request,
            *self._args,
            **self._kwargs
        )

    def decode(self, value, response):
        return self._decoder(
            value,
            response,
            *self._args,
            **self._kwargs
        )


class Lower(Normaliser):
    """
    Normalize a string to all lower cases.
    """

    def normalize(self, value, data):
        return value.strip().lower()


class Upper(Normaliser):
    """
    Normalize a string to all upper cases.
    """
    def normalize(self, value, data):
        return value.strip().upper()


class Unifier(Normaliser):
    """
    Many-to-one map for normalizing request & response.
    """

    def __init__(
            self,
            value_map,
            default=None,
            case_sensitive=False,
    ):
        """

        :param value_map:
            {"<unified value>": "<original value list>"}
        :param default: default value for input not in specific list
        :param case_sensitive: if it is False,
            it will return lower case
        """
        super(Unifier, self).__init__()
        self._case_sensitive = case_sensitive
        self._default = default
        self._value_map = {}
        for val_new, val_old_list in value_map.iteritems():
            for val_old in val_old_list:
                val_old = val_old if case_sensitive else val_old.lower()
                assert val_old not in self._value_map, \
                    'Normaliser "Unifier" only supports Many-to-one mapping: %s' % val_old
                self._value_map[val_old] = val_new

    def normalize(self, value, data):
        need_lower = not self._case_sensitive and \
                     isinstance(value, basestring)
        val_old = value.lower() if need_lower else value
        val_default = self._default or value
        return self._value_map.get(val_old, val_default)


class Boolean(Unifier):
    """
    Normalize a boolean field.

    Normalize given value to boolean: 0 or 1
        (for False and True respectively).
    If the given value is not-a-string or unrecognizable,
    it returns default value.
    """

    VALUES_TRUE = {'true', 't', '1', 'yes', 'y'}
    VALUES_FALSE = {'false', 'f', '0', 'no', 'n'}

    def __init__(self, default=True):
        """

        :param default: default for unrecognizable input of boolean.
        """
        super(Boolean, self).__init__(
            value_map={
                '1': Boolean.VALUES_TRUE,
                '0': Boolean.VALUES_FALSE,
            },
            default='1' if default else '0',
            case_sensitive=False,
        )


class Mapping(Converter):
    """
    One-to-one map between interface value and storage value.
    If value is not in specific mapping,
    it will return the original value.
    """

    def __init__(self, value_map, case_sensitive=False):
        """

        :param value_map: {"<interface value>": "<storage value>"}
        :param case_sensitive: if it is False,
            it will return lower case
        """
        super(Mapping, self).__init__()
        self._case_sensitive = case_sensitive
        self._map_interface, self._map_storage = {}, {}
        for interface, storage in value_map.iteritems():
            self._check_and_set(interface, storage)

    def _check_and_set(self, interface, storage):
        if not self._case_sensitive:
            interface = interface.lower()
            storage = storage.lower()
        assert interface not in self._map_interface, \
            'Converter "Mapping" only supports one-to-one mapping: "%s"' % interface
        assert storage not in self._map_storage, \
            'Converter "Mapping" only supports one-to-one mapping: "%s"' % storage
        self._map_interface[interface] = storage
        self._map_storage[storage] = interface

    def encode(self, value, request):
        if self._case_sensitive:
            interface = value
        else:
            interface = value.lower()
        return self._map_interface.get(interface, value)

    def decode(self, value, response):
        if self._case_sensitive:
            storage = value
        else:
            storage = value.lower()
        return self._map_storage.get(storage, value)


class Base64(Converter):
    """
    Covert input data to base64 string.
    """

    def encode(self, value, request):
        return base64.b64encode(value)

    def decode(self, value, response):
        return base64.b64decode(value)


class JSON(Converter):
    """
    Converter between object and JSON string.
    """

    def encode(self, value, request):
        return json.dumps(value)

    def decode(self, value, response):
        return json.loads(value)
