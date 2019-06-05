# coding: utf-8
from ..roles import DEFAULT_ROLE
from ..resolutionscope import EMPTY_SCOPE
from .._compat import OrderedDict
from .base import BaseSchemaField
from .util import validate, validate_regex


__all__ = [
    'StringField', 'BooleanField', 'EmailField', 'IPv4Field', 'DateTimeField',
    'UriField', 'NumberField', 'IntField', 'NullField'
]


class BooleanField(BaseSchemaField):
    """A boolean field."""

    def _get_definitions_and_schema(self, role=DEFAULT_ROLE, res_scope=EMPTY_SCOPE,
                                    ordered=False, ref_documents=None):
        id, res_scope = res_scope.alter(self.id)
        schema = (OrderedDict if ordered else dict)(type='boolean')
        schema = self._update_schema_with_common_fields(schema, id=id, role=role)
        return {}, schema


class StringField(BaseSchemaField):
    """A string field.

    :param pattern:
        A regular expression (ECMA 262) that a string value must match.
    :type pattern: string or :class:`.Resolvable`
    :param format:
        A semantic format of the string (for example, ``"date-time"``,
        ``"email"``, or ``"uri"``).
    :type format: string or :class:`.Resolvable`
    :param min_length:
        A minimum length.
    :type min_length: int or :class:`.Resolvable`
    :param max_length:
        A maximum length.
    :type max_length: int or :class:`.Resolvable`
    """
    _FORMAT = None

    def __init__(self, pattern=None, format=None, min_length=None, max_length=None, **kwargs):
        if pattern is not None:
            validate(pattern, validate_regex)
        self.pattern = pattern  #:
        self.format = format or self._FORMAT  #:
        self.min_length = min_length  #:
        self.max_length = max_length  #:
        super(StringField, self).__init__(**kwargs)

    def _get_definitions_and_schema(self, role=DEFAULT_ROLE, res_scope=EMPTY_SCOPE,
                                    ordered=False, ref_documents=None):
        id, res_scope = res_scope.alter(self.id)
        schema = (OrderedDict if ordered else dict)(type='string')
        schema = self._update_schema_with_common_fields(schema, id=id, role=role)

        pattern = self.resolve_attr('pattern', role).value
        if pattern:
            schema['pattern'] = pattern
        min_length = self.resolve_attr('min_length', role).value
        if min_length is not None:
            schema['minLength'] = min_length
        max_length = self.resolve_attr('max_length', role).value
        if max_length is not None:
            schema['maxLength'] = max_length
        format = self.resolve_attr('format', role).value
        if format is not None:
            schema['format'] = format
        return {}, schema


class EmailField(StringField):
    """An email field."""
    _FORMAT = 'email'


class IPv4Field(StringField):
    """An IPv4 field."""
    _FORMAT = 'ipv4'


class DateTimeField(StringField):
    """An ISO 8601 formatted date-time field."""
    _FORMAT = 'date-time'


class UriField(StringField):
    """A URI field."""
    _FORMAT = 'uri'


class NumberField(BaseSchemaField):
    """A number field.

    :param multiple_of:
        A value must be a multiple of this factor.
    :type multiple_of: number or :class:`.Resolvable`
    :param minimum:
        A minimum allowed value.
    :type minimum: number or :class:`.Resolvable`
    :param exclusive_minimum:
        Whether a value is allowed to exactly equal the minimum.
    :type exclusive_minimum: bool or :class:`.Resolvable`
    :param maximum:
        A maximum allowed value.
    :type maximum: number or :class:`.Resolvable`
    :param exclusive_maximum:
        Whether a value is allowed to exactly equal the maximum.
    :type exclusive_maximum: bool or :class:`.Resolvable`
    """
    _NUMBER_TYPE = 'number'

    def __init__(self, multiple_of=None, minimum=None, maximum=None,
                 exclusive_minimum=None, exclusive_maximum=None, **kwargs):
        self.multiple_of = multiple_of  #:
        self.minimum = minimum  #:
        self.exclusive_minimum = exclusive_minimum  #:
        self.maximum = maximum  #:
        self.exclusive_maximum = exclusive_maximum  #:
        super(NumberField, self).__init__(**kwargs)

    def _get_definitions_and_schema(self, role=DEFAULT_ROLE, res_scope=EMPTY_SCOPE,
                                    ordered=False, ref_documents=None):
        id, res_scope = res_scope.alter(self.id)
        schema = (OrderedDict if ordered else dict)(type=self._NUMBER_TYPE)
        schema = self._update_schema_with_common_fields(schema, id=id, role=role)
        multiple_of = self.resolve_attr('multiple_of', role).value
        if multiple_of is not None:
            schema['multipleOf'] = multiple_of
        minimum = self.resolve_attr('minimum', role).value
        if minimum is not None:
            schema['minimum'] = minimum
        exclusive_minimum = self.resolve_attr('exclusive_minimum', role).value
        if exclusive_minimum is not None:
            schema['exclusiveMinimum'] = exclusive_minimum
        maximum = self.resolve_attr('maximum', role).value
        if maximum is not None:
            schema['maximum'] = maximum
        exclusive_maximum = self.resolve_attr('exclusive_maximum', role).value
        if exclusive_maximum is not None:
            schema['exclusiveMaximum'] = exclusive_maximum
        return {}, schema


class IntField(NumberField):
    """An integer field."""
    _NUMBER_TYPE = 'integer'


class NullField(BaseSchemaField):
    """A null field."""

    def _get_definitions_and_schema(self, role=DEFAULT_ROLE, res_scope=EMPTY_SCOPE,
                                    ordered=False, ref_documents=None):
        id, res_scope = res_scope.alter(self.id)
        schema = (OrderedDict if ordered else dict)(type='null')
        schema = self._update_schema_with_common_fields(schema, id=id, role=role)
        return {}, schema
