# coding: utf-8
from ..exceptions import processing, FieldStep
from ..resolutionscope import EMPTY_SCOPE
from ..roles import Resolvable, Resolution, DEFAULT_ROLE


__all__ = ['Null', 'BaseField', 'BaseSchemaField']


class NullSentinel(object):
    """A class which instance represents a null value.
    Allows specifying fields with a default value of null.
    """

    def __bool__(self):
        return False

    __nonzero__ = __bool__


Null = NullSentinel()
"""
A special value that can be used to set the default value
of a field to null.
"""


# make sure nobody creates another Null value
def _failing_new(*args, **kwargs):
    raise TypeError('Can\'t create another NullSentinel instance')


NullSentinel.__new__ = staticmethod(_failing_new)
del _failing_new


class BaseField(Resolvable):
    """A base class for fields of :class:`documents <.Document>`.
    Instances of this class may be added to a document to define its properties.

    Implements the :class:`.Resolvable` interface.

    :param required:
        Whether the field is required. Defaults to ``False``.
    :type required: bool or :class:`.Resolvable`
    :param str name:
        If specified, used as a key under which the field schema
        appears in :class:`document <.Document>` schema properties.

        .. versionadded:: 0.1.3
    """

    def __init__(self, name=None, required=False, **kwargs):
        #: Name
        self.name = name
        #: Whether the field is required.
        self.required = required
        self._kwargs = kwargs

    def resolve(self, role):
        """
        Implements the :class:`.Resolvable` interface.

        Always returns a ``Resolution(self, role)``.

        :rtype: :class:`.Resolution`
        """
        return Resolution(self, role)

    def iter_possible_values(self):
        """Implements the :class:`.Resolvable` interface.

        Yields a single value -- ``self``.
        """
        yield self

    def get_definitions_and_schema(self, role=DEFAULT_ROLE, res_scope=EMPTY_SCOPE,
                                   ordered=False, ref_documents=None):  # pragma: no cover
        """Returns a tuple of two elements.

        The second element is a JSON schema of the data described by this field,
        and the first is a dictionary that contains definitions that are referenced
        from the schema.

        :param str role: A role.
        :param bool ordered:
            If ``True``, the resulting schema dictionary is ordered. Fields are
            listed in the order they are added to the class. Schema properties are
            also ordered in a sensible and consistent way, making the schema more
            human-readable.
        :param res_scope:
            The current resolution scope.
        :type res_scope: :class:`~.ResolutionScope`
        :param set ref_documents:
            If subclass of :class:`Document` is in this set, all :class:`DocumentField` s
            pointing to it will be resolved to a reference: ``{"$ref": "#/definitions/..."}``.
            Note: resulting definitions will not contain schema for this document.
        :raises: :class:`.SchemaGenerationException`
        :rtype: (dict, dict or OrderedDict)
        """
        with processing(FieldStep(self, role=role)):
            definitions, schema = self._get_definitions_and_schema(
                role=role, res_scope=res_scope, ordered=ordered, ref_documents=ref_documents)
        return definitions, self._extend_schema(schema, role=role, res_scope=res_scope,
                                                ordered=ordered, ref_documents=ref_documents)

    def _extend_schema(self, schema, role, res_scope, ordered, ref_documents):
        return schema

    def _get_definitions_and_schema(self, role=DEFAULT_ROLE, res_scope=EMPTY_SCOPE,
                                    ordered=False, ref_documents=None):  # pragma: no cover
        raise NotImplementedError

    def iter_fields(self):
        """Iterates over the nested fields of the document examining all
        possible values of the occuring :class:`resolvables <.Resolvable>`.
        """
        return iter([])

    def walk(self, through_document_fields=False, visited_documents=frozenset()):
        """Iterates recursively over the nested fields, examining all
        possible values of the occuring :class:`resolvables <.Resolvable>`.

        Visits fields in a DFS order.

        :param bool through_document_fields:
            If ``True``, walks through nested :class:`.DocumentField` fields.
        :param set visited_documents:
            Keeps track of visited :class:`documents <.Document>` to avoid infinite
            recursion when ``through_document_field`` is ``True``.
        :returns: iterable of :class:`.BaseField`
        """
        yield self
        for field in self.iter_fields():
            for field_ in field.walk(through_document_fields=through_document_fields,
                                     visited_documents=visited_documents):
                yield field_

    def resolve_and_iter_fields(self, role=DEFAULT_ROLE):
        """The same as :meth:`.iter_fields`, but :class:`resolvables <.Resolvable>`
        are resolved using ``role``.
        """
        return iter([])

    def resolve_and_walk(self, role=DEFAULT_ROLE, through_document_fields=False,
                         visited_documents=frozenset()):
        """The same as :meth:`.walk`, but :class:`resolvables <.Resolvable>` are
        resolved using ``role``.
        """
        yield self
        for field in self.resolve_and_iter_fields(role=role):
            field, field_role = field.resolve(role)
            for field_ in field.resolve_and_walk(role=field_role,
                                                 through_document_fields=through_document_fields,
                                                 visited_documents=visited_documents):
                yield field_

    def get_schema(self, ordered=False, role=DEFAULT_ROLE):
        """Returns a JSON schema (draft v4) of the field.

        :param str role:  A role.
        :param bool ordered:
            If ``True``, the resulting schema dictionary is ordered. Fields are
            listed in the order they are added to the class. Schema properties are
            also ordered in a sensible and consistent way, making the schema more
            human-readable.
        :raises: :class:`.SchemaGenerationException`
        :rtype: dict or OrderedDict
        """
        definitions, schema = self.get_definitions_and_schema(ordered=ordered, role=role)
        if definitions:
            schema['definitions'] = definitions
        return schema

    def resolve_attr(self, attr, role=DEFAULT_ROLE):
        """
        Resolves an attribure with the name ``field`` using ``role``.

        If the value of ``attr`` is :class:`resolvable <.Resolvable>`,
        it resolves it using a given ``role`` and returns the result.
        Otherwise it returns the raw value and ``role`` unchanged.

        :raises: :class:`AttributeError`
        :rtype: :class:`.Resolution`
        """
        value = getattr(self, attr)
        if isinstance(value, Resolvable):
            return value.resolve(role)
        return Resolution(value, role)


class BaseSchemaField(BaseField):
    """A base class for fields that directly map to JSON Schema validator.

    :param required:
        If the field is required. Defaults to ``False``.
    :type required: bool or :class:`.Resolvable`
    :param str id:
        A string to be used as a value of the `"id" keyword`_ of the resulting schema.
    :param default:
        The default value for this field. May be :data:`.Null` (a special value
        to set the default value to null) or a callable.
    :type default: any JSON-representable object, a callable or a :class:`.Resolvable`
    :param enum:
        A list of valid choices. May be a callable.
    :type enum: list, tuple, set, callable or :class:`.Resolvable`
    :param title:
        A short explanation about the purpose of the data described by this field.
    :type title: str or :class:`.Resolvable`
    :param description:
        A detailed explanation about the purpose of the data described by this field.
    :type description: str or :class:`.Resolvable`

    .. _"id" keyword: https://tools.ietf.org/html/draft-zyp-json-schema-04#section-7.2
    """

    def __init__(self, id='', default=None, enum=None, title=None, description=None, **kwargs):
        #: A string to be used as a value of the `"id" keyword`_ of the resulting schema.
        self.id = id
        #: A short explanation about the purpose of the data.
        self.title = title
        #: A detailed explanation about the purpose of the data.
        self.description = description
        self._enum = enum
        self._default = default
        super(BaseSchemaField, self).__init__(**kwargs)

    def get_enum(self, role=DEFAULT_ROLE):
        """Returns a list to be used as a value of the ``"enum"`` schema keyword."""
        enum = self.resolve_attr('_enum', role).value
        if callable(enum):
            enum = enum()
        return enum

    def get_default(self, role=DEFAULT_ROLE):
        """Returns a value of the ``"default"`` schema keyword."""
        default = self.resolve_attr('_default', role).value
        if callable(default):
            default = default()
        return default

    def _get_definitions_and_schema(self, role=DEFAULT_ROLE, res_scope=EMPTY_SCOPE,
                                    ordered=False, ref_documents=None):  # pragma: no cover
        raise NotImplementedError

    def _update_schema_with_common_fields(self, schema, id='', role=DEFAULT_ROLE):
        if id:
            schema['id'] = id
        title = self.resolve_attr('title', role).value
        if title is not None:
            schema['title'] = title
        description = self.resolve_attr('description', role).value
        if description is not None:
            schema['description'] = description
        enum = self.get_enum(role=role)
        if enum:
            schema['enum'] = list(enum)
        default = self.get_default(role=role)
        if default is not None:
            if default is Null:
                default = None
            schema['default'] = default
        return schema
