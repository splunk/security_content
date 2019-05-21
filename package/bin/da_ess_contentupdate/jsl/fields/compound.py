# coding: utf-8
import itertools

from .. import registry
from ..roles import DEFAULT_ROLE, Resolvable
from ..resolutionscope import EMPTY_SCOPE
from ..exceptions import SchemaGenerationException, processing, AttributeStep, ItemStep
from .._compat import iteritems, iterkeys, itervalues, string_types, OrderedDict
from .base import BaseSchemaField, BaseField
from .util import validate_regex


__all__ = [
    'ArrayField', 'DictField', 'OneOfField', 'AnyOfField', 'AllOfField',
    'NotField', 'DocumentField', 'RefField', 'RECURSIVE_REFERENCE_CONSTANT'
]

RECURSIVE_REFERENCE_CONSTANT = 'self'


class ArrayField(BaseSchemaField):
    """An array field.

    :param items:
        Either of the following:

        * :class:`BaseField` -- all items of the array must match the field schema;
        * a list or a tuple of :class:`fields <.BaseField>` -- all items of the array must be
          valid according to the field schema at the corresponding index (tuple typing);
        * a :class:`.Resolvable` resolving to either of the first two options.

    :param min_items:
        A minimum length of an array.
    :type min_items: int or :class:`.Resolvable`
    :param max_items:
        A maximum length of an array.
    :type max_items: int or :class:`.Resolvable`
    :param unique_items:
        Whether all the values in the array must be distinct.
    :type unique_items: bool or :class:`.Resolvable`
    :param additional_items:
        If the value of ``items`` is a list or a tuple, and the array length is larger than
        the number of fields in ``items``, then the additional items are described
        by the :class:`.BaseField` passed using this argument.
    :type additional_items: bool or :class:`.BaseField` or :class:`.Resolvable`
    """

    def __init__(self, items=None, additional_items=None,
                 min_items=None, max_items=None, unique_items=None, **kwargs):
        self.items = items  #:
        self.min_items = min_items  #:
        self.max_items = max_items  #:
        self.unique_items = unique_items  #:
        self.additional_items = additional_items  #:
        super(ArrayField, self).__init__(**kwargs)

    def _get_definitions_and_schema(self, role=DEFAULT_ROLE, res_scope=EMPTY_SCOPE,
                                    ordered=False, ref_documents=None):
        id, res_scope = res_scope.alter(self.id)
        schema = (OrderedDict if ordered else dict)(type='array')
        schema = self._update_schema_with_common_fields(schema, id=id, role=role)
        nested_definitions = {}

        items, items_role = self.resolve_attr('items', role)
        if items is not None:
            with processing(AttributeStep('items', role=role)):
                if isinstance(items, (list, tuple)):
                    items_schema = []
                    for i, item in enumerate(items):
                        with processing(ItemStep(i, role=items_role)):
                            if not isinstance(item, Resolvable):
                                raise SchemaGenerationException(u'{0} is not resolvable'.format(item))
                            item, item_role = item.resolve(items_role)
                            if item is None:
                                continue
                            item_definitions, item_schema = item.get_definitions_and_schema(
                                role=item_role, res_scope=res_scope,
                                ordered=ordered, ref_documents=ref_documents)
                            nested_definitions.update(item_definitions)
                            items_schema.append(item_schema)
                    if not items_schema:
                        raise SchemaGenerationException(u'Items tuple is empty')
                elif isinstance(items, BaseField):
                    items_definitions, items_schema = items.get_definitions_and_schema(
                        role=items_role, res_scope=res_scope, ordered=ordered,
                        ref_documents=ref_documents)
                    nested_definitions.update(items_definitions)
                else:
                    raise SchemaGenerationException(
                        u'{0} is not a BaseField, a list or a tuple'.format(items))
                schema['items'] = items_schema

        additional_items, additional_items_role = self.resolve_attr('additional_items', role)
        if additional_items is not None:
            with processing(AttributeStep('additional_items', role=role)):
                if isinstance(additional_items, bool):
                    schema['additionalItems'] = additional_items
                elif isinstance(additional_items, BaseField):
                    items_definitions, items_schema = additional_items.get_definitions_and_schema(
                        role=additional_items_role, res_scope=res_scope,
                        ordered=ordered, ref_documents=ref_documents)
                    schema['additionalItems'] = items_schema
                    nested_definitions.update(items_definitions)
                else:
                    raise SchemaGenerationException(
                        u'{0} is not a BaseField or a boolean'.format(additional_items))

        min_items = self.resolve_attr('min_items', role).value
        if min_items is not None:
            schema['minItems'] = min_items
        max_items = self.resolve_attr('max_items', role).value
        if max_items is not None:
            schema['maxItems'] = max_items
        unique_items = self.resolve_attr('unique_items', role).value
        if unique_items is not None:
            schema['uniqueItems'] = unique_items
        return nested_definitions, schema

    def iter_fields(self):
        rv = []
        if isinstance(self.items, (list, tuple)):
            for item in self.items:
                if isinstance(item, Resolvable):
                    rv.append(item.iter_possible_values())
        elif isinstance(self.items, Resolvable):
            for items_value in self.items.iter_possible_values():
                if isinstance(items_value, (list, tuple)):
                    for item in items_value:
                        if isinstance(item, Resolvable):
                            rv.append(item.iter_possible_values())
                else:
                    if isinstance(items_value, Resolvable):
                        rv.append(items_value.iter_possible_values())
        if isinstance(self.additional_items, Resolvable):
            rv.append(self.additional_items.iter_possible_values())
        return itertools.chain.from_iterable(rv)

    def resolve_and_iter_fields(self, role=DEFAULT_ROLE):
        items, items_role = self.resolve_attr('items', role)
        if isinstance(items, (list, tuple)):
            for item in items:
                if isinstance(item, Resolvable):
                    item_value = item.resolve(items_role).value
                    if isinstance(item_value, BaseField):
                        yield item_value
        elif isinstance(items, Resolvable):
            yield items
        additional_items = self.resolve_attr('additional_items', role).value
        if isinstance(additional_items, BaseField):
            yield additional_items


class DictField(BaseSchemaField):
    """A dictionary field.

    :param properties:
        A dictionary containing fields.
    :type properties: dict[str -> :class:`.BaseField` or :class:`.Resolvable`]
    :param pattern_properties:
        A dictionary whose keys are regular expressions (ECMA 262).
        Properties match against these regular expressions, and for any that match,
        the property is described by the corresponding field schema.
    :type pattern_properties: dict[str -> :class:`.BaseField` or :class:`.Resolvable`]
    :param additional_properties:
        Describes properties that are not described by the ``properties`` or ``pattern_properties``.
    :type additional_properties: bool or :class:`.BaseField` or :class:`.Resolvable`
    :param min_properties:
        A minimum number of properties.
    :type min_properties: int or :class:`.Resolvable`
    :param max_properties:
        A maximum number of properties
    :type max_properties: int or :class:`.Resolvable`
    """

    def __init__(self, properties=None, pattern_properties=None, additional_properties=None,
                 min_properties=None, max_properties=None, **kwargs):
        self.properties = properties  #:
        self.pattern_properties = pattern_properties  #:
        self.additional_properties = additional_properties  #:
        self.min_properties = min_properties  #:
        self.max_properties = max_properties  #:
        super(DictField, self).__init__(**kwargs)

    def _process_properties(self, attr, properties, res_scope, ordered=False,
                            ref_documents=None, role=DEFAULT_ROLE):
        if attr == 'properties':
            key_getter = self._get_property_key
        elif attr == 'pattern_properties':
            key_getter = self._get_pattern_property_key
        else:
            raise ValueError('attr must be either "properties" or "pattern_properties"')  # pragma: no cover
        nested_definitions = {}
        schema = OrderedDict() if ordered else {}
        required = []
        for prop, field in iteritems(properties):
            with processing(ItemStep(prop, role=role)):
                if not isinstance(field, Resolvable):
                    raise SchemaGenerationException(u'{0} is not resolvable'.format(field))
                field, field_role = field.resolve(role)
                if field is None:
                    continue
                field_definitions, field_schema = field.get_definitions_and_schema(
                    role=field_role, res_scope=res_scope,
                    ordered=ordered, ref_documents=ref_documents)
                key = key_getter(prop, field)
                if field.resolve_attr('required', field_role).value:
                    required.append(key)
                schema[key] = field_schema
                nested_definitions.update(field_definitions)
        return nested_definitions, required, schema

    def _get_property_key(self, prop, field):
        return prop

    def _get_pattern_property_key(self, prop, field):
        return prop

    def _update_schema_with_processed_properties(self, schema, nested_definitions,
                                                 role=DEFAULT_ROLE, res_scope=EMPTY_SCOPE,
                                                 ordered=False, ref_documents=None):
        with processing(AttributeStep('properties', role=role)):
            properties, properties_role = self.resolve_attr('properties', role)
            if properties is not None:
                if not isinstance(properties, dict):
                    raise SchemaGenerationException(u'{0} is not a dict'.format(properties))
                properties_definitions, properties_required, properties_schema = \
                    self._process_properties('properties', properties, res_scope,
                                             ordered=ordered, ref_documents=ref_documents,
                                             role=properties_role)
                schema['properties'] = properties_schema
                if properties_required:
                    schema['required'] = properties_required
                nested_definitions.update(properties_definitions)

    def _update_schema_with_processed_pattern_properties(self, schema, nested_definitions,
                                                         role=DEFAULT_ROLE, res_scope=EMPTY_SCOPE,
                                                         ordered=False, ref_documents=None):
        with processing(AttributeStep('pattern_properties', role=role)):
            pattern_properties, pattern_properties_role = \
                self.resolve_attr('pattern_properties', role)
            if pattern_properties is not None:
                if not isinstance(pattern_properties, dict):
                    raise SchemaGenerationException(u'{0} is not a dict'.format(pattern_properties))
                for key in iterkeys(pattern_properties):
                    try:
                        validate_regex(key)
                    except ValueError as e:
                        raise SchemaGenerationException(u'Invalid regexp: {0}'.format(e))
                properties_definitions, _, properties_schema = self._process_properties(
                    'pattern_properties', pattern_properties, res_scope,
                    ordered=ordered, ref_documents=ref_documents,
                    role=pattern_properties_role)
                schema['patternProperties'] = properties_schema
                nested_definitions.update(properties_definitions)

    def _update_schema_with_processed_additional_properties(self, schema, nested_definitions,
                                                            role=DEFAULT_ROLE, res_scope=EMPTY_SCOPE,
                                                            ordered=False, ref_documents=None):
        with processing(AttributeStep('additional_properties', role=role)):
            additional_properties, additional_properties_role = \
                self.resolve_attr('additional_properties', role)
            if additional_properties is not None:
                if isinstance(additional_properties, bool):
                    schema['additionalProperties'] = additional_properties
                elif isinstance(additional_properties, BaseField):
                    additional_properties_definitions, additional_properties_schema = \
                        additional_properties.get_definitions_and_schema(
                            role=additional_properties_role, res_scope=res_scope,
                            ordered=ordered, ref_documents=ref_documents)
                    schema['additionalProperties'] = additional_properties_schema
                    nested_definitions.update(additional_properties_definitions)
                else:
                    raise SchemaGenerationException(
                        u'{0} is not a BaseField or a boolean'.format(additional_properties))

    def _get_definitions_and_schema(self, role=DEFAULT_ROLE, res_scope=EMPTY_SCOPE,
                                    ordered=False, ref_documents=None):
        id, res_scope = res_scope.alter(self.id)
        schema = (OrderedDict if ordered else dict)(type='object')
        schema = self._update_schema_with_common_fields(schema, id=id, role=role)
        nested_definitions = {}

        for f in (
                self._update_schema_with_processed_properties,
                self._update_schema_with_processed_pattern_properties,
                self._update_schema_with_processed_additional_properties,
        ):
            f(schema, nested_definitions, role=role, res_scope=res_scope,
              ordered=ordered, ref_documents=ref_documents)

        min_properties = self.resolve_attr('min_properties', role).value
        if min_properties is not None:
            schema['minProperties'] = min_properties
        max_properties = self.resolve_attr('max_properties', role).value
        if max_properties is not None:
            schema['maxProperties'] = max_properties

        return nested_definitions, schema

    def iter_fields(self):
        def _extract_resolvables(dict_or_resolvable):
            rv = []
            possible_dicts = []
            if isinstance(dict_or_resolvable, Resolvable):
                possible_dicts = dict_or_resolvable.iter_possible_values()
            elif isinstance(dict_or_resolvable, dict):
                possible_dicts = [dict_or_resolvable]
            for possible_dict in possible_dicts:
                rv.extend(v for v in itervalues(possible_dict) if v is not None)
            return rv

        resolvables = _extract_resolvables(self.properties)
        resolvables.extend(_extract_resolvables(self.pattern_properties))
        if isinstance(self.additional_properties, Resolvable):
            resolvables.append(self.additional_properties)
        return itertools.chain.from_iterable(r.iter_possible_values() for r in resolvables)

    def resolve_and_iter_fields(self, role=DEFAULT_ROLE):
        properties, properties_role = self.resolve_attr('properties', role)
        if properties is not None:
            for field in itervalues(properties):
                field = field.resolve(properties_role).value
                if isinstance(field, BaseField):
                    yield field
        pattern_properties, pattern_properties_role = \
            self.resolve_attr('pattern_properties', role)
        if pattern_properties is not None:
            for field in itervalues(pattern_properties):
                field = field.resolve(pattern_properties_role).value
                if isinstance(field, BaseField):
                    yield field
        additional_properties = self.resolve_attr('additional_properties', role).value
        if isinstance(additional_properties, BaseField):
            yield additional_properties


class BaseOfField(BaseSchemaField):
    _KEYWORD = None

    def __init__(self, fields, **kwargs):
        self.fields = fields  #:
        super(BaseOfField, self).__init__(**kwargs)

    def _get_definitions_and_schema(self, role=DEFAULT_ROLE, res_scope=EMPTY_SCOPE,
                                    ordered=False, ref_documents=None):
        id, res_scope = res_scope.alter(self.id)
        schema = OrderedDict() if ordered else {}
        schema = self._update_schema_with_common_fields(schema, id=id)
        nested_definitions = {}

        one_of = []
        with processing(AttributeStep('fields', role=role)):
            fields, fields_role = self.resolve_attr('fields', role)
            if not isinstance(fields, (list, tuple)):
                raise SchemaGenerationException(u'{0} is not a list or a tuple'.format(fields))
            for i, field in enumerate(fields):
                with processing(ItemStep(i, role=fields_role)):
                    if not isinstance(field, Resolvable):
                        raise SchemaGenerationException(u'{0} is not resolvable'.format(field))
                    field, field_role = field.resolve(fields_role)
                    if field is None:
                        continue
                    if not isinstance(field, BaseField):
                        raise SchemaGenerationException(u'{0} is not a BaseField.'.format(field))
                    field_definitions, field_schema = field.get_definitions_and_schema(
                        role=field_role, res_scope=res_scope,
                        ordered=ordered, ref_documents=ref_documents)
                    nested_definitions.update(field_definitions)
                    one_of.append(field_schema)
            if not one_of:
                raise SchemaGenerationException(u'Fields list is empty')
        schema[self._KEYWORD] = one_of
        return nested_definitions, schema

    def iter_fields(self):
        resolvables = []
        if isinstance(self.fields, (list, tuple)):
            resolvables.extend(self.fields)
        if isinstance(self.fields, Resolvable):
            for fields in self.fields.iter_possible_values():
                if isinstance(fields, (list, tuple)):
                    resolvables.extend(fields)
                elif isinstance(fields, Resolvable):
                    resolvables.append(fields)
        return itertools.chain.from_iterable(r.iter_possible_values() for r in resolvables)

    def resolve_and_iter_fields(self, role=DEFAULT_ROLE):
        fields, fields_role = self.resolve_attr('fields', role)
        for field in fields:
            field = field.resolve(fields_role).value
            if isinstance(field, BaseField):
                yield field


class OneOfField(BaseOfField):
    """
    :param fields: A list of fields, exactly one of which describes the data.
    :type fields: list[:class:`.BaseField` or :class:`.Resolvable`]

    .. attribute:: fields
        :annotation: = None
    """
    _KEYWORD = 'oneOf'


class AnyOfField(BaseOfField):
    """
    :param fields: A list of fields, at least one of which describes the data.
    :type fields: list[:class:`.BaseField` or :class:`.Resolvable`]

    .. attribute:: fields
        :annotation: = None
    """
    _KEYWORD = 'anyOf'


class AllOfField(BaseOfField):
    """
    :param fields: A list of fields, all of which describe the data.
    :type fields: list[:class:`.BaseField` or :class:`.Resolvable`]

    .. attribute:: fields
        :annotation: = None
    """
    _KEYWORD = 'allOf'


class NotField(BaseSchemaField):
    """
    :param field: A field to negate.
    :type field: :class:`.BaseField` or :class:`.Resolvable`
    """

    def __init__(self, field, **kwargs):
        self.field = field  #:
        super(NotField, self).__init__(**kwargs)

    def iter_fields(self):
        return self.field.iter_possible_values()

    def resolve_and_iter_fields(self, role=DEFAULT_ROLE):
        field, field_role = self.resolve_attr('field', role)
        if isinstance(field, BaseField):
            yield field

    def _get_definitions_and_schema(self, role=DEFAULT_ROLE, res_scope=EMPTY_SCOPE,
                                    ordered=False, ref_documents=None):
        id, res_scope = res_scope.alter(self.id)
        schema = OrderedDict() if ordered else {}
        schema = self._update_schema_with_common_fields(schema, id=id, role=role)
        with processing(AttributeStep('field', role=role)):
            field, field_role = self.resolve_attr('field', role)
            if not isinstance(field, BaseField):
                raise SchemaGenerationException(u'{0} is not a BaseField.'.format(field))
            field_definitions, field_schema = field.get_definitions_and_schema(
                role=field_role, res_scope=res_scope,
                ordered=ordered, ref_documents=ref_documents)
        schema['not'] = field_schema
        return field_definitions, schema


class DocumentField(BaseField):
    """A reference to a nested document.

    :param document_cls:
        A string (dot-separated path to document class, i.e. ``"app.resources.User"``),
        :data:`RECURSIVE_REFERENCE_CONSTANT` or a :class:`.Document` subclass.
    :param bool as_ref:
        If ``True``, the schema of :attr:`document_cls`` is placed into the definitions
        dictionary, and the field schema just references to it:
        ``{"$ref": "#/definitions/..."}``.
        It may make a resulting schema more readable.
    """

    def __init__(self, document_cls, as_ref=False, **kwargs):
        self._document_cls = document_cls
        #: A :class:`.Document` this field is attached to.
        self.owner_cls = None
        self.as_ref = as_ref  #:
        super(DocumentField, self).__init__(**kwargs)

    def iter_fields(self):
        return self.document_cls.iter_fields()

    def walk(self, through_document_fields=False, visited_documents=frozenset()):
        yield self
        if through_document_fields:
            document_cls = self.document_cls
            if document_cls not in visited_documents:
                visited_documents = visited_documents | set([document_cls])
                for field in document_cls.walk(
                        through_document_fields=through_document_fields,
                        visited_documents=visited_documents):
                    yield field

    def resolve_and_walk(self, role=DEFAULT_ROLE, through_document_fields=False,
                         visited_documents=frozenset()):
        yield self
        if through_document_fields:
            document_cls = self.document_cls
            new_role = DEFAULT_ROLE
            if self.owner_cls:
                if self.owner_cls._options.roles_to_propagate(role):
                    new_role = role
            else:
                new_role = role
            if document_cls not in visited_documents:
                visited_documents = visited_documents | set([document_cls])
                for field in document_cls.resolve_and_walk(
                        role=new_role,
                        through_document_fields=through_document_fields,
                        visited_documents=visited_documents):
                    yield field

    def _get_definitions_and_schema(self, role=DEFAULT_ROLE, res_scope=EMPTY_SCOPE,
                                    ordered=False, ref_documents=None):
        document_cls = self.document_cls
        definition_id = document_cls.get_definition_id(role=role)
        if ref_documents and document_cls in ref_documents:
            return {}, res_scope.create_ref(definition_id)
        else:
            new_role = DEFAULT_ROLE
            if self.owner_cls:
                if self.owner_cls._options.roles_to_propagate(role):
                    new_role = role
            else:
                new_role = role
            document_definitions, document_schema = document_cls.get_definitions_and_schema(
                role=new_role, res_scope=res_scope, ordered=ordered, ref_documents=ref_documents)
            if self.as_ref and not document_cls.is_recursive(role=new_role):
                document_definitions[definition_id] = document_schema
                return document_definitions, res_scope.create_ref(definition_id)
            else:
                return document_definitions, document_schema

    @property
    def document_cls(self):
        """A :class:`.Document` this field points to."""
        document_cls = self._document_cls
        if isinstance(document_cls, string_types):
            if document_cls == RECURSIVE_REFERENCE_CONSTANT:
                if self.owner_cls is None:
                    raise ValueError('owner_cls is not set')
                document_cls = self.owner_cls
            else:
                try:
                    document_cls = registry.get_document(document_cls)
                except KeyError:
                    if self.owner_cls is None:
                        raise ValueError('owner_cls is not set')
                    document_cls = registry.get_document(document_cls,
                                                         module=self.owner_cls.__module__)
        return document_cls


class RefField(BaseField):
    """A reference.

    :param str pointer:
        A `JSON pointer`_.

        .. _JSON pointer: http://tools.ietf.org/html/draft-pbryan-zyp-json-pointer-02
    """

    def __init__(self, pointer, **kwargs):
        self.pointer = pointer  #:
        super(RefField, self).__init__(**kwargs)

    def _get_definitions_and_schema(self, role=DEFAULT_ROLE, res_scope=EMPTY_SCOPE,
                                    ordered=False, ref_documents=None):
        with processing(AttributeStep('pointer', role=role)):
            pointer, _ = self.resolve_attr('pointer', role)
            if not isinstance(pointer, string_types):
                raise SchemaGenerationException(u'{0} is not a string.'.format(pointer))
        return {}, {'$ref': pointer}

    def walk(self, through_document_fields=False, visited_documents=frozenset()):
        yield self
